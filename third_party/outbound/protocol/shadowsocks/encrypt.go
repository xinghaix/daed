package shadowsocks

import (
	"crypto/sha1"
	"fmt"
	"hash"
	"sync"

	"github.com/daeuniverse/outbound/ciphers"
	"github.com/daeuniverse/outbound/pool"
)

// subKeyPool reuses subKey buffers to reduce allocations in the hot path.
// Shadowsocks AEAD uses either 16-byte (AES-128) or 32-byte (AES-256) keys.
var subKeyPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 32) // max key size
	},
}

// getSubKey gets a subKey buffer from the pool.
func getSubKey(keyLen int) []byte {
	return subKeyPool.Get().([]byte)[:keyLen]
}

// putSubKey returns a subKey buffer to the pool.
func putSubKey(subKey []byte) {
	if subKey != nil && cap(subKey) >= 16 && cap(subKey) <= 32 {
		// nolint:staticcheck
		subKeyPool.Put(subKey[:32])
	}
}

// sha1DigestPool reuses sha1 digests across the per-packet HKDF key schedule.
// hmac.New would allocate an hmac wrapper + opad + a fresh sha1 digest for each
// of the three HMACs, which dominated the UDP hot path (17 allocs/op with
// hkdf.New). One pooled digest is reset between HMACs instead.
var sha1DigestPool = sync.Pool{
	New: func() interface{} { return sha1.New() },
}

// hmacBuf holds the scratch arrays of one HMAC-SHA1. It is pool-allocated so
// that slices handed to the hash.Hash interface alias heap memory instead of
// escaping a stack array (which previously cost ~232 B and 5 allocs per HMAC).
type hmacBuf struct {
	kbuf, ipad, opad [64]byte
	inner            [sha1.Size]byte
	prk              [sha1.Size]byte
	t1               [sha1.Size]byte
	t2               [sha1.Size]byte
}

var hmacBufPool = sync.Pool{
	New: func() interface{} { return &hmacBuf{} },
}

// hmacSHA1Into computes HMAC-SHA1 without variadic slices or returned arrays,
// keeping all transient values in the caller's pooled scratch.
func hmacSHA1Into(
	h hash.Hash,
	b *hmacBuf,
	out *[sha1.Size]byte,
	key []byte,
	msg1 []byte,
	msg2 []byte,
	msg3 []byte,
) {
	if len(key) > 64 {
		h.Reset()
		h.Write(key)
		h.Sum(b.kbuf[:0])
		// kbuf is pooled and may hold stale bytes past the SHA-1 digest; HMAC
		// pads the hashed key to block size with zeros, so clear the tail.
		clear(b.kbuf[sha1.Size:])
	} else {
		copy(b.kbuf[:], key)
		// kbuf is pooled and may hold stale bytes past len(key); HMAC pads the
		// key to block size with zeros, so the tail must be cleared.
		clear(b.kbuf[len(key):])
	}
	for i := 0; i < len(b.kbuf); i++ {
		b.ipad[i] = b.kbuf[i] ^ 0x36
		b.opad[i] = b.kbuf[i] ^ 0x5c
	}
	h.Reset()
	h.Write(b.ipad[:])
	if len(msg1) > 0 {
		h.Write(msg1)
	}
	if len(msg2) > 0 {
		h.Write(msg2)
	}
	if len(msg3) > 0 {
		h.Write(msg3)
	}
	h.Sum(b.inner[:0])
	h.Reset()
	h.Write(b.opad[:])
	h.Write(b.inner[:])
	h.Sum(out[:0])
}

// deriveSubKey computes subKey = HKDF-SHA1(masterKey, salt, info)[:len(dst)]
// inline. The SS AEAD key schedule only ever needs 1-2 HKDF-Expand blocks
// (SHA-1 is 20 bytes; keys are 16 or 32), so the hkdf.Reader wrapper and its
// per-Read hmac allocations are pure overhead on the per-packet UDP hot path.
func deriveSubKey(dst []byte, masterKey, salt, info []byte) {
	h := sha1DigestPool.Get().(hash.Hash)
	defer sha1DigestPool.Put(h)
	b := hmacBufPool.Get().(*hmacBuf)
	defer hmacBufPool.Put(b)

	// Extract: PRK = HMAC-SHA1(key=salt, data=masterKey)
	hmacSHA1Into(h, b, &b.prk, salt, masterKey, nil, nil)

	// Expand: T(1) = HMAC-SHA1(PRK, info || 0x01)
	hmacSHA1Into(h, b, &b.t1, b.prk[:], info, one, nil)
	n := copy(dst, b.t1[:])
	if n == len(dst) {
		return
	}
	// T(2) = HMAC-SHA1(PRK, T(1) || info || 0x02), only needed for 32-byte keys.
	hmacSHA1Into(h, b, &b.t2, b.prk[:], b.t1[:], info, two)
	copy(dst[n:], b.t2[:])
}

// one and two are the HKDF-Expand block counters, kept as package-level slices
// so the hmacSHA1 variadic call does not allocate per invocation.
var (
	one = []byte{0x01}
	two = []byte{0x02}
)

// EncryptUDPTo encrypts one UDP packet into caller-owned storage. dst must not
// overlap plaintext and must hold salt, ciphertext, and the authentication tag.
func EncryptUDPTo(dst []byte, key *Key, plaintext []byte, salt []byte, reusedInfo []byte) (int, error) {
	subKey := getSubKey(key.CipherConf.KeyLen)
	defer putSubKey(subKey)
	return encryptUDPTo(dst, key, plaintext, salt, reusedInfo, subKey)
}

// EncryptUDPToWithScratch encrypts using caller-owned subkey storage. The
// scratch must hold CipherConf.KeyLen bytes and must not be used concurrently.
func EncryptUDPToWithScratch(
	dst []byte,
	key *Key,
	plaintext []byte,
	salt []byte,
	reusedInfo []byte,
	subKeyScratch []byte,
) (int, error) {
	keyLen := key.CipherConf.KeyLen
	if len(subKeyScratch) < keyLen {
		return 0, fmt.Errorf("subkey scratch is too short: got %d, need %d", len(subKeyScratch), keyLen)
	}
	return encryptUDPTo(dst, key, plaintext, salt, reusedInfo, subKeyScratch[:keyLen])
}

func encryptUDPTo(
	dst []byte,
	key *Key,
	plaintext []byte,
	salt []byte,
	reusedInfo []byte,
	subKey []byte,
) (int, error) {
	saltLen := key.CipherConf.SaltLen
	if len(salt) < saltLen {
		return 0, fmt.Errorf("salt is too short: got %d, need %d", len(salt), saltLen)
	}
	required := saltLen + len(plaintext) + key.CipherConf.TagLen
	if len(dst) < required {
		return 0, fmt.Errorf("destination is too short: got %d, need %d", len(dst), required)
	}
	dst = dst[:required]
	copy(dst, salt[:saltLen])
	deriveSubKey(subKey, key.MasterKey, dst[:saltLen], reusedInfo)
	ciph, err := key.CipherConf.NewCipher(subKey)
	if err != nil {
		return 0, err
	}
	// The AEAD nonce is ciphers.ZeroNonce for every packet, which is the
	// Shadowsocks AEAD UDP layout: the per-packet salt is the only key
	// freshness, so the salt carries the whole nonce-uniqueness requirement.
	// See EncryptUDPFromPoolZeroNonce for the caller-facing contract.
	_ = ciph.Seal(dst[saltLen:saltLen], ciphers.ZeroNonce[:key.CipherConf.NonceLen], plaintext, nil)
	return required, nil
}

// EncryptUDPFromPoolZeroNonce encrypts one UDP packet into pooled storage with
// the fixed ciphers.ZeroNonce as the AEAD nonce. The name states the layout on
// purpose: the salt is not just a protocol field here, it is the only thing
// separating this packet's AEAD key/nonce pair from the next one's.
//
// Contract: salt is used as the HKDF salt AND copied into the packet verbatim,
// while the nonce is always zero, so the packet is fully determined by
// (masterKey, salt, plaintext, reusedInfo) and two packets encrypted under the
// same master key and the same salt share a keystream. An observer holding both
// ciphertexts then recovers c1^c2 = p1^p2 without the key, which is why salt
// MUST be a fresh random value for every packet. Nonce uniqueness is the
// caller's responsibility, and TestEncryptUDPFromPoolZeroNonceSaltReuse pins
// that failure mode.
//
// The production UDP paths generate their salt per packet (protocol/shadowsocks
// UdpConn.WriteTo via RandomSaltGenerator, protocol/juicity's packet conn) and
// go through EncryptUDPTo/EncryptUDPToWithScratch; this pooled helper has no
// production caller in this module.
func EncryptUDPFromPoolZeroNonce(key *Key, b []byte, salt []byte, reusedInfo []byte) (pool.PB, error) {
	buf := pool.Get(key.CipherConf.SaltLen + len(b) + key.CipherConf.TagLen)
	n, err := EncryptUDPTo(buf, key, b, salt, reusedInfo)
	if err != nil {
		pool.Put(buf)
		return nil, err
	}
	return buf[:n], nil
}

func DecryptUDPFromPool(key *Key, shadowBytes []byte, reusedInfo []byte) (buf pool.PB, err error) {
	buf = pool.Get(len(shadowBytes))
	if buf.HeadOverlap(shadowBytes) {
		// The caller may still own the encrypted packet. Do not let pooled
		// output alias it, or AEAD Open will reject the overlap and the input
		// packet will be corrupted on successful decrypt.
		buf = pool.PB(make([]byte, len(shadowBytes)))
	}
	n, err := DecryptUDP(buf[:0], key, shadowBytes, reusedInfo)
	if err != nil {
		buf.Put()
		return nil, err
	}
	return buf[:n], nil
}

func DecryptUDP(writeTo []byte, key *Key, shadowBytes []byte, reusedInfo []byte) (int, error) {
	subKey := getSubKey(key.CipherConf.KeyLen)
	defer putSubKey(subKey)
	return decryptUDP(writeTo, key, shadowBytes, reusedInfo, subKey)
}

// DecryptUDPWithScratch decrypts using caller-owned subkey storage. The
// scratch must hold CipherConf.KeyLen bytes and must not be used concurrently.
func DecryptUDPWithScratch(
	writeTo []byte,
	key *Key,
	shadowBytes []byte,
	reusedInfo []byte,
	subKeyScratch []byte,
) (int, error) {
	keyLen := key.CipherConf.KeyLen
	if len(subKeyScratch) < keyLen {
		return 0, fmt.Errorf("subkey scratch is too short: got %d, need %d", len(subKeyScratch), keyLen)
	}
	return decryptUDP(writeTo, key, shadowBytes, reusedInfo, subKeyScratch[:keyLen])
}

func decryptUDP(
	writeTo []byte,
	key *Key,
	shadowBytes []byte,
	reusedInfo []byte,
	subKey []byte,
) (int, error) {
	if len(shadowBytes) < key.CipherConf.SaltLen {
		return 0, fmt.Errorf("short length to decrypt")
	}
	deriveSubKey(subKey, key.MasterKey, shadowBytes[:key.CipherConf.SaltLen], reusedInfo)
	ciph, err := key.CipherConf.NewCipher(subKey)
	if err != nil {
		return 0, err
	}
	writeTo, err = ciph.Open(writeTo[:0], ciphers.ZeroNonce[:key.CipherConf.NonceLen], shadowBytes[key.CipherConf.SaltLen:], nil)
	if err != nil {
		return 0, err
	}
	return len(writeTo), nil
}
