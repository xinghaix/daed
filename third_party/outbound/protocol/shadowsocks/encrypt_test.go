package shadowsocks

import (
	"bytes"
	"testing"

	"github.com/daeuniverse/outbound/ciphers"
	"github.com/daeuniverse/outbound/pool"
)

func TestEncryptDecrypt(t *testing.T) {
	conf := ciphers.AeadCiphersConf["aes-256-gcm"]
	masterKey := make([]byte, conf.KeyLen)
	fillRandom(t, masterKey)

	salt := make([]byte, conf.SaltLen)
	fillRandom(t, salt)

	plaintext := []byte("Hello, World! This is a test message for Shadowsocks encryption.")
	reusedInfo := []byte("ss-subkey")

	key := &Key{
		CipherConf: conf,
		MasterKey:  masterKey,
	}

	encrypted, err := EncryptUDPFromPoolZeroNonce(key, plaintext, salt, reusedInfo)
	if err != nil {
		t.Fatalf("EncryptUDPFromPoolZeroNonce failed: %v", err)
	}
	defer encrypted.Put()

	decrypted, err := DecryptUDPFromPool(key, encrypted, reusedInfo)
	if err != nil {
		t.Fatalf("DecryptUDPFromPool failed: %v", err)
	}
	defer decrypted.Put()

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("Decrypted text doesn't match plaintext:\n  decrypted: %x\n  plaintext: %x", decrypted, plaintext)
	}
}

func TestEncryptUDPToMatchesPooledWire(t *testing.T) {
	conf := ciphers.AeadCiphersConf["aes-256-gcm"]
	key := &Key{CipherConf: conf, MasterKey: make([]byte, conf.KeyLen)}
	salt := make([]byte, conf.SaltLen)
	plaintext := []byte("destination-buffer")
	reusedInfo := []byte("ss-subkey")

	pooled, err := EncryptUDPFromPoolZeroNonce(key, plaintext, salt, reusedInfo)
	if err != nil {
		t.Fatal(err)
	}
	defer pooled.Put()

	dst := make([]byte, len(pooled))
	n, err := EncryptUDPTo(dst, key, plaintext, salt, reusedInfo)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(pooled) || !bytes.Equal(dst[:n], pooled) {
		t.Fatal("destination encryption changed wire bytes")
	}
	if _, err := EncryptUDPTo(dst[:len(dst)-1], key, plaintext, salt, reusedInfo); err == nil {
		t.Fatal("short destination buffer was accepted")
	}

	scratchDst := make([]byte, len(pooled))
	subKeyScratch := make([]byte, conf.KeyLen)
	n, err = EncryptUDPToWithScratch(scratchDst, key, plaintext, salt, reusedInfo, subKeyScratch)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(pooled) || !bytes.Equal(scratchDst[:n], pooled) {
		t.Fatal("scratch encryption changed wire bytes")
	}
}

func TestMultipleSalts(t *testing.T) {
	conf := ciphers.AeadCiphersConf["aes-256-gcm"]
	masterKey := make([]byte, conf.KeyLen)
	fillRandom(t, masterKey)

	plaintext := []byte("Multi-salt test")
	reusedInfo := []byte("ss-subkey")

	key := &Key{
		CipherConf: conf,
		MasterKey:  masterKey,
	}

	for i := 0; i < 10; i++ {
		salt := make([]byte, conf.SaltLen)
		fillRandom(t, salt)

		encrypted, err := EncryptUDPFromPoolZeroNonce(key, plaintext, salt, reusedInfo)
		if err != nil {
			t.Fatalf("Encrypt iteration %d failed: %v", i, err)
		}

		decrypted, err := DecryptUDPFromPool(key, encrypted, reusedInfo)
		if err != nil {
			encrypted.Put()
			t.Fatalf("Decrypt iteration %d failed: %v", i, err)
		}

		if !bytes.Equal(decrypted, plaintext) {
			t.Errorf("Salt %d failed", i)
		}

		encrypted.Put()
		decrypted.Put()
	}
}

func TestDecryptUDPWithScratchMatchesPlaintext(t *testing.T) {
	conf := ciphers.AeadCiphersConf["chacha20-poly1305"]
	key := &Key{CipherConf: conf, MasterKey: make([]byte, conf.KeyLen)}
	salt := make([]byte, conf.SaltLen)
	plaintext := []byte("destination-decryption")
	reusedInfo := []byte("ss-subkey")
	encrypted, err := EncryptUDPFromPoolZeroNonce(key, plaintext, salt, reusedInfo)
	if err != nil {
		t.Fatal(err)
	}
	defer encrypted.Put()

	dst := make([]byte, len(plaintext))
	subKeyScratch := make([]byte, conf.KeyLen)
	n, err := DecryptUDPWithScratch(dst, key, encrypted, reusedInfo, subKeyScratch)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dst[:n], plaintext) {
		t.Fatal("scratch decryption changed plaintext")
	}
}

// TestEncryptUDPFromPoolZeroNonceSaltReuse is the failure assertion behind the
// contract documented on EncryptUDPFromPoolZeroNonce: reusing a salt reuses the
// AEAD key/nonce pair, and the damage is visible in the ciphertexts alone.
//
// Two packets with different plaintexts, encrypted under one master key with
// the same salt, share a keystream. XOR-ing their payloads cancels that
// keystream and yields the XOR of the two plaintexts, so an observer who sees
// both packets on the wire learns p1^p2 with no key and no cryptanalysis. Both
// packets remain individually valid and decryptable, so nothing downstream
// reports a problem; only the XOR reveals the reuse.
//
// The test fails if the zero-nonce layout stops holding (the XOR equality would
// disappear) or if the salt stops being the only per-packet input to the key
// schedule (a different salt would no longer break the equality). It is the
// assertion that makes this API's hazard explicit instead of leaving it as a
// trap for the next caller.
func TestEncryptUDPFromPoolZeroNonceSaltReuse(t *testing.T) {
	for _, cipherName := range []string{"aes-128-gcm", "aes-256-gcm", "chacha20-poly1305"} {
		t.Run(cipherName, func(t *testing.T) {
			conf := ciphers.AeadCiphersConf[cipherName]
			masterKey := make([]byte, conf.KeyLen)
			fillRandom(t, masterKey)
			key := &Key{CipherConf: conf, MasterKey: masterKey}
			reusedInfo := []byte("ss-subkey")

			salt := make([]byte, conf.SaltLen)
			fillRandom(t, salt)

			// Equal-length plaintexts so the payload XOR is well defined.
			firstPlain := []byte("first plaintext: 0123456789abcdef")
			secondPlain := []byte("second plaintext, different bytes")
			if len(firstPlain) != len(secondPlain) {
				t.Fatalf("test setup: plaintext lengths differ (%d, %d)", len(firstPlain), len(secondPlain))
			}

			encrypt := func(plaintext, salt []byte) pool.PB {
				packet, err := EncryptUDPFromPoolZeroNonce(key, plaintext, salt, reusedInfo)
				if err != nil {
					t.Fatalf("EncryptUDPFromPoolZeroNonce: %v", err)
				}
				return packet
			}
			payload := func(packet pool.PB) []byte {
				return packet[conf.SaltLen : conf.SaltLen+len(firstPlain)]
			}
			xor := func(a, b []byte) []byte {
				out := make([]byte, len(a))
				for i := range a {
					out[i] = a[i] ^ b[i]
				}
				return out
			}

			first := encrypt(firstPlain, salt)
			defer first.Put()
			second := encrypt(secondPlain, salt)
			defer second.Put()

			if !bytes.Equal(first[:conf.SaltLen], salt) || !bytes.Equal(second[:conf.SaltLen], salt) {
				t.Fatal("the packet must carry the caller-supplied salt verbatim")
			}
			if bytes.Equal(first, second) {
				t.Fatal("different plaintexts produced identical packets")
			}

			// Same salt => same keystream => c1^c2 == p1^p2.
			recovered := xor(payload(first), payload(second))
			want := xor(firstPlain, secondPlain)
			if bytes.Equal(want, make([]byte, len(want))) {
				t.Fatal("test setup: the two plaintexts must differ")
			}
			if !bytes.Equal(recovered, want) {
				t.Fatalf("reused salt did not reuse the keystream: c1^c2 = %x, want p1^p2 = %x",
					recovered, want)
			}

			// The reuse is silent: both packets still decrypt on their own.
			for i, plaintext := range [][]byte{firstPlain, secondPlain} {
				packet := [2]pool.PB{first, second}[i]
				decrypted, err := DecryptUDPFromPool(key, packet, reusedInfo)
				if err != nil {
					t.Fatalf("packet %d did not decrypt: %v", i, err)
				}
				if !bytes.Equal(decrypted, plaintext) {
					t.Fatalf("packet %d decrypted to %q, want %q", i, decrypted, plaintext)
				}
				decrypted.Put()
			}

			// A fresh salt breaks the equality: that is the whole protection.
			otherSalt := make([]byte, conf.SaltLen)
			fillRandom(t, otherSalt)
			third := encrypt(firstPlain, otherSalt)
			defer third.Put()
			if bytes.Equal(xor(payload(third), payload(second)), want) {
				t.Fatal("a different salt still shared the keystream")
			}
		})
	}
}

func TestEncryptUDPToAllocationCeiling(t *testing.T) {
	conf := ciphers.AeadCiphersConf["chacha20-poly1305"]
	key := &Key{CipherConf: conf, MasterKey: make([]byte, conf.KeyLen)}
	salt := make([]byte, conf.SaltLen)
	plaintext := make([]byte, 1400)
	dst := make([]byte, conf.SaltLen+len(plaintext)+conf.TagLen)
	reusedInfo := []byte("ss-subkey")

	var encryptErr error
	allocs := testing.AllocsPerRun(1000, func() {
		_, encryptErr = EncryptUDPTo(dst, key, plaintext, salt, reusedInfo)
	})
	if encryptErr != nil {
		t.Fatal(encryptErr)
	}
	if allocs > 3 {
		t.Fatalf("EncryptUDPTo allocations = %v, want at most 3", allocs)
	}
}

func TestEncryptUDPToWithScratchAllocationCeiling(t *testing.T) {
	conf := ciphers.AeadCiphersConf["chacha20-poly1305"]
	key := &Key{CipherConf: conf, MasterKey: make([]byte, conf.KeyLen)}
	salt := make([]byte, conf.SaltLen)
	plaintext := make([]byte, 1400)
	dst := make([]byte, conf.SaltLen+len(plaintext)+conf.TagLen)
	subKeyScratch := make([]byte, conf.KeyLen)
	reusedInfo := []byte("ss-subkey")

	var encryptErr error
	allocs := testing.AllocsPerRun(1000, func() {
		_, encryptErr = EncryptUDPToWithScratch(dst, key, plaintext, salt, reusedInfo, subKeyScratch)
	})
	if encryptErr != nil {
		t.Fatal(encryptErr)
	}
	if allocs > 1 {
		t.Fatalf("EncryptUDPToWithScratch allocations = %v, want at most 1", allocs)
	}
}

func TestDecryptUDPWithScratchAllocationCeiling(t *testing.T) {
	conf := ciphers.AeadCiphersConf["chacha20-poly1305"]
	key := &Key{CipherConf: conf, MasterKey: make([]byte, conf.KeyLen)}
	salt := make([]byte, conf.SaltLen)
	plaintext := make([]byte, 1400)
	reusedInfo := []byte("ss-subkey")
	encrypted, err := EncryptUDPFromPoolZeroNonce(key, plaintext, salt, reusedInfo)
	if err != nil {
		t.Fatal(err)
	}
	defer encrypted.Put()
	dst := make([]byte, len(plaintext))
	subKeyScratch := make([]byte, conf.KeyLen)

	var decryptErr error
	allocs := testing.AllocsPerRun(1000, func() {
		_, decryptErr = DecryptUDPWithScratch(dst, key, encrypted, reusedInfo, subKeyScratch)
	})
	if decryptErr != nil {
		t.Fatal(decryptErr)
	}
	if allocs > 1 {
		t.Fatalf("DecryptUDPWithScratch allocations = %v, want at most 1", allocs)
	}
}

func BenchmarkEncrypt(b *testing.B) {
	conf := ciphers.AeadCiphersConf["aes-256-gcm"]
	masterKey := make([]byte, conf.KeyLen)
	salt := make([]byte, conf.SaltLen)
	plaintext := make([]byte, 1024)
	reusedInfo := []byte("ss-subkey")

	key := &Key{
		CipherConf: conf,
		MasterKey:  masterKey,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		shadowBytes, _ := EncryptUDPFromPoolZeroNonce(key, plaintext, salt, reusedInfo)
		shadowBytes.Put()
	}
}

func BenchmarkDecrypt(b *testing.B) {
	conf := ciphers.AeadCiphersConf["aes-256-gcm"]
	masterKey := make([]byte, conf.KeyLen)
	salt := make([]byte, conf.SaltLen)
	plaintext := make([]byte, 1024)
	reusedInfo := []byte("ss-subkey")

	key := &Key{
		CipherConf: conf,
		MasterKey:  masterKey,
	}

	shadowBytes, _ := EncryptUDPFromPoolZeroNonce(key, plaintext, salt, reusedInfo)
	defer shadowBytes.Put()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf, _ := DecryptUDPFromPool(key, shadowBytes, reusedInfo)
		buf.Put()
	}
}
