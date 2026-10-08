package shadowsocks

import (
	"crypto/rand"
	"crypto/sha1"
	"testing"

	"github.com/daeuniverse/outbound/ciphers"
	"golang.org/x/crypto/hkdf"
)

// BenchmarkUDPRealistic simulates the realistic UDP case: every packet uses a
// different salt
func BenchmarkUDPRealistic(b *testing.B) {
	masterKey := make([]byte, 32)
	key := &Key{
		MasterKey:  masterKey,
		CipherConf: ciphers.AeadCiphersConf["aes-256-gcm"],
	}
	reusedInfo := []byte("ss-subkey")
	data := make([]byte, 1400) // MTU

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		// Realistic case: every UDP packet uses a different random salt
		salt := make([]byte, 32)
		_, err := rand.Read(salt) // Simulate RandomSaltGenerator
		if err != nil {
			b.Fatal(err)
		}

		// Run the full encryption path through EncryptUDPFromPoolZeroNonce
		_, err = EncryptUDPFromPoolZeroNonce(key, data, salt, reusedInfo)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkUDPSameSalt is the wrong scenario: every packet uses the same salt
// (an earlier test of mine)
func BenchmarkUDPSameSalt(b *testing.B) {
	masterKey := make([]byte, 32)
	key := &Key{
		MasterKey:  masterKey,
		CipherConf: ciphers.AeadCiphersConf["aes-256-gcm"],
	}
	reusedInfo := []byte("ss-subkey")
	data := make([]byte, 1400)
	salt := make([]byte, 32) // fixed salt

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := EncryptUDPFromPoolZeroNonce(key, data, salt, reusedInfo)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkTCPRealistic simulates the realistic TCP case: the cipher is
// initialized once per connection
func BenchmarkTCPRealistic(b *testing.B) {
	masterKey := make([]byte, 32)
	key := &Key{
		MasterKey:  masterKey,
		CipherConf: ciphers.AeadCiphersConf["aes-256-gcm"],
	}
	reusedInfo := []byte("ss-subkey")
	salt := make([]byte, 32)
	_, err := rand.Read(salt)
	if err != nil {
		b.Fatal(err)
	}

	// Simulate TCP connection setup: derive subKey and cipher once
	subKey := make([]byte, key.CipherConf.KeyLen)
	kdf := hkdf.New(sha1.New, key.MasterKey, salt, reusedInfo)
	_, _ = kdf.Read(subKey)
	ciph, _ := key.CipherConf.NewCipher(subKey)

	// Simulate several packets sharing one cipher
	data := make([]byte, 1400)
	nonce := make([]byte, key.CipherConf.NonceLen)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		// TCP case: the cipher already exists, so only Seal is needed
		_ = ciph.Seal(data[:0], nonce, data, nil)
	}
}

// BenchmarkTCPOverheadIncludingInit is TCP including the initialization
// overhead
func BenchmarkTCPOverheadIncludingInit(b *testing.B) {
	masterKey := make([]byte, 32)
	key := &Key{
		MasterKey:  masterKey,
		CipherConf: ciphers.AeadCiphersConf["aes-256-gcm"],
	}
	reusedInfo := []byte("ss-subkey")
	data := make([]byte, 1400)
	nonce := make([]byte, key.CipherConf.NonceLen)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		// Re-initialize on every iteration (simulating a new connection)
		salt := make([]byte, 32)
		_, err := rand.Read(salt)
		if err != nil {
			b.Fatal(err)
		}

		subKey := make([]byte, key.CipherConf.KeyLen)
		kdf := hkdf.New(sha1.New, key.MasterKey, salt, reusedInfo)
		_, _ = kdf.Read(subKey)
		ciph, _ := key.CipherConf.NewCipher(subKey)

		_ = ciph.Seal(data[:0], nonce, data, nil)
	}
}

// BenchmarkUDPSmallPacketRealistic is the realistic small-packet UDP case
func BenchmarkUDPSmallPacketRealistic(b *testing.B) {
	masterKey := make([]byte, 32)
	key := &Key{
		MasterKey:  masterKey,
		CipherConf: ciphers.AeadCiphersConf["aes-128-gcm"],
	}
	reusedInfo := []byte("ss-subkey")
	data := make([]byte, 64) // packet sized like a DNS query

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		salt := make([]byte, 16)
		_, err := rand.Read(salt)
		if err != nil {
			b.Fatal(err)
		}

		_, err = EncryptUDPFromPoolZeroNonce(key, data, salt, reusedInfo)
		if err != nil {
			b.Fatal(err)
		}
	}
}
