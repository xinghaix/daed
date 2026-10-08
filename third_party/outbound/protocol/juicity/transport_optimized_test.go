package juicity

import (
	"bytes"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/ciphers"
	"github.com/daeuniverse/outbound/pkg/fastrand"
	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol/shadowsocks"
	"github.com/olicesx/quic-go"
)

func TestOptimizedEncryptDecryptCorrectness(t *testing.T) {
	conf := CipherConf
	masterKey := make([]byte, conf.KeyLen)
	_, _ = fastrand.Read(masterKey)

	key := &shadowsocks.Key{
		CipherConf: conf,
		MasterKey:  masterKey,
	}

	plaintext := []byte("Hello, Juicity! This is a test message for UDP optimization.")
	reusedInfo := ciphers.JuicityReusedInfo

	for i := 0; i < 10; i++ {
		salt := make([]byte, conf.SaltLen)
		_, _ = fastrand.Read(salt)

		encrypted, err := shadowsocks.EncryptUDPFromPoolZeroNonce(key, plaintext, salt, reusedInfo)
		if err != nil {
			t.Fatalf("Encryption failed at iteration %d: %v", i, err)
		}

		decrypted, err := shadowsocks.DecryptUDPFromPool(key, encrypted, reusedInfo)
		if err != nil {
			encrypted.Put()
			t.Fatalf("Decryption failed at iteration %d: %v", i, err)
		}

		if !bytes.Equal(decrypted, plaintext) {
			encrypted.Put()
			decrypted.Put()
			t.Errorf("Decrypted text doesn't match at iteration %d", i)
		}

		encrypted.Put()
		decrypted.Put()
	}
}

func TestOptimizedCacheEffectiveness(t *testing.T) {
	conf := CipherConf
	masterKey := make([]byte, conf.KeyLen)
	_, _ = fastrand.Read(masterKey)

	key := &shadowsocks.Key{
		CipherConf: conf,
		MasterKey:  masterKey,
	}

	salt := make([]byte, conf.SaltLen)
	_, _ = fastrand.Read(salt)

	plaintext := []byte("Cache test for juicity")
	reusedInfo := ciphers.JuicityReusedInfo

	encrypted1, err := shadowsocks.EncryptUDPFromPoolZeroNonce(key, plaintext, salt, reusedInfo)
	if err != nil {
		t.Fatal(err)
	}
	encrypted1.Put()

	encrypted2, err := shadowsocks.EncryptUDPFromPoolZeroNonce(key, plaintext, salt, reusedInfo)
	if err != nil {
		t.Fatal(err)
	}
	defer encrypted2.Put()

	if !bytes.Equal(encrypted1, encrypted2) {
		t.Error("Cached encryption should produce same result")
	}

	decrypted, err := shadowsocks.DecryptUDPFromPool(key, encrypted2, reusedInfo)
	if err != nil {
		t.Fatal(err)
	}
	defer decrypted.Put()

	if !bytes.Equal(decrypted, plaintext) {
		t.Error("Decrypted text doesn't match")
	}
}

func TestOptimizedConcurrentAccess(t *testing.T) {
	conf := CipherConf
	masterKey := make([]byte, conf.KeyLen)
	_, _ = fastrand.Read(masterKey)

	key := &shadowsocks.Key{
		CipherConf: conf,
		MasterKey:  masterKey,
	}

	salt := make([]byte, conf.SaltLen)
	_, _ = fastrand.Read(salt)

	plaintext := []byte("Concurrent test")
	reusedInfo := ciphers.JuicityReusedInfo

	var wg sync.WaitGroup
	errors := make(chan error, 100)

	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				encrypted, err := shadowsocks.EncryptUDPFromPoolZeroNonce(key, plaintext, salt, reusedInfo)
				if err != nil {
					errors <- err
					return
				}

				decrypted, err := shadowsocks.DecryptUDPFromPool(key, encrypted, reusedInfo)
				encrypted.Put()
				if err != nil {
					errors <- err
					return
				}

				if !bytes.Equal(decrypted, plaintext) {
					errors <- bytes.ErrTooLarge
					decrypted.Put()
					return
				}
				decrypted.Put()
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Errorf("Concurrent access error: %v", err)
	}
}

func TestOptimizedMemoryLeak(t *testing.T) {
	conf := CipherConf
	masterKey := make([]byte, conf.KeyLen)
	_, _ = fastrand.Read(masterKey)

	key := &shadowsocks.Key{
		CipherConf: conf,
		MasterKey:  masterKey,
	}

	plaintext := make([]byte, 1400)
	reusedInfo := ciphers.JuicityReusedInfo

	runtime.GC()
	var memBefore runtime.MemStats
	runtime.ReadMemStats(&memBefore)

	for i := 0; i < 10000; i++ {
		salt := make([]byte, conf.SaltLen)
		_, _ = fastrand.Read(salt)

		encrypted, err := shadowsocks.EncryptUDPFromPoolZeroNonce(key, plaintext, salt, reusedInfo)
		if err != nil {
			t.Fatal(err)
		}

		decrypted, err := shadowsocks.DecryptUDPFromPool(key, encrypted, reusedInfo)
		encrypted.Put()
		if err != nil {
			t.Fatal(err)
		}
		decrypted.Put()
	}

	runtime.GC()
	var memAfter runtime.MemStats
	runtime.ReadMemStats(&memAfter)

	heapGrowth := int64(memAfter.HeapAlloc) - int64(memBefore.HeapAlloc)
	t.Logf("Heap before: %d bytes", memBefore.HeapAlloc)
	t.Logf("Heap after: %d bytes", memAfter.HeapAlloc)
	t.Logf("Heap growth: %d bytes", heapGrowth)

	if heapGrowth > 10*1024*1024 {
		t.Errorf("Potential memory leak: heap grew by %d bytes (> 10MB)", heapGrowth)
	}
}

func TestOptimizedPoolMemoryLeak(t *testing.T) {
	conf := CipherConf
	masterKey := make([]byte, conf.KeyLen)
	_, _ = fastrand.Read(masterKey)

	key := &shadowsocks.Key{
		CipherConf: conf,
		MasterKey:  masterKey,
	}

	salt := make([]byte, conf.SaltLen)
	_, _ = fastrand.Read(salt)

	plaintext := make([]byte, 1400)
	reusedInfo := ciphers.JuicityReusedInfo

	runtime.GC()
	var memBefore runtime.MemStats
	runtime.ReadMemStats(&memBefore)

	for i := 0; i < 10000; i++ {
		encrypted, err := shadowsocks.EncryptUDPFromPoolZeroNonce(key, plaintext, salt, reusedInfo)
		if err != nil {
			t.Fatal(err)
		}

		decrypted, err := shadowsocks.DecryptUDPFromPool(key, encrypted, reusedInfo)
		encrypted.Put()
		if err != nil {
			t.Fatal(err)
		}
		decrypted.Put()
	}

	runtime.GC()
	var memAfter runtime.MemStats
	runtime.ReadMemStats(&memAfter)

	heapGrowth := int64(memAfter.HeapAlloc) - int64(memBefore.HeapAlloc)
	t.Logf("Pool test - Heap before: %d bytes", memBefore.HeapAlloc)
	t.Logf("Pool test - Heap after: %d bytes", memAfter.HeapAlloc)
	t.Logf("Pool test - Heap growth: %d bytes", heapGrowth)

	if heapGrowth > 5*1024*1024 {
		t.Errorf("Potential pool memory leak: heap grew by %d bytes (> 5MB)", heapGrowth)
	}
}

func BenchmarkJuicityEncrypt(b *testing.B) {
	conf := CipherConf
	masterKey := make([]byte, conf.KeyLen)
	_, _ = fastrand.Read(masterKey)

	key := &shadowsocks.Key{
		CipherConf: conf,
		MasterKey:  masterKey,
	}

	salt := make([]byte, conf.SaltLen)
	_, _ = fastrand.Read(salt)

	plaintext := make([]byte, 1400)
	reusedInfo := ciphers.JuicityReusedInfo

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		encrypted, _ := shadowsocks.EncryptUDPFromPoolZeroNonce(key, plaintext, salt, reusedInfo)
		encrypted.Put()
	}
}

func BenchmarkJuicityDecrypt(b *testing.B) {
	conf := CipherConf
	masterKey := make([]byte, conf.KeyLen)
	_, _ = fastrand.Read(masterKey)

	key := &shadowsocks.Key{
		CipherConf: conf,
		MasterKey:  masterKey,
	}

	salt := make([]byte, conf.SaltLen)
	_, _ = fastrand.Read(salt)

	plaintext := make([]byte, 1400)
	reusedInfo := ciphers.JuicityReusedInfo

	encrypted, _ := shadowsocks.EncryptUDPFromPoolZeroNonce(key, plaintext, salt, reusedInfo)
	defer encrypted.Put()

	decrypted, _ := shadowsocks.DecryptUDPFromPool(key, encrypted, reusedInfo)
	decrypted.Put()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		buf, _ := shadowsocks.DecryptUDPFromPool(key, encrypted, reusedInfo)
		buf.Put()
	}
}

func BenchmarkJuicityEncryptDecrypt(b *testing.B) {
	conf := CipherConf
	masterKey := make([]byte, conf.KeyLen)
	_, _ = fastrand.Read(masterKey)

	key := &shadowsocks.Key{
		CipherConf: conf,
		MasterKey:  masterKey,
	}

	salt := make([]byte, conf.SaltLen)
	_, _ = fastrand.Read(salt)

	plaintext := make([]byte, 1400)
	reusedInfo := ciphers.JuicityReusedInfo

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		encrypted, _ := shadowsocks.EncryptUDPFromPoolZeroNonce(key, plaintext, salt, reusedInfo)
		decrypted, _ := shadowsocks.DecryptUDPFromPool(key, encrypted, reusedInfo)
		encrypted.Put()
		decrypted.Put()
	}
}

func BenchmarkJuicityVsOriginal(b *testing.B) {
	conf := CipherConf
	masterKey := make([]byte, conf.KeyLen)
	_, _ = fastrand.Read(masterKey)

	key := &shadowsocks.Key{
		CipherConf: conf,
		MasterKey:  masterKey,
	}

	salt := make([]byte, conf.SaltLen)
	_, _ = fastrand.Read(salt)

	plaintext := make([]byte, 1400)
	reusedInfo := ciphers.JuicityReusedInfo

	b.Run("Original", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			encrypted, _ := shadowsocks.EncryptUDPFromPoolZeroNonce(key, plaintext, salt, reusedInfo)
			decrypted := pool.Get(len(encrypted))
			n, _ := shadowsocks.DecryptUDP(decrypted[:0], key, encrypted, reusedInfo)
			encrypted.Put()
			pool.Put(decrypted)
			_ = n
		}
	})

	b.Run("Optimized", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			encrypted, _ := shadowsocks.EncryptUDPFromPoolZeroNonce(key, plaintext, salt, reusedInfo)
			decrypted, _ := shadowsocks.DecryptUDPFromPool(key, encrypted, reusedInfo)
			encrypted.Put()
			decrypted.Put()
		}
	})
}

func BenchmarkJuicityMultipleSalts(b *testing.B) {
	conf := CipherConf
	masterKey := make([]byte, conf.KeyLen)
	_, _ = fastrand.Read(masterKey)

	key := &shadowsocks.Key{
		CipherConf: conf,
		MasterKey:  masterKey,
	}

	plaintext := make([]byte, 1400)
	reusedInfo := ciphers.JuicityReusedInfo

	numSalts := 50
	salts := make([][]byte, numSalts)
	for i := range salts {
		salts[i] = make([]byte, conf.SaltLen)
		_, _ = fastrand.Read(salts[i])
	}

	b.Run("Original_MultiSalt", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			salt := salts[i%numSalts]
			encrypted, _ := shadowsocks.EncryptUDPFromPoolZeroNonce(key, plaintext, salt, reusedInfo)
			encrypted.Put()
		}
	})

	b.Run("Optimized_MultiSalt", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			salt := salts[i%numSalts]
			encrypted, _ := shadowsocks.EncryptUDPFromPoolZeroNonce(key, plaintext, salt, reusedInfo)
			encrypted.Put()
		}
	})
}

func BenchmarkJuicityRealistic(b *testing.B) {
	conf := CipherConf
	masterKey := make([]byte, conf.KeyLen)
	_, _ = fastrand.Read(masterKey)

	key := &shadowsocks.Key{
		CipherConf: conf,
		MasterKey:  masterKey,
	}

	plaintext := make([]byte, 1400)
	reusedInfo := ciphers.JuicityReusedInfo

	b.Run("Realistic_Optimized", func(b *testing.B) {
		b.ReportAllocs()

		salt := make([]byte, conf.SaltLen)
		_, _ = fastrand.Read(salt)

		for i := 0; i < b.N; i++ {
			if i%100 == 0 {
				_, _ = fastrand.Read(salt)
			}
			encrypted, _ := shadowsocks.EncryptUDPFromPoolZeroNonce(key, plaintext, salt, reusedInfo)
			decrypted, _ := shadowsocks.DecryptUDPFromPool(key, encrypted, reusedInfo)
			encrypted.Put()
			decrypted.Put()
		}
	})
}

func TestTransportPacketConnOptimizedPath(t *testing.T) {
	conf := CipherConf
	masterKey := make([]byte, conf.KeyLen)
	_, _ = fastrand.Read(masterKey)

	key := &shadowsocks.Key{
		CipherConf: conf,
		MasterKey:  masterKey,
	}

	plaintext := []byte("TransportPacketConn test payload")
	salt := make([]byte, conf.SaltLen)
	_, _ = fastrand.Read(salt)
	reusedInfo := ciphers.JuicityReusedInfo

	encrypted, err := shadowsocks.EncryptUDPFromPoolZeroNonce(key, plaintext, salt, reusedInfo)
	if err != nil {
		t.Fatal(err)
	}
	defer encrypted.Put()

	decrypted, err := shadowsocks.DecryptUDPFromPool(key, encrypted, reusedInfo)
	if err != nil {
		t.Fatal(err)
	}
	defer decrypted.Put()

	if !bytes.Equal(decrypted, plaintext) {
		t.Error("TransportPacketConn encryption/decryption mismatch")
	}
}

func TestTransportPacketConnWriteReturnsPlaintextLength(t *testing.T) {
	server, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket server: %v", err)
	}
	defer func() { _ = server.Close() }()

	client, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket client: %v", err)
	}

	conf := CipherConf
	masterKey := make([]byte, conf.KeyLen)
	_, _ = fastrand.Read(masterKey)
	conn := &TransportPacketConn{
		Transport: &quic.Transport{Conn: client},
		proxyAddr: server.LocalAddr().(*net.UDPAddr),
		key: &shadowsocks.Key{
			CipherConf: conf,
			MasterKey:  masterKey,
		},
	}
	defer func() { _ = conn.Close() }()

	payload := []byte("plaintext payload")
	n, err := conn.Write(payload)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != len(payload) {
		t.Fatalf("Write returned %d, want plaintext length %d", n, len(payload))
	}

	buf := make([]byte, 2048)
	if err := server.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	readN, _, err := server.ReadFrom(buf)
	if err != nil {
		t.Fatalf("server ReadFrom: %v", err)
	}
	if readN != len(payload)+conf.SaltLen+conf.TagLen {
		t.Fatalf("server received %d bytes, want encrypted length %d", readN, len(payload)+conf.SaltLen+conf.TagLen)
	}
}

func TestTransportPacketConnSimulatedReadWrite(t *testing.T) {
	conf := CipherConf
	masterKey := make([]byte, conf.KeyLen)
	_, _ = fastrand.Read(masterKey)

	key := &shadowsocks.Key{
		CipherConf: conf,
		MasterKey:  masterKey,
	}

	for i := 0; i < 100; i++ {
		plaintext := make([]byte, 100+fastrand.Intn(1300))
		_, _ = fastrand.Read(plaintext)

		salt := make([]byte, conf.SaltLen)
		_, _ = fastrand.Read(salt)

		reusedInfo := ciphers.JuicityReusedInfo

		encrypted, err := shadowsocks.EncryptUDPFromPoolZeroNonce(key, plaintext, salt, reusedInfo)
		if err != nil {
			t.Fatal(err)
		}

		decrypted, err := shadowsocks.DecryptUDPFromPool(key, encrypted, reusedInfo)
		encrypted.Put()
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(decrypted, plaintext) {
			decrypted.Put()
			t.Errorf("Mismatch at iteration %d", i)
		}
		decrypted.Put()
	}
}

func TestTransportPacketConnTargetAddress(t *testing.T) {
	tgt := netip.MustParseAddrPort("192.168.1.1:443")

	plaintext := []byte("Test data with target address")
	conf := CipherConf
	masterKey := make([]byte, conf.KeyLen)
	_, _ = fastrand.Read(masterKey)

	key := &shadowsocks.Key{
		CipherConf: conf,
		MasterKey:  masterKey,
	}

	salt := make([]byte, conf.SaltLen)
	_, _ = fastrand.Read(salt)
	reusedInfo := ciphers.JuicityReusedInfo

	encrypted, err := shadowsocks.EncryptUDPFromPoolZeroNonce(key, plaintext, salt, reusedInfo)
	if err != nil {
		t.Fatal(err)
	}
	defer encrypted.Put()

	decrypted, err := shadowsocks.DecryptUDPFromPool(key, encrypted, reusedInfo)
	if err != nil {
		t.Fatal(err)
	}
	defer decrypted.Put()

	if !bytes.Equal(decrypted, plaintext) {
		t.Error("Decryption mismatch with target address")
	}

	_ = tgt
}

// TestEncryptUDPFromPoolZeroNonceIsDeterministicPerSalt is the P3-27 replacement for the
// former TestCacheExpiration, which asserted nothing: it compared a buffer
// AFTER returning it to the pool (use-after-Put, so the comparison was against
// whatever the pool's LIFO handed back) and only checked that the result was
// still decryptable, which the pool reuse made true regardless of the cipher.
//
// The replacement pins what the function actually guarantees. It is
// deterministic: the salt is copied into the packet and used as the HKDF salt
// while the AEAD nonce is the fixed ciphers.ZeroNonce, so two calls with the
// same salt produce identical bytes. Nonce uniqueness is therefore the CALLER's
// responsibility through salt uniqueness, and this test states that contract
// explicitly instead of asserting an independence the implementation does not
// provide.
func TestEncryptUDPFromPoolZeroNonceIsDeterministicPerSalt(t *testing.T) {
	conf := CipherConf
	masterKey := make([]byte, conf.KeyLen)
	_, _ = fastrand.Read(masterKey)

	key := &shadowsocks.Key{
		CipherConf: conf,
		MasterKey:  masterKey,
	}

	salt := make([]byte, conf.SaltLen)
	_, _ = fastrand.Read(salt)

	plaintext := []byte("Per-call encryption test")
	reusedInfo := ciphers.JuicityReusedInfo

	first, err := shadowsocks.EncryptUDPFromPoolZeroNonce(key, plaintext, salt, reusedInfo)
	if err != nil {
		t.Fatal(err)
	}
	// Copy before Put: reading a pooled buffer after returning it is
	// use-after-Put (the pool may hand the same slice to another caller).
	firstBytes := append([]byte(nil), []byte(first)...)
	first.Put()

	second, err := shadowsocks.EncryptUDPFromPoolZeroNonce(key, plaintext, salt, reusedInfo)
	if err != nil {
		t.Fatal(err)
	}
	secondBytes := append([]byte(nil), []byte(second)...)
	second.Put()

	if !bytes.Equal(firstBytes, secondBytes) {
		t.Fatal("same salt produced different ciphertext; the salt/no-nonce layout changed " +
			"and this test must be updated with it")
	}
	if !bytes.Equal(firstBytes[:conf.SaltLen], salt) {
		t.Fatal("the packet must carry the caller-supplied salt verbatim")
	}

	// A different salt must produce a different packet (a different subkey),
	// which is the property that makes salt uniqueness load-bearing.
	otherSalt := make([]byte, conf.SaltLen)
	_, _ = fastrand.Read(otherSalt)
	third, err := shadowsocks.EncryptUDPFromPoolZeroNonce(key, plaintext, otherSalt, reusedInfo)
	if err != nil {
		t.Fatal(err)
	}
	thirdBytes := append([]byte(nil), []byte(third)...)
	third.Put()
	if bytes.Equal(firstBytes, thirdBytes) {
		t.Fatal("a different salt produced identical bytes: the HKDF salt is not being used")
	}

	// Every ciphertext must decrypt independently.
	for i, ct := range [][]byte{firstBytes, secondBytes, thirdBytes} {
		decrypted, err := shadowsocks.DecryptUDPFromPool(key, ct, reusedInfo)
		if err != nil {
			t.Fatalf("ciphertext %d: DecryptUDPFromPool error = %v", i, err)
		}
		got := append([]byte(nil), []byte(decrypted)...)
		decrypted.Put()
		if !bytes.Equal(got, plaintext) {
			t.Fatalf("ciphertext %d: decrypted %q, want %q", i, got, plaintext)
		}
	}
}
