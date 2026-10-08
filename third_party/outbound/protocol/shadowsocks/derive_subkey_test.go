package shadowsocks

import (
	"bytes"
	"crypto/sha1"
	"io"
	"testing"

	"github.com/daeuniverse/outbound/pkg/fastrand"
	"golang.org/x/crypto/hkdf"
)

// TestDeriveSubKeyMatchesHKDF cross-checks the inline key schedule against the
// standard x/crypto/hkdf over random inputs, for both 16-byte (AES-128) and
// 32-byte (AES-256/chacha20) keys. A mismatch would silently break crypto.
func TestDeriveSubKeyMatchesHKDF(t *testing.T) {
	info := []byte("ss-subkey")
	for _, keyLen := range []int{16, 32} {
		for i := 0; i < 200; i++ {
			masterKey := make([]byte, 32)
			salt := make([]byte, 32)
			_, _ = fastrand.Read(masterKey)
			_, _ = fastrand.Read(salt)

			want := make([]byte, keyLen)
			kdf := hkdf.New(sha1.New, masterKey, salt, info)
			if _, err := io.ReadFull(kdf, want); err != nil {
				t.Fatalf("hkdf: %v", err)
			}

			got := make([]byte, keyLen)
			deriveSubKey(got, masterKey, salt, info)
			if !bytes.Equal(got, want) {
				t.Fatalf("keyLen=%d iter=%d: deriveSubKey mismatch\n got=%x\nwant=%x",
					keyLen, i, got, want)
			}
		}
	}
}
