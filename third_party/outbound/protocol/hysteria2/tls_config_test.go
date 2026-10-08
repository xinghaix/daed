package hysteria2

import (
	"bytes"
	"crypto/tls"
	"testing"
)

func TestToClientTLSConfigPreservesECHConfigList(t *testing.T) {
	want := []byte{0x00, 0x04, 0xfe, 0x0d, 0x00, 0x00}
	got := toClientTLSConfig(&tls.Config{EncryptedClientHelloConfigList: want})

	if !bytes.Equal(got.EncryptedClientHelloConfigList, want) {
		t.Fatalf("EncryptedClientHelloConfigList = %x, want %x", got.EncryptedClientHelloConfigList, want)
	}
}
