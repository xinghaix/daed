package client

import (
	"bytes"
	"testing"
)

func TestTLSConfigPreservesECHConfigList(t *testing.T) {
	want := []byte{0x00, 0x04, 0xfe, 0x0d, 0x00, 0x00}
	got := (TLSConfig{EncryptedClientHelloConfigList: want}).toTLSConfig()

	if !bytes.Equal(got.EncryptedClientHelloConfigList, want) {
		t.Fatalf("EncryptedClientHelloConfigList = %x, want %x", got.EncryptedClientHelloConfigList, want)
	}
}
