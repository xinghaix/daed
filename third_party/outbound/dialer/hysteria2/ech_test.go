package hysteria2

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func testECHConfigList() []byte {
	return []byte{0x00, 0x08, 0xfe, 0x0d, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00}
}

func TestDecodeECHConfigListAcceptsCommonBase64Encodings(t *testing.T) {
	want := testECHConfigList()
	encodings := map[string]string{
		"standard":     base64.StdEncoding.EncodeToString(want),
		"raw-standard": base64.RawStdEncoding.EncodeToString(want),
		"url":          base64.URLEncoding.EncodeToString(want),
		"raw-url":      base64.RawURLEncoding.EncodeToString(want),
	}
	for name, encoded := range encodings {
		t.Run(name, func(t *testing.T) {
			got, err := decodeECHConfigList(encoded)
			if err != nil {
				t.Fatalf("decodeECHConfigList() error = %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("decodeECHConfigList() = %x, want %x", got, want)
			}
		})
	}
}

func TestDecodeECHConfigListRejectsMalformedInput(t *testing.T) {
	encode := base64.StdEncoding.EncodeToString
	tests := map[string]string{
		"empty":                   "",
		"invalid-base64":          "not%%%base64",
		"empty-list":              encode([]byte{0x00, 0x00}),
		"invalid-list-length":     encode([]byte{0x00, 0x08, 0xfe, 0x0d}),
		"truncated-config-header": encode([]byte{0x00, 0x03, 0xfe, 0x0d, 0x00}),
		"truncated-config-body":   encode([]byte{0x00, 0x04, 0xfe, 0x0d, 0x00, 0x01}),
	}
	for name, encoded := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeECHConfigList(encoded); err == nil {
				t.Fatal("decodeECHConfigList() unexpectedly succeeded")
			}
		})
	}
}
