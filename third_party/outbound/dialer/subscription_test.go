package dialer

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

func TestParseSubscription(t *testing.T) {
	links := []string{
		"vmess://dm1lc3M=",
		"vless://00000000-0000-0000-0000-000000000000@example.com:443?type=tcp#\u00be",
	}
	plaintext := strings.Join(links, "\r\n")
	urlSafe := base64.RawURLEncoding.EncodeToString([]byte(plaintext))
	if !strings.ContainsAny(urlSafe, "-_") {
		t.Fatal("URL-safe fixture must contain '-' or '_'")
	}

	tests := []struct {
		name    string
		content string
	}{
		{name: "plaintext", content: "\ufeff# comment\n\n" + plaintext},
		{name: "standard Base64", content: base64.StdEncoding.EncodeToString([]byte(plaintext))},
		{name: "raw standard Base64", content: base64.RawStdEncoding.EncodeToString([]byte(plaintext))},
		{name: "URL-safe Base64", content: urlSafe},
		{
			name: "wrapped Base64",
			content: func() string {
				encoded := base64.StdEncoding.EncodeToString([]byte(plaintext))
				return encoded[:12] + "\n  " + encoded[12:]
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseSubscription(tt.content)
			if err != nil {
				t.Fatalf("ParseSubscription() error = %v", err)
			}
			if strings.Join(got, "\n") != strings.Join(links, "\n") {
				t.Fatalf("ParseSubscription() = %q, want %q", got, links)
			}
		})
	}
}

func TestParseSubscriptionRejectsUnsupportedContentShape(t *testing.T) {
	_, err := ParseSubscription("proxies:\n  - name: node")
	if !errors.Is(err, ErrInvalidSubscription) {
		t.Fatalf("ParseSubscription() error = %v, want ErrInvalidSubscription", err)
	}
}

func TestParseSubscriptionPreservesTaggedAndChainedLinks(t *testing.T) {
	content := "preferred:vmess://dm1lc3M= -> tls://example.com:443"
	links, err := ParseSubscription(content)
	if err != nil {
		t.Fatalf("ParseSubscription() error = %v", err)
	}
	if len(links) != 1 || links[0] != content {
		t.Fatalf("ParseSubscription() = %q, want %q", links, content)
	}
}
