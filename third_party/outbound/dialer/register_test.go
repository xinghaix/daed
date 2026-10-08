package dialer_test

import (
	"testing"

	"github.com/daeuniverse/outbound/dialer"
	_ "github.com/daeuniverse/outbound/dialer/shadowsocks"
	_ "github.com/daeuniverse/outbound/protocol/shadowsocks_2022"
)

func TestNewNetproxyDialerFromLinkAcceptsPlainSSPasswordWithSlash(t *testing.T) {
	const password = "RCF/0OOYmo6crue3LwlEyD8izLAbuUuyPic/vasJH/o="
	link := "ss://2022-blake3-aes-256-gcm:" + password + "@127.0.0.1:443#test"
	base, _ := dialer.NewDirectDialer(&dialer.ExtraOption{}, false)

	_, property, err := dialer.NewNetproxyDialerFromLink(base, &dialer.ExtraOption{}, link)
	if err != nil {
		t.Fatalf("NewNetproxyDialerFromLink failed: %v", err)
	}
	if property.Name != "test" {
		t.Fatalf("unexpected property name: %q", property.Name)
	}
	if property.Address != "127.0.0.1:443" {
		t.Fatalf("unexpected property address: %q", property.Address)
	}
}
