package anytls

import (
	"reflect"
	"testing"

	"github.com/daeuniverse/outbound/dialer"
	protocolanytls "github.com/daeuniverse/outbound/protocol/anytls"
	"github.com/daeuniverse/outbound/protocol/direct"
)

func TestDialerRespectsGlobalAllowInsecure(t *testing.T) {
	d, _, err := (&Anytls{
		Host: "example.com:443",
		Sni:  "example.com",
	}).Dialer(&dialer.ExtraOption{AllowInsecure: true}, direct.SymmetricDirect)
	if err != nil {
		t.Fatalf("Dialer() error = %v", err)
	}
	if !insecureSkipVerify(t, d) {
		t.Fatal("Dialer() did not propagate global AllowInsecure to tls.Config")
	}
}

func TestDialerRespectsNodeInsecure(t *testing.T) {
	d, _, err := (&Anytls{
		Host:     "example.com:443",
		Sni:      "example.com",
		Insecure: true,
	}).Dialer(&dialer.ExtraOption{}, direct.SymmetricDirect)
	if err != nil {
		t.Fatalf("Dialer() error = %v", err)
	}
	if !insecureSkipVerify(t, d) {
		t.Fatal("Dialer() did not propagate node insecure flag to tls.Config")
	}
}

func TestDialerKeepsVerificationEnabledByDefault(t *testing.T) {
	d, _, err := (&Anytls{
		Host: "example.com:443",
		Sni:  "example.com",
	}).Dialer(&dialer.ExtraOption{}, direct.SymmetricDirect)
	if err != nil {
		t.Fatalf("Dialer() error = %v", err)
	}
	if insecureSkipVerify(t, d) {
		t.Fatal("Dialer() unexpectedly disabled certificate verification")
	}
}

func insecureSkipVerify(t *testing.T, d any) bool {
	t.Helper()

	protocolDialer, ok := d.(*protocolanytls.Dialer)
	if !ok {
		t.Fatalf("Dialer() returned %T, want *protocolanytls.Dialer", d)
	}

	value := reflect.ValueOf(protocolDialer).Elem().FieldByName("tlsConfig")
	if !value.IsValid() || value.IsNil() {
		t.Fatal("protocol dialer tlsConfig is nil")
	}
	return value.Elem().FieldByName("InsecureSkipVerify").Bool()
}
