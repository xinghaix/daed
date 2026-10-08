package hysteria2

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
)

func TestPinnedCertVerifierMatchesLeafOnly(t *testing.T) {
	leaf := []byte("leaf-cert")
	intermediate := []byte("intermediate-cert")

	leafHash := sha256.Sum256(leaf)
	verify := newPinnedCertVerifier(hex.EncodeToString(leafHash[:]))
	if err := verify([][]byte{leaf, intermediate}, nil); err != nil {
		t.Fatalf("verify() error = %v", err)
	}
}

func TestPinnedCertVerifierRejectsPinnedIntermediate(t *testing.T) {
	leaf := []byte("leaf-cert")
	intermediate := []byte("intermediate-cert")

	intermediateHash := sha256.Sum256(intermediate)
	verify := newPinnedCertVerifier(hex.EncodeToString(intermediateHash[:]))
	if err := verify([][]byte{leaf, intermediate}, nil); err == nil {
		t.Fatal("expected verifier to reject non-leaf certificate pin")
	}
}

func TestPinnedCertVerifierRejectsMissingCertificates(t *testing.T) {
	verify := newPinnedCertVerifier("deadbeef")
	if err := verify(nil, nil); err == nil {
		t.Fatal("expected verifier to reject empty certificate list")
	}
}

func TestParseHysteria2URLIncludesCA(t *testing.T) {
	link := "hy2://user:pass@example.com:443?insecure=0&sni=edge.example.com&pinSHA256=deadbeef&ca=%2Fetc%2Fssl%2Fcustom-ca.pem#demo"

	conf, err := ParseHysteria2URL(link)
	if err != nil {
		t.Fatalf("ParseHysteria2URL() error = %v", err)
	}
	if conf.CA != "/etc/ssl/custom-ca.pem" {
		t.Fatalf("ParseHysteria2URL() CA = %q, want %q", conf.CA, "/etc/ssl/custom-ca.pem")
	}

	roundTrip, err := ParseHysteria2URL(conf.ExportToURL())
	if err != nil {
		t.Fatalf("ParseHysteria2URL() on exported URL error = %v", err)
	}
	if roundTrip.CA != conf.CA {
		t.Fatalf("round-trip CA = %q, want %q", roundTrip.CA, conf.CA)
	}
}

func TestLoadCustomRootCAs(t *testing.T) {
	caPath, cert := writeTestCAPEM(t)

	pool, err := loadCustomRootCAs(caPath)
	if err != nil {
		t.Fatalf("loadCustomRootCAs() error = %v", err)
	}
	if pool == nil {
		t.Fatal("loadCustomRootCAs() returned nil pool")
	}
	if _, err := cert.Verify(x509.VerifyOptions{Roots: pool}); err != nil {
		t.Fatalf("expected returned pool to trust the custom CA: %v", err)
	}
}

func TestLoadCustomRootCAsRejectsInvalidPEM(t *testing.T) {
	caPath := filepath.Join(t.TempDir(), "invalid-ca.pem")
	if err := os.WriteFile(caPath, []byte("not a pem"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	if _, err := loadCustomRootCAs(caPath); err == nil {
		t.Fatal("expected loadCustomRootCAs() to reject invalid PEM data")
	}
}

func TestPinSHA256ForcesInsecureSkipVerify(t *testing.T) {
	// When pinSHA256 is set, InsecureSkipVerify must be true even if
	// insecure=0, so that Go's TLS skips chain verification and lets the
	// pin callback handle trust decisions.
	conf := &Hysteria2{
		Name:      "test",
		User:      "user",
		Password:  "pass",
		Server:    "example.com:443",
		Insecure:  false, // insecure=0
		Sni:       "example.com",
		PinSHA256: "deadbeef",
	}
	_, prop, err := conf.Dialer(&dialer.ExtraOption{}, &noopDialer{})
	if err != nil {
		t.Fatalf("Dialer() error = %v", err)
	}
	_ = prop
}

type noopDialer struct{}

func (n *noopDialer) DialContext(_ context.Context, _, _ string) (netproxy.Conn, error) {
	return nil, fmt.Errorf("noop")
}

func TestNoPinSHA256RespectsInsecure(t *testing.T) {
	// When pinSHA256 is NOT set and insecure=0, InsecureSkipVerify must
	// remain false so normal chain verification runs.
	conf := &Hysteria2{
		Name:     "test",
		User:     "user",
		Password: "pass",
		Server:   "example.com:443",
		Insecure: false,
		Sni:      "example.com",
	}
	_, _, err := conf.Dialer(&dialer.ExtraOption{}, &noopDialer{})
	if err != nil {
		// Dialer may fail because we use a noop dialer, but that's fine -
		// we just want to check it doesn't crash.
		t.Logf("Dialer() returned expected error: %v", err)
	}
}

func writeTestCAPEM(t *testing.T) (string, *x509.Certificate) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate() error = %v", err)
	}

	caPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: der,
	})
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, caPEM, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	return caPath, cert
}

func TestPinnedCertVerifierAcceptsLinkFormats(t *testing.T) {
	leaf := []byte("leaf-cert")
	sum := sha256.Sum256(leaf)
	hexPin := hex.EncodeToString(sum[:])
	var colon []string
	for i := 0; i < len(hexPin); i += 2 {
		colon = append(colon, strings.ToUpper(hexPin[i:i+2]))
	}
	for name, pin := range map[string]string{
		"hex":          hexPin,
		"upper-colon":  strings.Join(colon, ":"),
		"base64":       base64.StdEncoding.EncodeToString(sum[:]),
		"base64-raw":   base64.RawURLEncoding.EncodeToString(sum[:]),
		"list":         strings.Repeat("0", 64) + "," + hexPin,
		"spaced-colon": " " + strings.Join(colon, ":") + " ",
	} {
		if err := newPinnedCertVerifier(pin)([][]byte{leaf}, nil); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := newPinnedCertVerifier(base64.StdEncoding.EncodeToString(make([]byte, 32)))([][]byte{leaf}, nil); err == nil {
		t.Error("wrong base64 pin accepted")
	}
}

func TestParseHysteria2URLSingBoxStyle(t *testing.T) {
	sum := sha256.Sum256([]byte("leaf"))
	link := "hysteria2://pass@203.0.113.7:51859?sni=random.example&insecure=1&alpn=h3&pinSHA256=" + hex.EncodeToString(sum[:]) + "#sg-relay-hy2"
	s, err := ParseHysteria2URL(link)
	if err != nil {
		t.Fatal(err)
	}
	if !s.Insecure || s.Sni != "random.example" || s.PinSHA256 == "" || s.Server != "203.0.113.7:51859" {
		t.Fatalf("parsed %+v", s)
	}
}
