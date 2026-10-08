package hysteria2

import (
	"bytes"
	"encoding/base64"
	"errors"
	stdurl "net/url"
	"testing"

	"github.com/daeuniverse/outbound/dialer"
)

func TestParseHysteria2URLIncludesECH(t *testing.T) {
	want := testECHConfigList()
	encoded := base64.StdEncoding.EncodeToString(want)
	link := "hy2://user:pass@example.com:443?ech=" + stdurl.QueryEscape(encoded) + "&sni=real.example.com#demo"

	conf, err := ParseHysteria2URL(link)
	if err != nil {
		t.Fatalf("ParseHysteria2URL() error = %v", err)
	}
	if !bytes.Equal(conf.ECHConfigList, want) {
		t.Fatalf("ParseHysteria2URL() ECHConfigList = %x, want %x", conf.ECHConfigList, want)
	}

	exported := conf.ExportToURL()
	exportedURL, err := stdurl.Parse(exported)
	if err != nil {
		t.Fatalf("url.Parse(ExportToURL()) error = %v", err)
	}
	if got := exportedURL.Query().Get("ech"); got != encoded {
		t.Fatalf("ExportToURL() ech = %q, want %q", got, encoded)
	}
	roundTrip, err := ParseHysteria2URL(exported)
	if err != nil {
		t.Fatalf("ParseHysteria2URL(ExportToURL()) error = %v", err)
	}
	if !bytes.Equal(roundTrip.ECHConfigList, want) {
		t.Fatalf("round-trip ECHConfigList = %x, want %x", roundTrip.ECHConfigList, want)
	}
}

func TestParseHysteria2URLRejectsMalformedECH(t *testing.T) {
	malformed := base64.StdEncoding.EncodeToString([]byte{0x00, 0x00})
	link := "hy2://user@example.com:443?ech=" + stdurl.QueryEscape(malformed)

	_, err := ParseHysteria2URL(link)
	if !errors.Is(err, dialer.InvalidParameterErr) {
		t.Fatalf("ParseHysteria2URL() error = %v, want InvalidParameterErr", err)
	}
}
