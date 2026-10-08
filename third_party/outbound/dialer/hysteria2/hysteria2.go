package hysteria2

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/daeuniverse/outbound/common/bandwidth"
	"github.com/daeuniverse/outbound/common/url"
	"github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/hysteria2"
	"github.com/daeuniverse/outbound/protocol/hysteria2/client"
)

func init() {
	dialer.FromLinkRegister("hysteria2", NewHysteria2)
	dialer.FromLinkRegister("hy2", NewHysteria2)
}

type Hysteria2 struct {
	Name          string
	User          string
	Password      string
	Server        string
	Insecure      bool
	Sni           string
	PinSHA256     string
	CA            string
	ECHConfigList []byte
	MaxTx         uint64
	MaxRx         uint64
	ObfsPassword  string
	// CCOverride is the client-local congestion controller override carried
	// by the "cc_override" query parameter. It is never sent to the server.
	CCOverride string
}

func NewHysteria2(option *dialer.ExtraOption, nextDialer netproxy.Dialer, link string) (netproxy.Dialer, *dialer.Property, error) {
	s, err := ParseHysteria2URL(link)
	if err != nil {
		return nil, nil, err
	}
	return s.Dialer(option, nextDialer)
}

func (s *Hysteria2) Dialer(option *dialer.ExtraOption, nextDialer netproxy.Dialer) (netproxy.Dialer, *dialer.Property, error) {
	d := nextDialer
	// When pinSHA256 is set, certificate pin verification replaces chain
	// verification. Force InsecureSkipVerify so that Go's TLS skips chain
	// verification; the pin callback handles all trust decisions.
	skipVerify := s.Insecure || option.AllowInsecure || s.PinSHA256 != ""
	tlsConfig := &tls.Config{
		ServerName:                     s.Sni,
		InsecureSkipVerify:             skipVerify,
		EncryptedClientHelloConfigList: s.ECHConfigList,
	}
	if s.CA != "" {
		rootCAs, err := loadCustomRootCAs(s.CA)
		if err != nil {
			return nil, nil, err
		}
		tlsConfig.RootCAs = rootCAs
	}
	header := protocol.Header{
		ProxyAddress: s.Server,
		TlsConfig:    tlsConfig,
		SNI:          s.Sni,
		User:         s.User,
		Password:     s.Password,
		IsClient:     true,
		// Client-local cc_override; the hysteria2 auth request carries no
		// congestion controller, so nothing about this reaches the server.
		CongestionOverride: s.CCOverride,
	}

	feature1 := &hysteria2.Feature1{
		UDPHopInterval: option.UDPHopInterval,
		ObfsPassword:   s.ObfsPassword,
	}
	if s.MaxTx > 0 && s.MaxRx > 0 {
		feature1.BandwidthConfig = client.BandwidthConfig{
			MaxRx: s.MaxRx,
			MaxTx: s.MaxTx,
		}
	} else if option.BandwidthMaxRx != "" && option.BandwidthMaxTx != "" {
		maxRx, err := bandwidth.Parse(option.BandwidthMaxRx)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid bandwidth value for MaxRx: %w", err)
		}
		maxTx, err := bandwidth.Parse(option.BandwidthMaxTx)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid bandwidth value for MaxTx: %w", err)
		}
		if maxRx > 0 && maxTx > 0 {
			feature1.BandwidthConfig = client.BandwidthConfig{
				MaxRx: maxRx,
				MaxTx: maxTx,
			}
		}
	}
	header.Feature1 = feature1

	if s.PinSHA256 != "" {
		header.TlsConfig.VerifyPeerCertificate = newPinnedCertVerifier(s.PinSHA256)
	}
	var err error
	if d, err = protocol.NewDialer("hysteria2", d, header); err != nil {
		return nil, nil, err
	}
	return d, &dialer.Property{
		Name:     s.Name,
		Address:  s.Server,
		Protocol: "hysteria2",
		Link:     s.ExportToURL(),
	}, nil
}

func normalizeCertHash(hash string) string {
	r := strings.ToLower(hash)
	r = strings.ReplaceAll(r, ":", "")
	r = strings.ReplaceAll(r, "-", "")
	return r
}

func newPinnedCertVerifier(pinSHA256 string) func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	nHash := normalizeCertHash(pinSHA256)
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return fmt.Errorf("no peer certificate provided")
		}
		hash := sha256.Sum256(rawCerts[0])
		hashHex := hex.EncodeToString(hash[:])
		if hashHex != nHash {
			return fmt.Errorf("leaf certificate pin mismatch: %s != %s", hashHex, nHash)
		}
		return nil
	}
}

func loadCustomRootCAs(caPath string) (*x509.CertPool, error) {
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("load custom CA %q: %w", caPath, err)
	}
	rootCAs := x509.NewCertPool()
	if !rootCAs.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("load custom CA %q: failed to parse PEM certificate", caPath)
	}
	return rootCAs, nil
}

// ref: https://v2.hysteria.network/zh/docs/developers/URI-Scheme/
func ParseHysteria2URL(link string) (*Hysteria2, error) {
	// TODO: support salamander obfuscation
	u, err := url.Parse(link)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	var insecure bool
	if insecureValue := q.Get("insecure"); insecureValue != "" {
		insecure, err = strconv.ParseBool(q.Get("insecure"))
		if err != nil {
			return nil, dialer.InvalidParameterErr
		}
	}
	var maxTx, maxRx uint64
	// upmbps/downmbps: hysteria2 official / sing-box style bandwidth
	// declarations in Mbps, usable individually. Converted to bytes per
	// second (Mbps * 1_000_000 / 8) for the underlying BandwidthConfig.
	if up := q.Get("upmbps"); up != "" {
		v, err := strconv.ParseUint(up, 10, 64)
		if err != nil {
			return nil, dialer.InvalidParameterErr
		}
		maxTx = v * 1_000_000 / 8
	}
	if down := q.Get("downmbps"); down != "" {
		v, err := strconv.ParseUint(down, 10, 64)
		if err != nil {
			return nil, dialer.InvalidParameterErr
		}
		maxRx = v * 1_000_000 / 8
	}
	// Legacy dae-style maxTx/maxRx in raw bytes per second; both must be
	// present together. Only fills dimensions not already set by
	// upmbps/downmbps so mixed forms (e.g. upmbps + maxRx) behave sanely.
	if q.Get("maxTx") != "" && q.Get("maxRx") != "" {
		if maxTx == 0 {
			maxTx, err = strconv.ParseUint(q.Get("maxTx"), 10, 64)
			if err != nil {
				return nil, dialer.InvalidParameterErr
			}
		}
		if maxRx == 0 {
			maxRx, err = strconv.ParseUint(q.Get("maxRx"), 10, 64)
			if err != nil {
				return nil, dialer.InvalidParameterErr
			}
		}
	}
	var obfsPassword string
	if obfsType := q.Get("obfs"); obfsType != "" {
		switch strings.ToLower(obfsType) {
		case "salamander":
			obfsPassword = q.Get("obfs-password")
			if obfsPassword == "" {
				return nil, fmt.Errorf("%w: obfs=salamander requires obfs-password", dialer.InvalidParameterErr)
			}
		case "gecko":
			return nil, fmt.Errorf("%w: obfs=gecko is not supported yet", dialer.InvalidParameterErr)
		default:
			return nil, fmt.Errorf("%w: unknown obfs type %q", dialer.InvalidParameterErr, obfsType)
		}
	}
	var echConfigList []byte
	if ech := q.Get("ech"); ech != "" {
		echConfigList, err = decodeECHConfigList(ech)
		if err != nil {
			return nil, fmt.Errorf("%w: ech: %w", dialer.InvalidParameterErr, err)
		}
	}
	conf := &Hysteria2{
		Name:          u.Fragment,
		User:          u.User.Username(),
		Server:        u.Host,
		Insecure:      insecure,
		Sni:           q.Get("sni"),
		PinSHA256:     q.Get("pinSHA256"),
		CA:            q.Get("ca"),
		ECHConfigList: echConfigList,
		MaxTx:         maxTx,
		MaxRx:         maxRx,
		ObfsPassword:  obfsPassword,
		CCOverride:    strings.ToLower(strings.TrimSpace(q.Get("cc_override"))),
	}
	conf.Password, _ = u.User.Password()
	return conf, nil
}

func (s *Hysteria2) ExportToURL() string {
	t := url.URL{
		Scheme:   "hysteria2",
		Host:     s.Server,
		User:     url.User(s.User),
		Fragment: s.Name,
	}
	if s.Password != "" {
		t.User = url.UserPassword(s.User, s.Password)
	}
	q := t.Query()
	if s.Insecure {
		q.Set("insecure", "1")
	}
	if s.Sni != "" {
		q.Set("sni", s.Sni)
	}
	if s.PinSHA256 != "" {
		q.Set("pinSHA256", s.PinSHA256)
	}
	if s.CA != "" {
		q.Set("ca", s.CA)
	}
	if len(s.ECHConfigList) > 0 {
		q.Set("ech", base64.StdEncoding.EncodeToString(s.ECHConfigList))
	}
	if s.MaxTx > 0 && s.MaxRx > 0 {
		q.Set("maxTx", strconv.FormatUint(s.MaxTx, 10))
		q.Set("maxRx", strconv.FormatUint(s.MaxRx, 10))
	}
	if s.CCOverride != "" {
		q.Set("cc_override", s.CCOverride)
	}
	t.RawQuery = q.Encode()
	return t.String()
}
