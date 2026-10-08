package juicity

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/daeuniverse/outbound/common"
	"github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
)

func init() {
	dialer.FromLinkRegister("juicity", NewJuicity)
}

type Juicity struct {
	Name              string
	Server            string
	Port              int
	User              string
	Password          string
	Sni               string
	AllowInsecure     bool
	CongestionControl string
	// Cwnd is the congestion_control parameter: for "brutal" it carries the
	// target bandwidth in bytes per second (same convention as tuic).
	Cwnd                  int
	PinnedCertchainSha256 string
	Protocol              string
	// CCOverride is the client-local congestion controller override carried
	// by the "cc_override" query parameter. It is never sent to the server;
	// CongestionControl still supplies the value echoed in the handshake.
	CCOverride string
}

func NewJuicity(option *dialer.ExtraOption, nextDialer netproxy.Dialer, link string) (netproxy.Dialer, *dialer.Property, error) {
	s, err := ParseJuicityURL(link)
	if err != nil {
		return nil, nil, err
	}
	return s.Dialer(option, nextDialer)
}

func (s *Juicity) Dialer(option *dialer.ExtraOption, nextDialer netproxy.Dialer) (netproxy.Dialer, *dialer.Property, error) {
	d := nextDialer
	var err error
	tlsConfig := &tls.Config{
		NextProtos:         []string{"h3"},
		MinVersion:         tls.VersionTLS13,
		ServerName:         s.Sni,
		InsecureSkipVerify: s.AllowInsecure || option.AllowInsecure,
	}
	if s.PinnedCertchainSha256 != "" {
		pinnedHash, err := base64.URLEncoding.DecodeString(s.PinnedCertchainSha256)
		if err != nil {
			pinnedHash, err = base64.StdEncoding.DecodeString(s.PinnedCertchainSha256)
			if err != nil {
				pinnedHash, err = hex.DecodeString(s.PinnedCertchainSha256)
				if err != nil {
					return nil, nil, fmt.Errorf("failed to decode PinnedCertchainSha256")
				}
			}
		}
		tlsConfig.InsecureSkipVerify = true
		tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			if !bytes.Equal(common.GenerateCertChainHash(rawCerts), pinnedHash) {
				return fmt.Errorf("pinned hash of cert chain does not match")
			}
			return nil
		}
	}
	if d, err = protocol.NewDialer("juicity", d, protocol.Header{
		ProxyAddress: net.JoinHostPort(s.Server, strconv.Itoa(s.Port)),
		Feature1:     s.CongestionControl,
		Feature2:     s.Cwnd,
		// The override stays client-local: Feature1 above is what the server
		// echoes back and what unmodified servers understand.
		CongestionOverride: s.CCOverride,
		TlsConfig:          tlsConfig,
		User:               s.User,
		Password:           s.Password,
		IsClient:           true,
	}); err != nil {
		return nil, nil, err
	}
	return d, &dialer.Property{
		Name:     s.Name,
		Address:  net.JoinHostPort(s.Server, strconv.Itoa(s.Port)),
		Protocol: s.Protocol,
		Link:     s.ExportToURL(),
	}, nil
}

func ParseJuicityURL(u string) (data *Juicity, err error) {
	t, err := url.Parse(u)
	if err != nil {
		err = fmt.Errorf("invalid juicity format")
		return
	}
	allowInsecure := dialer.AllowInsecureFromQuery(t.Query())
	sni := dialer.SNIFromQuery(t.Query(), t.Hostname())
	port, err := strconv.Atoi(t.Port())
	if err != nil {
		return nil, dialer.InvalidParameterErr
	}
	password, _ := t.User.Password()
	data = &Juicity{
		Name:                  t.Fragment,
		Server:                t.Hostname(),
		Port:                  port,
		User:                  t.User.Username(),
		Password:              password,
		Sni:                   sni,
		AllowInsecure:         allowInsecure,
		CongestionControl:     t.Query().Get("congestion_control"),
		Cwnd:                  dialer.CwndFromQuery(t),
		PinnedCertchainSha256: t.Query().Get("pinned_certchain_sha256"),
		CCOverride:            strings.ToLower(strings.TrimSpace(t.Query().Get("cc_override"))),
		Protocol:              "juicity",
	}
	return data, nil
}

func (t *Juicity) ExportToURL() string {
	u := &url.URL{
		Scheme:   "juicity",
		User:     url.UserPassword(t.User, t.Password),
		Host:     net.JoinHostPort(t.Server, strconv.Itoa(t.Port)),
		Fragment: t.Name,
	}
	q := u.Query()
	if t.AllowInsecure {
		q.Set("allow_insecure", "1")
	}
	common.SetValue(&q, "sni", t.Sni)
	common.SetValue(&q, "congestion_control", t.CongestionControl)
	if t.Cwnd > 0 {
		common.SetValue(&q, "cwnd", strconv.Itoa(t.Cwnd))
	}
	common.SetValue(&q, "pinned_certchain_sha256", t.PinnedCertchainSha256)
	if t.CCOverride != "" {
		common.SetValue(&q, "cc_override", t.CCOverride)
	}
	u.RawQuery = q.Encode()
	return u.String()
}
