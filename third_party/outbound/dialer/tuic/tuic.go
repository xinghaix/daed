package tuic

import (
	"crypto/tls"
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
	dialer.FromLinkRegister("tuic", NewTuic)
}

type Tuic struct {
	Name              string
	Server            string
	Port              int
	User              string
	Password          string
	Sni               string
	AllowInsecure     bool
	DisableSni        bool
	CongestionControl string
	// Cwnd is the congestion_control parameter: for "brutal" it carries the
	// target bandwidth in bytes per second (community convention, matching
	// sing-box and the tuic brutal forks).
	Cwnd         int
	Alpn         []string
	Protocol     string
	UdpRelayMode string
	// CCOverride is the client-local congestion controller override carried
	// by the "cc_override" query parameter. It is never sent to the server;
	// CongestionControl still supplies the value echoed in the handshake.
	CCOverride string
}

// newProtocolDialer is a test seam: production always calls protocol.NewDialer.
// It lets a test observe the header Dialer builds, including the client-local
// congestion controller override that must reach the protocol layer.
var newProtocolDialer = protocol.NewDialer

func NewTuic(option *dialer.ExtraOption, nextDialer netproxy.Dialer, link string) (netproxy.Dialer, *dialer.Property, error) {
	s, err := ParseTuicURL(link)
	if err != nil {
		return nil, nil, err
	}
	return s.Dialer(option, nextDialer)
}

func (s *Tuic) Dialer(option *dialer.ExtraOption, nextDialer netproxy.Dialer) (netproxy.Dialer, *dialer.Property, error) {
	d := nextDialer
	var err error
	var flags protocol.Flags
	if s.UdpRelayMode == "quic" {
		flags |= protocol.Flags_Tuic_UdpRelayModeQuic
	}
	if d, err = newProtocolDialer("tuic", d, protocol.Header{
		ProxyAddress: net.JoinHostPort(s.Server, strconv.Itoa(s.Port)),
		Feature1:     s.CongestionControl,
		Feature2:     s.Cwnd,
		// The override stays client-local: Feature1 above is what the server
		// echoes back and what unmodified servers understand.
		CongestionOverride: s.CCOverride,
		TlsConfig: &tls.Config{
			NextProtos:         s.Alpn,
			MinVersion:         tls.VersionTLS13,
			ServerName:         s.Sni,
			InsecureSkipVerify: s.AllowInsecure || option.AllowInsecure,
		},
		User:     s.User,
		Password: s.Password,
		IsClient: true,
		Flags:    flags,
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

func ParseTuicURL(u string) (data *Tuic, err error) {
	//trojan://password@server:port#escape(remarks)
	t, err := url.Parse(u)
	if err != nil {
		err = fmt.Errorf("invalid tuic format")
		return
	}
	var alpn []string
	if t.Query().Has("alpn") {
		alpn = strings.Split(t.Query().Get("alpn"), ",")
		for i := range alpn {
			alpn[i] = strings.TrimSpace(alpn[i])
		}
	}
	allowInsecure := dialer.AllowInsecureFromQuery(t.Query())
	sni := dialer.SNIFromQuery(t.Query(), t.Hostname())
	disableSni, _ := strconv.ParseBool(t.Query().Get("disable_sni"))
	if disableSni {
		sni = ""
		allowInsecure = true
	}
	port, err := strconv.Atoi(t.Port())
	if err != nil {
		return nil, dialer.InvalidParameterErr
	}
	password, _ := t.User.Password()
	data = &Tuic{
		Name:              t.Fragment,
		Server:            t.Hostname(),
		Port:              port,
		User:              t.User.Username(),
		Password:          password,
		Sni:               sni,
		AllowInsecure:     allowInsecure,
		DisableSni:        disableSni,
		CongestionControl: t.Query().Get("congestion_control"),
		Cwnd:              dialer.CwndFromQuery(t),
		Alpn:              alpn,
		UdpRelayMode:      strings.ToLower(t.Query().Get("udp_relay_mode")),
		CCOverride:        strings.ToLower(strings.TrimSpace(t.Query().Get("cc_override"))),
		Protocol:          "tuic",
	}
	return data, nil
}

func (t *Tuic) ExportToURL() string {
	u := &url.URL{
		Scheme:   "tuic",
		User:     url.UserPassword(t.User, t.Password),
		Host:     net.JoinHostPort(t.Server, strconv.Itoa(t.Port)),
		Fragment: t.Name,
	}
	q := u.Query()
	if t.AllowInsecure {
		q.Set("allow_insecure", "1")
	}
	common.SetValue(&q, "sni", t.Sni)
	if t.DisableSni {
		common.SetValue(&q, "disable_sni", "1")
	}
	if t.CongestionControl != "" {
		common.SetValue(&q, "congestion_control", t.CongestionControl)
	}
	if t.CCOverride != "" {
		common.SetValue(&q, "cc_override", t.CCOverride)
	}
	if t.Cwnd > 0 {
		common.SetValue(&q, "cwnd", strconv.Itoa(t.Cwnd))
	}
	if len(t.Alpn) > 0 {
		common.SetValue(&q, "alpn", strings.Join(t.Alpn, ","))
	}
	if t.UdpRelayMode != "" {
		common.SetValue(&q, "udp_relay_mode", t.UdpRelayMode)
	}

	u.RawQuery = q.Encode()
	return u.String()
}
