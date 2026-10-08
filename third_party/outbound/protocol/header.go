package protocol

import "crypto/tls"

type Header struct {
	ProxyAddress string
	SNI          string
	// Feature1 carries a protocol-specific, per-protocol-typed value. The type
	// is part of each protocol's contract, and every dialer must type-assert it
	// with the ok form and return a descriptive error on mismatch instead of
	// panicking, because Header is an exported API:
	//   hysteria2     -> *hysteria2.Feature1
	//   vmess         -> string (the gRPC service name)
	//   vless         -> string (the flow value)
	//   tuic, juicity -> string (the server-echoed congestion controller)
	Feature1 interface{}
	Feature2 interface{}
	// CongestionOverride is a client-local congestion controller override. It
	// is never sent to the server: Feature1 keeps carrying the value that the
	// handshake echoes back. Empty means "use the server-echoed controller".
	CongestionOverride string
	TlsConfig          *tls.Config
	Cipher             string
	User               string
	Password           string
	IsClient           bool
	Flags              Flags
}

type Flags uint64

const (
	Flags_VMess_UsePacketAddr = 1 << iota
)

const (
	Flags_Tuic_UdpRelayModeQuic = 1 << iota
)
