package protocol

import (
	"fmt"
	"strings"

	"github.com/daeuniverse/outbound/common"
)

var (
	ErrFailAuth     = fmt.Errorf("fail to authenticate")
	ErrReplayAttack = fmt.Errorf("replay attack")
	// ErrTimestampExpired reports a message whose timestamp fell outside the
	// accepted clock window. SIP022 §3.2.3 groups that with replay ("messages
	// with over 30 seconds of time difference MUST be treated as replay"), so
	// the packet is rejected exactly like a replay, but the cause is different:
	// a replay is an attacker or a duplicate, a stale timestamp is usually
	// clock skew or a long-lived session. It is a distinct sentinel rather than
	// a wrapper so a caller can tell the two apart with errors.Is; callers that
	// must keep treating both as "drop the packet, keep the transport alive"
	// have to check for both.
	ErrTimestampExpired = fmt.Errorf("timestamp expired")
)

type Protocol string

const (
	ProtocolVMessTCP     Protocol = "vmess"
	ProtocolVMessTlsGrpc Protocol = "vmess+tls+grpc"
	ProtocolShadowsocks  Protocol = "shadowsocks"
	ProtocolJuicity      Protocol = "juicity"
)

func (p Protocol) Valid() bool {
	switch p {
	case ProtocolVMessTCP, ProtocolVMessTlsGrpc, ProtocolShadowsocks, ProtocolJuicity:
		return true
	default:
		return false
	}
}

func (p Protocol) WithTLS() bool {
	return common.StringsHas(strings.Split(string(p), "+"), "tls")
}
