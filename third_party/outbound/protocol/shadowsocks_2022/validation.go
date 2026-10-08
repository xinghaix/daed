package shadowsocks_2022

import (
	"time"

	"github.com/daeuniverse/outbound/ciphers"
	"github.com/daeuniverse/outbound/protocol"
)

// validateTimestamp enforces the SIP022 §3.2.3 clock window on a message
// timestamp. An out-of-window timestamp is rejected with ErrTimestampExpired
// rather than ErrReplayAttack so an operator can tell clock skew from a genuine
// replay. Both are still rejected and both are still per-packet rejections that
// leave the transport untouched, so nothing about whether a packet is dropped
// depends on the new classification; only its reporting does. The UDP payload
// decoder and the TCP response reader both funnel through here, so the
// distinction covers both transports.
func validateTimestamp(timestamp time.Time, now time.Time) error {
	if timestamp.Before(now.Add(-ciphers.TimestampTolerance)) ||
		timestamp.After(now.Add(ciphers.TimestampTolerance)) {
		return protocol.ErrTimestampExpired
	}
	return nil
}
