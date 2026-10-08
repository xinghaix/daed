package congestion

import (
	"github.com/daeuniverse/outbound/protocol/tuic/congestion/bbr"
	"github.com/daeuniverse/outbound/protocol/tuic/congestion/bbr3"
	"github.com/daeuniverse/outbound/protocol/tuic/congestion/brutal"
	"github.com/olicesx/quic-go"
)

// UseBBR installs the Chromium-lineage BBRv1 sender.
func UseBBR(conn quic.Connection) {
	conn.SetCongestionControl(bbr.NewBbrSender(
		bbr.DefaultClock{},
		bbr.GetInitialPacketSize(conn.RemoteAddr()),
	))
}

// UseBbr3 installs the BBRv3-lineage sender. hintBps is the access-link upper
// bound in bytes per second; zero leaves the sender purely probing.
func UseBbr3(conn quic.Connection, hintBps uint64) {
	conn.SetCongestionControl(bbr3.NewBbr3Sender(
		bbr.GetInitialPacketSize(conn.RemoteAddr()),
		hintBps,
	))
}

// UseBrutal installs the fixed-rate Brutal sender.
func UseBrutal(conn quic.Connection, tx uint64) {
	conn.SetCongestionControl(brutal.NewBrutalSender(tx))
}
