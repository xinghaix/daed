package tuic

import (
	"bytes"
	"errors"
	"net/netip"
	"testing"

	"github.com/daeuniverse/outbound/protocol/tuic/common"
)

// buildPacketMessageForTest serializes a well-formed TUIC Packet command for
// the given association, so the classifier can be shown not to over-trigger on
// valid traffic. Mirrors buildPacketMessage (the benchmark helper), which
// takes a *testing.B.
func buildPacketMessageForTest(t *testing.T, assocID uint16, payload []byte) []byte {
	t.Helper()
	addr := NewAddressAddrPort(netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), 8080))
	pkt := NewPacket(assocID, 1, 1, 0, uint16(len(payload)), addr, payload, Ver5)
	var buf bytes.Buffer
	if err := pkt.WriteTo(&buf); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	return buf.Bytes()
}

// malformedDatagramCases are byte strings a hostile or broken peer can put on
// the wire. Every one of them reaches readPacketFromMessage and fails on the
// peer's own bytes, so every one must be dropped rather than retire the shared
// tunnel.
var malformedDatagramCases = []struct {
	name string
	msg  []byte
}{
	{"empty", []byte{}},
	{"single-byte", []byte{Ver5}},
	{"header-only", []byte{Ver5, byte(PacketType)}},
	{"truncated-fixed-header", []byte{Ver5, byte(PacketType), 0x00, 0x01}},
	// Every case below is a PacketType datagram whose body is truncated or
	// malformed, i.e. the shape a peer actually produces. A datagram carrying
	// an unassigned command type is covered separately by
	// TestUnassignedCommandTypeDoesNotRetireTunnel: processDatagram's switch
	// dispatches on the command type before the parser runs, so it is a
	// different code path and must not be conflated with the classifier.
	{"unknown-address-type", append([]byte{Ver5, byte(PacketType), 0, 1, 0, 1, 1, 0, 0, 8}, 0x7f)},
	{"ipv4-address-truncated", append([]byte{Ver5, byte(PacketType), 0, 1, 0, 1, 1, 0, 0, 0}, AtypIPv4, 127, 0)},
	{"ipv6-address-truncated", append([]byte{Ver5, byte(PacketType), 0, 1, 0, 1, 1, 0, 0, 0}, AtypIPv6, 0x20, 0x01)},
	{"domain-length-missing", append([]byte{Ver5, byte(PacketType), 0, 1, 0, 1, 1, 0, 0, 0}, AtypDomainName)},
	{"domain-truncated", append([]byte{Ver5, byte(PacketType), 0, 1, 0, 1, 1, 0, 0, 0, AtypDomainName, 20}, []byte("short")...)},
	{"port-missing", append([]byte{Ver5, byte(PacketType), 0, 1, 0, 1, 1, 0, 0, 0, AtypIPv4, 127, 0, 0, 1}, 0x00)},
	{"data-truncated", append([]byte{Ver5, byte(PacketType), 0, 1, 0, 1, 1, 0, 0x10, 0x00, AtypIPv4, 127, 0, 0, 1, 0x00, 0x35}, []byte("only-a-few")...)},
}

// TestUnassignedCommandTypeDoesNotRetireTunnel pins the switch dispatch: a
// datagram whose command type matches neither PacketType nor HeartbeatType
// never reaches the parser, so it must be neither counted as malformed nor
// allowed to retire the tunnel.
func TestUnassignedCommandTypeDoesNotRetireTunnel(t *testing.T) {
	conn := newCancelTestConn()
	c := newCancelTestClient(t, conn)
	c.processDatagram(conn, []byte{Ver5, 0x7f, 0, 1, 0, 1, 1, 0, 0, 0, 0})
	if c.closed.Load() {
		t.Fatal("shared tunnel retired by an unassigned command type")
	}
	if stats := c.MalformedDatagramStats(); stats.MalformedDatagrams != 0 {
		t.Fatalf("MalformedDatagrams = %d, want 0: the parser never ran", stats.MalformedDatagrams)
	}
}

// malformedFloodDatagram returns a datagram that processDatagram always
// classifies as malformed: too short to carry a command header, so no valid
// interpretation of it exists.
func malformedFloodDatagram() []byte { return []byte{Ver5} }

// TestReadPacketFromMessageClassifiesMalformed pins the P2-11 sentinel: every
// peer-data parse failure must be errors.Is(err, errMalformedDatagram) so the
// receive loop can tell it apart from a broken connection.
func TestReadPacketFromMessageClassifiesMalformed(t *testing.T) {
	for _, tc := range malformedDatagramCases {
		t.Run(tc.name, func(t *testing.T) {
			pkt, err := readPacketFromMessage(tc.msg)
			if err == nil {
				t.Fatalf("readPacketFromMessage(%v) = %v, want an error", tc.msg, pkt)
			}
			if !errors.Is(err, errMalformedDatagram) {
				t.Fatalf("error %v is not classified as errMalformedDatagram", err)
			}
		})
	}
}

// TestMalformedDatagramDoesNotRetireTunnel is the P2-11 regression: before the
// fix, processDatagram assigned the parse error to the deferred `err`, and
// deferQuicConn tore down the shared QUIC connection — taking every
// multiplexed TCP stream and every other UDP association with it. One peer's
// garbage datagram must not do that.
func TestMalformedDatagramDoesNotRetireTunnel(t *testing.T) {
	conn := newCancelTestConn()
	c := newCancelTestClient(t, conn)

	for _, tc := range malformedDatagramCases {
		c.processDatagram(conn, tc.msg)
		if c.closed.Load() {
			t.Fatalf("%s: shared tunnel retired by a malformed datagram", tc.name)
		}
	}

	stats := c.MalformedDatagramStats()
	if stats.MalformedDatagrams != uint64(len(malformedDatagramCases)) {
		t.Fatalf("MalformedDatagrams = %d, want %d", stats.MalformedDatagrams, len(malformedDatagramCases))
	}
	if stats.MalformedDatagramsWindow != uint64(len(malformedDatagramCases)) {
		t.Fatalf("MalformedDatagramsWindow = %d, want %d", stats.MalformedDatagramsWindow, len(malformedDatagramCases))
	}
}

// TestMalformedDatagramEscalatesAtThreshold pins the bounded side of the
// classification: dropping forever is a silent degradation, so a peer that
// cannot produce a single valid datagram is retired once it crosses the
// threshold, and the counter stays observable.
func TestMalformedDatagramEscalatesAtThreshold(t *testing.T) {
	conn := newCancelTestConn()
	c := newCancelTestClient(t, conn)
	msg := malformedFloodDatagram()

	for i := 0; i < malformedDatagramEscalationThreshold-1; i++ {
		c.processDatagram(conn, msg)
	}
	if c.closed.Load() {
		t.Fatalf("tunnel retired at %d malformed datagrams, want retirement only at %d",
			malformedDatagramEscalationThreshold-1, malformedDatagramEscalationThreshold)
	}

	c.processDatagram(conn, msg)
	if !c.closed.Load() {
		t.Fatalf("tunnel still alive after %d malformed datagrams, want retirement",
			malformedDatagramEscalationThreshold)
	}
	stats := c.MalformedDatagramStats()
	if stats.MalformedDatagrams != malformedDatagramEscalationThreshold {
		t.Fatalf("MalformedDatagrams = %d, want %d", stats.MalformedDatagrams, malformedDatagramEscalationThreshold)
	}
	if stats.MalformedDatagramsWindow != 0 {
		t.Fatalf("MalformedDatagramsWindow = %d after escalation, want the window reset", stats.MalformedDatagramsWindow)
	}
}

// TestMalformedDatagramWindowIsIndependentOfLifetimeTotal pins that the
// escalation window resets while the lifetime counter keeps accumulating, so
// an operator can still tell "one bad burst" from "a permanently broken peer".
func TestMalformedDatagramWindowIsIndependentOfLifetimeTotal(t *testing.T) {
	conn := newCancelTestConn()
	c := newCancelTestClient(t, conn)
	msg := malformedFloodDatagram()

	for burst := 0; burst < 2; burst++ {
		for i := 0; i < malformedDatagramEscalationThreshold; i++ {
			c.processDatagram(conn, msg)
		}
		stats := c.MalformedDatagramStats()
		wantTotal := uint64((burst + 1) * malformedDatagramEscalationThreshold)
		if stats.MalformedDatagrams != wantTotal {
			t.Fatalf("burst %d: MalformedDatagrams = %d, want %d", burst, stats.MalformedDatagrams, wantTotal)
		}
		if stats.MalformedDatagramsWindow != 0 {
			t.Fatalf("burst %d: window = %d, want it reset at the threshold", burst, stats.MalformedDatagramsWindow)
		}
	}
}

// TestMalformedDatagramIsNotCountedForValidTraffic pins that the classifier
// does not over-trigger: well-formed datagrams still reach the association
// queue without touching the malformed counters.
func TestMalformedDatagramIsNotCountedForValidTraffic(t *testing.T) {
	conn := newCancelTestConn()
	c := newCancelTestClient(t, conn)

	packets := NewPackets()
	c.udpIncomingPacketsMap.Store(uint16(7), packets)

	msg := buildPacketMessageForTest(t, 7, []byte("hello"))
	c.processDatagram(conn, msg)
	c.processDatagram(conn, msg)
	stats := c.MalformedDatagramStats()
	if stats.MalformedDatagrams != 0 {
		t.Fatalf("MalformedDatagrams = %d for valid datagrams, want 0", stats.MalformedDatagrams)
	}
	for i := 0; i < 2; i++ {
		pkt, closed := packets.PopFrontBlock()
		if closed || pkt == nil {
			t.Fatalf("packet %d not delivered: closed=%v pkt=%v", i, closed, pkt)
		}
		if string(pkt.DATA) != "hello" {
			t.Fatalf("packet %d DATA = %q, want %q", i, pkt.DATA, "hello")
		}
		pkt.releaseData()
	}
}

// TestNoteMalformedDatagramLogIsRateLimited pins the anti-log-spam guard: a
// datagram flood must not produce one log line per datagram.
func TestNoteMalformedDatagramLogIsRateLimited(t *testing.T) {
	c := newClientImpl(&ClientOption{UdpRelayMode: common.NATIVE}, true, 4)
	for i := 0; i < 1000; i++ {
		c.noteMalformedDatagram(nil, nil, "rate-limit probe")
	}
	if got := c.MalformedDatagramStats().MalformedDatagrams; got != 1000 {
		t.Fatalf("MalformedDatagrams = %d, want 1000 (counting must not be rate-limited)", got)
	}
	if got := c.lastMalformedLogNano.Load(); got == 0 {
		t.Fatal("no log timestamp recorded, want the first drop to log")
	}
}
