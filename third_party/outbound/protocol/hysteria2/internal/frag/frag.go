package frag

import (
	"fmt"

	"github.com/daeuniverse/outbound/protocol/hysteria2/internal/protocol"
)

func FragUDPMessage(m *protocol.UDPMessage, maxSize int) ([]protocol.UDPMessage, error) {
	if m.Size() <= maxSize {
		return []protocol.UDPMessage{*m}, nil
	}
	fullPayload := m.Data
	maxPayloadSize := maxSize - m.HeaderSize()
	if maxPayloadSize <= 0 {
		return nil, fmt.Errorf("hysteria2: datagram max size %d cannot hold UDP header of %d bytes", maxSize, m.HeaderSize())
	}
	fragCount := (len(fullPayload) + maxPayloadSize - 1) / maxPayloadSize // round up
	if fragCount > 255 {
		return nil, fmt.Errorf("hysteria2: datagram requires %d fragments, exceeds uint8 FragCount", fragCount)
	}
	off := 0
	fragID := uint8(0)
	frags := make([]protocol.UDPMessage, fragCount)
	for off < len(fullPayload) {
		payloadSize := len(fullPayload) - off
		if payloadSize > maxPayloadSize {
			payloadSize = maxPayloadSize
		}
		frag := *m
		frag.FragID = fragID
		frag.FragCount = uint8(fragCount)
		frag.Data = fullPayload[off : off+payloadSize]
		frags[fragID] = frag
		off += payloadSize
		fragID++
	}
	return frags, nil
}

// Defragger handles the defragmentation of UDP messages.
// The current implementation can only handle one packet ID at a time.
// If another packet arrives before a packet has received all fragments
// in their entirety, any previous state is discarded.
type Defragger struct {
	pktID  uint16
	frags  []*protocol.UDPMessage
	count  uint8
	size   int // data size
	closed bool
}

func (d *Defragger) Feed(m *protocol.UDPMessage) *protocol.UDPMessage {
	if d.closed {
		if m.Release != nil {
			m.Release()
		}
		return nil
	}
	if m.FragCount <= 1 {
		return m
	}
	if m.FragID >= m.FragCount {
		// wtf is this?
		if m.Release != nil {
			m.Release()
		}
		return nil
	}
	if m.PacketID != d.pktID || m.FragCount != uint8(len(d.frags)) {
		// new message, clear previous state: release the buffers of any
		// fragments that were still pending reassembly.
		d.releaseHeld()
		d.pktID = m.PacketID
		d.frags = make([]*protocol.UDPMessage, m.FragCount)
		d.frags[m.FragID] = m
		d.count = 1
		d.size = len(m.Data)
	} else if d.frags[m.FragID] == nil {
		d.frags[m.FragID] = m
		d.count++
		d.size += len(m.Data)
		if int(d.count) == len(d.frags) {
			// all fragments received, assemble
			data := make([]byte, d.size)
			off := 0
			for _, frag := range d.frags {
				off += copy(data[off:], frag.Data)
			}
			// Addr aliases the trigger fragment's pooled datagram.
			// Copy it before releaseHeld returns that buffer; otherwise
			// consumers parse a use-after-release slice and a later
			// pool Get can silently rewrite the UDP source address.
			addr := append([]byte(nil), m.Addr...)
			// The assembled payload lives in the freshly allocated data
			// slice; every fragment's backing buffer can now be returned
			// to its pool. The trigger fragment's Release must be cleared:
			// its buffer was already released by releaseHeld, and the
			// caller will (correctly) invoke Release on the returned
			// message - double-returning the same buffer to the pool
			// would hand one buffer to two consumers.
			d.releaseHeld()
			m.Addr = addr
			m.Data = data
			m.FragID = 0
			m.FragCount = 1
			m.Release = nil
			return m
		}
	} else if d.frags[m.FragID] != m && m.Release != nil {
		// A distinct duplicate doesn't contribute to reassembly, so its receive
		// buffer can be returned immediately. Keep the retained pointer alive if
		// a caller accidentally feeds the same message object twice.
		m.Release()
	}
	return nil
}

// releaseHeld returns the pooled storage of every held fragment — whether
// still pending reassembly (superseded by a newer message, or the defragger
// is closing) or just completed — and resets the defragger state.
func (d *Defragger) releaseHeld() {
	for _, frag := range d.frags {
		if frag != nil && frag.Release != nil {
			frag.Release()
		}
	}
	d.frags = nil
	d.count = 0
	d.size = 0
}

// Close returns any fragments still held for reassembly to their pools.
// Called when the owning session dies with an incomplete message in flight;
// without this, those pooled datagram buffers would be retained until the
// session object itself is garbage collected.
func (d *Defragger) Close() {
	d.closed = true
	d.releaseHeld()
}
