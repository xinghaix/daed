package protocol

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/daeuniverse/outbound/protocol/hysteria2/errors"

	"github.com/olicesx/quic-go/quicvarint"
)

const (
	FrameTypeTCPRequest = 0x401

	// Max length values are for preventing DoS attacks

	MaxAddressLength = 2048
	MaxMessageLength = 2048
	MaxPaddingLength = 4096

	MaxUDPSize = 4096

	maxVarInt1 = 63
	maxVarInt2 = 16383
	maxVarInt4 = 1073741823
	maxVarInt8 = 4611686018427387903
)

// TCPRequest format:
// 0x401 (QUIC varint)
// Address length (QUIC varint)
// Address (bytes)
// Padding length (QUIC varint)
// Padding (bytes)

func ReadTCPRequest(r io.Reader) (string, error) {
	bReader := quicvarint.NewReader(r)
	addrLen, err := quicvarint.Read(bReader)
	if err != nil {
		return "", err
	}
	if addrLen == 0 || addrLen > MaxAddressLength {
		return "", errors.ProtocolError{Message: "invalid address length"}
	}
	addrBuf := make([]byte, addrLen)
	_, err = io.ReadFull(r, addrBuf)
	if err != nil {
		return "", err
	}
	paddingLen, err := quicvarint.Read(bReader)
	if err != nil {
		return "", err
	}
	if paddingLen > MaxPaddingLength {
		return "", errors.ProtocolError{Message: "invalid padding length"}
	}
	if paddingLen > 0 {
		_, err = io.CopyN(io.Discard, r, int64(paddingLen))
		if err != nil {
			return "", err
		}
	}
	return string(addrBuf), nil
}

func WriteTCPRequest(w io.Writer, addr string) error {
	paddingLen := tcpRequestPadding.randomLen()
	addrLen := len(addr)
	sz := int(quicvarint.Len(FrameTypeTCPRequest)) +
		int(quicvarint.Len(uint64(addrLen))) + addrLen +
		int(quicvarint.Len(uint64(paddingLen))) + paddingLen
	buf := make([]byte, sz)
	i := varintPut(buf, FrameTypeTCPRequest)
	i += varintPut(buf[i:], uint64(addrLen))
	i += copy(buf[i:], addr)
	i += varintPut(buf[i:], uint64(paddingLen))
	writeRandomBytes(buf[i : i+paddingLen])
	_, err := w.Write(buf)
	return err
}

// TCPResponse format:
// Status (byte, 0=ok, 1=error)
// Message length (QUIC varint)
// Message (bytes)
// Padding length (QUIC varint)
// Padding (bytes)

func ReadTCPResponse(r io.Reader) (bool, string, error) {
	var status [1]byte
	if _, err := io.ReadFull(r, status[:]); err != nil {
		return false, "", err
	}
	bReader := quicvarint.NewReader(r)
	msgLen, err := quicvarint.Read(bReader)
	if err != nil {
		return false, "", err
	}
	if msgLen > MaxMessageLength {
		return false, "", errors.ProtocolError{Message: "invalid message length"}
	}
	var msgBuf []byte
	// No message is fine
	if msgLen > 0 {
		msgBuf = make([]byte, msgLen)
		_, err = io.ReadFull(r, msgBuf)
		if err != nil {
			return false, "", err
		}
	}
	paddingLen, err := quicvarint.Read(bReader)
	if err != nil {
		return false, "", err
	}
	if paddingLen > MaxPaddingLength {
		return false, "", errors.ProtocolError{Message: "invalid padding length"}
	}
	if paddingLen > 0 {
		_, err = io.CopyN(io.Discard, r, int64(paddingLen))
		if err != nil {
			return false, "", err
		}
	}
	return status[0] == 0, string(msgBuf), nil
}

func WriteTCPResponse(w io.Writer, ok bool, msg string) error {
	paddingLen := tcpResponsePadding.randomLen()
	msgLen := len(msg)
	sz := 1 + int(quicvarint.Len(uint64(msgLen))) + msgLen +
		int(quicvarint.Len(uint64(paddingLen))) + paddingLen
	buf := make([]byte, sz)
	if ok {
		buf[0] = 0
	} else {
		buf[0] = 1
	}
	i := varintPut(buf[1:], uint64(msgLen))
	i += copy(buf[1+i:], msg)
	i += varintPut(buf[1+i:], uint64(paddingLen))
	writeRandomBytes(buf[1+i : 1+i+paddingLen])
	_, err := w.Write(buf)
	return err
}

// UDPMessage format:
// Session ID (uint32 BE)
// Packet ID (uint16 BE)
// Fragment ID (uint8)
// Fragment count (uint8)
// Address length (QUIC varint)
// Address (bytes)
// Data...

type UDPMessage struct {
	SessionID uint32 // 4
	PacketID  uint16 // 2
	FragID    uint8  // 1
	FragCount uint8  // 1
	// Addr is the wire address bytes ("host:port"). It stays a byte slice
	// so parsing subslices the datagram buffer instead of materializing a
	// string per inbound message; consumers compare against the cached
	// default target and only stringify non-default addresses.
	Addr []byte // varint + bytes
	Data []byte
	// Release returns the backing datagram buffer (when the message was
	// obtained via a pooled transport such as quic-go's ReceiveDatagram)
	// to its pool. Must be called exactly once when Data is no longer
	// referenced; nil when the message owns no pooled storage.
	Release func()
}

func (m *UDPMessage) HeaderSize() int {
	lAddr := len(m.Addr)
	return 4 + 2 + 1 + 1 + int(quicvarint.Len(uint64(lAddr))) + lAddr
}

func (m *UDPMessage) Size() int {
	return m.HeaderSize() + len(m.Data)
}

func (m *UDPMessage) Serialize(buf []byte) int {
	// Make sure the buffer is big enough
	if len(buf) < m.Size() {
		return -1
	}
	binary.BigEndian.PutUint32(buf, m.SessionID)
	binary.BigEndian.PutUint16(buf[4:], m.PacketID)
	buf[6] = m.FragID
	buf[7] = m.FragCount
	i := varintPut(buf[8:], uint64(len(m.Addr)))
	i += copy(buf[8+i:], m.Addr)
	i += copy(buf[8+i:], m.Data)
	return 8 + i
}

func ParseUDPMessage(msg []byte) (*UDPMessage, error) {
	// Fixed header: SessionID(4) + PacketID(2) + FragID(1) + FragCount(1) = 8 bytes.
	// Parse directly from the slice instead of routing four fields through
	// binary.Read (reflection) + bytes.Buffer wrapping. This mirrors Serialize.
	if len(msg) < 8 {
		return nil, errors.ProtocolError{Message: "invalid message: header too short"}
	}
	m := &UDPMessage{
		SessionID: binary.BigEndian.Uint32(msg[0:4]),
		PacketID:  binary.BigEndian.Uint16(msg[4:6]),
		FragID:    msg[6],
		FragCount: msg[7],
	}
	lAddr, n, err := quicvarint.Parse(msg[8:])
	if err != nil {
		return nil, err
	}
	if lAddr == 0 || lAddr > MaxMessageLength {
		return nil, errors.ProtocolError{Message: "invalid address length"}
	}
	body := msg[8+n:]
	if int64(lAddr) > int64(len(body))-1 {
		// We need at least one byte of data after the address.
		return nil, errors.ProtocolError{Message: "invalid message length"}
	}
	m.Addr = body[:lAddr]
	m.Data = body[lAddr:]
	return m, nil
}

// varintPut is like quicvarint.Append, but instead of appending to a slice,
// it writes to a fixed-size buffer. Returns the number of bytes written.
func varintPut(b []byte, i uint64) int {
	if i <= maxVarInt1 {
		b[0] = uint8(i)
		return 1
	}
	if i <= maxVarInt2 {
		b[0] = uint8(i>>8) | 0x40
		b[1] = uint8(i)
		return 2
	}
	if i <= maxVarInt4 {
		b[0] = uint8(i>>24) | 0x80
		b[1] = uint8(i >> 16)
		b[2] = uint8(i >> 8)
		b[3] = uint8(i)
		return 4
	}
	if i <= maxVarInt8 {
		b[0] = uint8(i>>56) | 0xc0
		b[1] = uint8(i >> 48)
		b[2] = uint8(i >> 40)
		b[3] = uint8(i >> 32)
		b[4] = uint8(i >> 24)
		b[5] = uint8(i >> 16)
		b[6] = uint8(i >> 8)
		b[7] = uint8(i)
		return 8
	}
	panic(fmt.Sprintf("%#x doesn't fit into 62 bits", i))
}
