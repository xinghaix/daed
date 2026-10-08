package trojanc

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"

	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol"
)

func ParseMetadataType(t byte) protocol.MetadataType {
	switch t {
	case 1:
		return protocol.MetadataTypeIPv4
	case 2:
		return protocol.MetadataTypeMsg
	case 3:
		return protocol.MetadataTypeDomain
	case 4:
		return protocol.MetadataTypeIPv6
	default:
		return protocol.MetadataTypeInvalid
	}
}

func MetadataTypeToByte(typ protocol.MetadataType) byte {
	switch typ {
	case protocol.MetadataTypeIPv4:
		return 1
	case protocol.MetadataTypeMsg:
		return 2
	case protocol.MetadataTypeDomain:
		return 3
	case protocol.MetadataTypeIPv6:
		return 4
	default:
		return 0
	}
}

func ParseNetwork(n byte) string {
	switch n {
	case 1:
		return "tcp"
	case 3:
		return "udp"
	default:
		return "invalid"
	}
}

func NetworkToByte(network string) byte {
	switch network {
	case "tcp":
		return 1
	case "udp":
		return 3
	default:
		return 0
	}
}

type Metadata struct {
	protocol.Metadata
	Network string
}

var (
	ErrInvalidMetadata = fmt.Errorf("invalid metadata")
)

func (m *Metadata) Len() int {
	switch m.Type {
	case protocol.MetadataTypeIPv4:
		return 3 + 4
	case protocol.MetadataTypeIPv6:
		return 3 + 16
	case protocol.MetadataTypeDomain:
		return 4 + len([]byte(m.Hostname))
	case protocol.MetadataTypeMsg:
		return 2
	default:
		return 0
	}
}

func (m *Metadata) PackTo(dst []byte) (n int) {
	dst[0] = MetadataTypeToByte(m.Type)
	switch m.Type {
	case protocol.MetadataTypeIPv4:
		copy(dst[1:], net.ParseIP(m.Hostname).To4()[:4])
		binary.BigEndian.PutUint16(dst[5:], m.Port)
		return 7
	case protocol.MetadataTypeIPv6:
		copy(dst[1:], net.ParseIP(m.Hostname)[:16])
		binary.BigEndian.PutUint16(dst[17:], m.Port)
		return 19
	case protocol.MetadataTypeDomain:
		dst[1] = byte(len([]byte(m.Hostname)))
		copy(dst[2:], m.Hostname)
		binary.BigEndian.PutUint16(dst[2+dst[1]:], m.Port)
		return 4 + int(dst[1])
	case protocol.MetadataTypeMsg:
		dst[1] = byte(m.Cmd)
		return 2
	default:
		return 0
	}
}

func (m *Metadata) Unpack(r io.Reader) (n int, err error) {
	// The domain branch reads up to 2+255 hostname bytes plus a 2-byte port
	// (4+maxDomainLen in total); the buffer must cover the full range or a
	// legal 253..255 byte hostname panics on the slice below.
	const (
		maxDomainLen   = 255
		maxMetadataLen = 4 + maxDomainLen
	)
	buf := pool.Get(maxMetadataLen)
	defer buf.Put()
	if _, err = io.ReadFull(r, buf[:2]); err != nil {
		return 0, err
	}
	m.Type = ParseMetadataType(buf[0])
	switch m.Type {
	case protocol.MetadataTypeIPv4:
		if _, err = io.ReadFull(r, buf[2:7]); err != nil {
			return 0, err
		}
		m.Hostname = net.IP(buf[1:5]).String()
		m.Port = binary.BigEndian.Uint16(buf[5:])
		return 7, nil
	case protocol.MetadataTypeIPv6:
		if _, err = io.ReadFull(r, buf[2:19]); err != nil {
			return 0, err
		}
		m.Hostname = net.IP(buf[1:17]).String()
		m.Port = binary.BigEndian.Uint16(buf[17:])
		return 19, nil
	case protocol.MetadataTypeDomain:
		// Cast the length to int before the arithmetic: as a byte
		// expression 2+buf[1] wraps mod 256 (255 -> 1) and panics.
		domainLen := int(buf[1])
		if _, err = io.ReadFull(r, buf[2:4+domainLen]); err != nil {
			return 0, err
		}
		m.Hostname = string(buf[2 : 2+domainLen])
		m.Port = binary.BigEndian.Uint16(buf[2+domainLen:])
		return 4 + domainLen, nil
	case protocol.MetadataTypeMsg:
		m.Cmd = protocol.MetadataCmd(buf[1])
		return 2, nil
	default:
		return 0, fmt.Errorf("unexpected metadata type: %v", m.Type)
	}
}
