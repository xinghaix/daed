package shadowsocks

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"

	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol"
)

func ParseMetadataType(t byte) protocol.MetadataType {
	switch t {
	case 1:
		return protocol.MetadataTypeIPv4
	case 3:
		return protocol.MetadataTypeDomain
	case 4:
		return protocol.MetadataTypeIPv6
	case 5:
		return protocol.MetadataTypeMsg
	default:
		return protocol.MetadataTypeInvalid
	}
}

func MetadataTypeToByte(typ protocol.MetadataType) byte {
	switch typ {
	case protocol.MetadataTypeIPv4:
		return 1
	case protocol.MetadataTypeDomain:
		return 3
	case protocol.MetadataTypeIPv6:
		return 4
	case protocol.MetadataTypeMsg:
		return 5
	default:
		return 0
	}
}

type Metadata struct {
	protocol.Metadata
	LenMsgBody uint32
}

var (
	ErrInvalidMetadata = fmt.Errorf("invalid metadata")
)

func BytesSizeForMetadata(firstTwoByte []byte) (int, error) {
	if len(firstTwoByte) < 2 {
		return 0, fmt.Errorf("%w: too short", ErrInvalidMetadata)
	}
	switch ParseMetadataType(firstTwoByte[0]) {
	case protocol.MetadataTypeIPv4:
		return 1 + 4 + 2, nil
	case protocol.MetadataTypeIPv6:
		return 1 + 16 + 2, nil
	case protocol.MetadataTypeDomain:
		lenDN := int(firstTwoByte[1])
		return 1 + 1 + lenDN + 2, nil
	case protocol.MetadataTypeMsg:
		return 1 + 1 + 4, nil
	default:
		return 0, fmt.Errorf("BytesSizeForMetadata: %w: invalid type: %v", ErrInvalidMetadata, firstTwoByte[0])
	}
}

func NewMetadata(bytesMetadata []byte) (*Metadata, error) {
	if len(bytesMetadata) < 2 {
		return nil, io.ErrUnexpectedEOF
	}
	meta := new(Metadata)
	meta.Type = ParseMetadataType(bytesMetadata[0])
	length, err := BytesSizeForMetadata(bytesMetadata)
	if err != nil {
		return nil, err
	}
	if len(bytesMetadata) < length {
		return nil, fmt.Errorf("%w: too short", ErrInvalidMetadata)
	}
	switch meta.Type {
	case protocol.MetadataTypeIPv4:
		// Keep the address binary: hot reply paths consume meta.IP without
		// a Hostname string round-trip.
		if ip, ok := netip.AddrFromSlice(bytesMetadata[1:5]); ok {
			meta.IP = ip
		}
		meta.Port = binary.BigEndian.Uint16(bytesMetadata[5:])
		return meta, nil
	case protocol.MetadataTypeIPv6:
		if ip, ok := netip.AddrFromSlice(bytesMetadata[1:17]); ok {
			meta.IP = ip
		}
		meta.Port = binary.BigEndian.Uint16(bytesMetadata[17:])
		return meta, nil
	case protocol.MetadataTypeDomain:
		lenDN := int(bytesMetadata[1])
		meta.Hostname = string(bytesMetadata[2 : 2+lenDN])
		meta.Port = binary.BigEndian.Uint16(bytesMetadata[2+lenDN:])
		return meta, nil
	case protocol.MetadataTypeMsg:
		meta.Cmd = protocol.MetadataCmd(bytesMetadata[1])
		meta.LenMsgBody = binary.BigEndian.Uint32(bytesMetadata[2:])
		return meta, nil
	default:
		return nil, fmt.Errorf("NewMetadata: %w: invalid type: %v", ErrInvalidMetadata, meta.Type)
	}
}

func (meta *Metadata) Bytes() (b []byte, err error) {
	poolBytes, err := meta.BytesFromPool()
	if err != nil {
		return nil, err
	}
	b = make([]byte, len(poolBytes))
	copy(b, poolBytes)
	pool.Put(poolBytes)
	return b, nil
}
func (meta *Metadata) BytesFromPool() (b []byte, err error) {
	switch meta.Type {
	case protocol.MetadataTypeIPv4:
		var ip4 [4]byte
		if meta.IP.Is4() {
			ip4 = meta.IP.As4()
		} else if ip := net.ParseIP(meta.Hostname); ip != nil && ip.To4() != nil {
			copy(ip4[:], ip.To4()[:4])
		} else {
			return nil, fmt.Errorf("not a valid ipv4: %v (type %v)", meta.Hostname, meta.Type)
		}
		b = pool.Get(1 + 4 + 2)
		copy(b[1:], ip4[:])
		binary.BigEndian.PutUint16(b[5:], meta.Port)
	case protocol.MetadataTypeIPv6:
		var ip16 [16]byte
		if meta.IP.IsValid() && !meta.IP.Is4() {
			ip16 = meta.IP.As16()
		} else if ip := net.ParseIP(meta.Hostname); ip != nil && ip.To16() != nil {
			copy(ip16[:], ip.To16()[:16])
		} else {
			return nil, fmt.Errorf("not a valid ipv6: %v (type %v)", meta.Hostname, meta.Type)
		}
		b = pool.Get(1 + 16 + 2)
		copy(b[1:], ip16[:])
		binary.BigEndian.PutUint16(b[17:], meta.Port)
	case protocol.MetadataTypeDomain:
		hostname := []byte(meta.Hostname)
		lenDN := len(hostname)
		if lenDN > 255 {
			return nil, fmt.Errorf("domain name too long: %d", lenDN)
		}
		b = pool.Get(1 + 1 + lenDN + 2)
		b[1] = uint8(lenDN)
		copy(b[2:], hostname)
		binary.BigEndian.PutUint16(b[2+lenDN:], meta.Port)
	case protocol.MetadataTypeMsg:
		b = pool.Get(1 + 1 + 4)
		b[1] = uint8(meta.Cmd)
		binary.BigEndian.PutUint32(b[2:], meta.LenMsgBody)
	}
	b[0] = MetadataTypeToByte(meta.Type)
	return b, nil
}
