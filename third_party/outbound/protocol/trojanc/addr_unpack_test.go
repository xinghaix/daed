package trojanc

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

// TestMetadataUnpackMaxDomain pins the Unpack buffer sizing: a legal
// 255-byte hostname (length prefix is a full byte on the wire) must parse
// without a slice-bounds panic. This is the parser juicity's UDP downlink
// reuses on every packet.
func TestMetadataUnpackMaxDomain(t *testing.T) {
	const domainLen = 255
	domain := strings.Repeat("d", domainLen)

	var buf bytes.Buffer
	buf.WriteByte(3) // wire code for MetadataTypeDomain (see ParseMetadataType)
	buf.WriteByte(domainLen)
	buf.WriteString(domain)
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], 443)
	buf.Write(port[:])

	var m Metadata
	n, err := m.Unpack(&buf)
	if err != nil {
		t.Fatalf("Unpack() error = %v", err)
	}
	if want := 4 + domainLen; n != want {
		t.Fatalf("Unpack() consumed %d bytes, want %d", n, want)
	}
	if m.Hostname != domain {
		t.Fatalf("Unpack() hostname length = %d, want %d", len(m.Hostname), domainLen)
	}
	if m.Port != 443 {
		t.Fatalf("Unpack() port = %d, want 443", m.Port)
	}
}
