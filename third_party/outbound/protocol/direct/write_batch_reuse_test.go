package direct

import (
	"net"
	"testing"

	"golang.org/x/net/ipv6"
)

func TestResetDirectBatchScratchClearsPayloadReferences(t *testing.T) {
	scratch := &directBatchScratch{
		msgs: make([]ipv6.Message, 1),
		iovs: make([][]byte, 1),
	}
	payload := []byte("payload")
	scratch.iovs[0] = payload
	scratch.msgs[0].Buffers = scratch.iovs[:1]
	resetDirectBatchScratch(scratch, 1)

	if scratch.iovs[0] != nil {
		t.Fatal("scratch retained payload reference")
	}
	if scratch.msgs[0].Buffers != nil || scratch.msgs[0].Addr != nil {
		t.Fatal("scratch retained message references")
	}
}

func TestDirectPacketConnCachesBatchWriter(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = server.Close() }()
	client, err := net.DialUDP("udp4", nil, server.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()

	conn := &directPacketConn{UDPConn: client}
	first := conn.getBatchWriter()
	second := conn.getBatchWriter()
	if first != second {
		t.Fatal("batch writer was rebuilt")
	}
}
