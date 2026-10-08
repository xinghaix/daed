package juicity

import "testing"

func TestTransportPacketConnReusesAndReleasesCipherBuffers(t *testing.T) {
	conn := &TransportPacketConn{}

	write := conn.borrowWriteBuffer(1500)
	writeBacking := &write[0]
	if got := conn.borrowWriteBuffer(1200); &got[0] != writeBacking {
		t.Fatal("write cipher buffer was not reused")
	}
	read := conn.borrowReadBuffer(1500)
	readBacking := &read[0]
	if got := conn.borrowReadBuffer(1200); &got[0] != readBacking {
		t.Fatal("read cipher buffer was not reused")
	}

	oversized := conn.borrowWriteBuffer(maxReusablePacketWriteBufferSize + 1)
	if &oversized[0] == writeBacking {
		t.Fatal("oversized write unexpectedly reused bounded buffer")
	}
	if &conn.writeBuf[0] != writeBacking {
		t.Fatal("oversized write replaced bounded reusable buffer")
	}
	conn.writeSubKey[0] = 1
	conn.readSubKey[0] = 1

	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if conn.writeBuf != nil || conn.readBuf != nil {
		t.Fatal("Close retained transport cipher buffers")
	}
	if conn.writeSubKey[0] != 0 || conn.readSubKey[0] != 0 {
		t.Fatal("Close retained derived subkeys")
	}
}
