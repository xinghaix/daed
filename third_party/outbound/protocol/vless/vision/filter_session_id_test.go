package vision

import (
	"encoding/binary"
	"testing"
)

const (
	// serverHelloSIDLenOffset is where RFC 8446 4.1.2 puts
	// legacy_session_id_length inside the record filterTLSLocked parses:
	// 5 record/handshake bytes + 38 fixed ServerHello prefix bytes.
	serverHelloSIDLenOffset = 43
	// serverHelloFixedOverhead is the number of bytes before the cipher suite
	// for a zero-length session ID (sidLenOffset + 1 length byte).
	serverHelloFixedOverhead = serverHelloSIDLenOffset + 1
)

// buildServerHello builds a buffer that satisfies every entry condition of
// filterTLSLocked and carries a ServerHello whose legacy_session_id_length byte
// is caller-controlled.
//
// Two independent length conditions gate cipher discovery, and the pre-fix
// panic needs both satisfied while the real length is short:
//   - `lenP-index >= 79` walks the actual slice, so the buffer must hold at
//     least 79 bytes;
//   - `remainingServerHello >= 79` reads the record length at index+3, so the
//     encoded ServerHello length must be >= 74.
//
// It returns a buffer with room for a spec-shaped ServerHello plus slack, but
// never enough room for the cipher-suite offset an out-of-range session ID
// implies.
func buildServerHello(sessionIDLen byte, sessionIDFill byte) []byte {
	buf := make([]byte, 96)
	// filterTLSLocked locates the ServerHello via tlsServerHandshakeStart.
	copy(buf, tlsServerHandshakeStart)
	// The TLS-record guard requires buffer[0..2] == 22,3,3.
	buf[0], buf[1], buf[2] = 22, 3, 3
	// ServerHello handshake length: remainingServerHello = this + 5 must reach
	// 79, so encode 80.
	binary.BigEndian.PutUint16(buf[3:], 80)
	buf[5] = tlsHandshakeTypeServerHello
	buf[serverHelloSIDLenOffset] = sessionIDLen
	for i := serverHelloSIDLenOffset + 1; i < len(buf); i++ {
		buf[i] = sessionIDFill
	}
	return buf
}

// newFilterConn returns a Conn whose sniffer is armed for one packet, i.e. the
// state filterTLSLocked requires to do any work at all.
func newFilterConn() *Conn {
	return &Conn{packetsToFilter: 1}
}

func callFilterTLS(t *testing.T, vc *Conn, buf []byte, label string) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("%s: FilterTLS panicked: %v", label, r)
		}
	}()
	vc.FilterTLS(buf)
}

// TestFilterTLSHostileSessionIDLenDoesNotPanic is the P1-7 regression: a
// ServerHello claiming a legacy_session_id longer than the RFC 8446 maximum
// (32) drove the pre-fix cipher-suite index past the end of the buffer. The
// sniffer must survive every byte value of that length field.
func TestFilterTLSHostileSessionIDLenDoesNotPanic(t *testing.T) {
	for sid := 0; sid <= 0xff; sid++ {
		vc := newFilterConn()
		buf := buildServerHello(byte(sid), 0xAA)
		callFilterTLS(t, vc, buf, "sessionIDLen")

		if sid > 32 {
			if vc.cipher != 0 {
				t.Fatalf("sessionIDLen=%d: cipher=%#x, want it left unset for an out-of-range session ID", sid, vc.cipher)
			}
			if vc.enableXTLS {
				t.Fatalf("sessionIDLen=%d: enableXTLS=true, want the fail-safe plain-VLESS fallback", sid)
			}
			if !vc.isTLS12orAbove {
				t.Fatalf("sessionIDLen=%d: isTLS12orAbove=false, want the ServerHello still recognised", sid)
			}
		}
	}
}

// TestFilterTLSShortBufferWithLargeSessionIDDoesNotPanic covers the second way
// the pre-fix index escaped the slice: a buffer only just long enough to clear
// the >= 79 entry guard, carrying a session ID that pushes the cipher offset
// past its end.
func TestFilterTLSShortBufferWithLargeSessionIDDoesNotPanic(t *testing.T) {
	full := buildServerHello(255, 0xAB)
	for n := 79; n <= len(full); n++ {
		vc := newFilterConn()
		callFilterTLS(t, vc, full[:n], "short buffer")
		if vc.cipher != 0 {
			t.Fatalf("len=%d: cipher=%#x, want it left unset when the cipher suite is not fully present", n, vc.cipher)
		}
	}
}

// TestFilterTLSTruncatedBufferDoesNotPanic feeds every truncation of a valid
// ServerHello: the pre-fix code indexed the cipher suite without checking that
// the buffer was long enough to hold it.
func TestFilterTLSTruncatedBufferDoesNotPanic(t *testing.T) {
	full := buildServerHello(32, 0xBB)
	for n := 0; n <= len(full); n++ {
		vc := newFilterConn()
		callFilterTLS(t, vc, full[:n], "truncated")
	}
}

// TestFilterTLSValidSessionIDStillResolvesCipher pins that the bounds fix did
// not disable the legitimate path: a spec-shaped ServerHello still yields the
// cipher suite, which is what enables XTLS Vision.
func TestFilterTLSValidSessionIDStillResolvesCipher(t *testing.T) {
	const cipher = uint16(0x1301) // TLS_AES_128_GCM_SHA256
	for _, sid := range []byte{0, 1, 16, 32} {
		buf := buildServerHello(sid, 0xCC)
		// Place a real cipher suite right after the session ID.
		binary.BigEndian.PutUint16(buf[serverHelloFixedOverhead+int(sid):], cipher)

		vc := newFilterConn()
		vc.FilterTLS(buf)
		if vc.cipher != cipher {
			t.Fatalf("sessionIDLen=%d: cipher=%#x, want %#x", sid, vc.cipher, cipher)
		}
		if !vc.isTLS12orAbove {
			t.Fatalf("sessionIDLen=%d: isTLS12orAbove=false, want the ServerHello recorded", sid)
		}
	}
}

// TestFilterTLSCipherOffsetSkipsSessionID pins the offset arithmetic: the
// cipher suite sits at index+44+sessionIDLen, not at a fixed index.
func TestFilterTLSCipherOffsetSkipsSessionID(t *testing.T) {
	const sidLen = 20
	const want = uint16(0x1303) // TLS_CHACHA20_POLY1305_SHA256
	buf := buildServerHello(sidLen, 0xDD)
	cipherOff := serverHelloFixedOverhead + sidLen
	// Plant a decoy one byte before the real offset first: a reader that
	// forgot the session-ID length entirely would land there and read 0xDEAD.
	binary.BigEndian.PutUint16(buf[cipherOff-1:], 0xDEAD)
	binary.BigEndian.PutUint16(buf[cipherOff:], want)

	vc := newFilterConn()
	vc.FilterTLS(buf)
	if vc.cipher == 0xDEAD {
		t.Fatalf("cipher read at the session-ID-blind offset %d", cipherOff-1)
	}
	if vc.cipher != want {
		t.Fatalf("cipher=%#x, want %#x", vc.cipher, want)
	}
}
