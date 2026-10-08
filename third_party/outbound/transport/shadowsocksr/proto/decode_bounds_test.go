package proto

import (
	"encoding/binary"
	"errors"
	"testing"

	"github.com/daeuniverse/outbound/transport/shadowsocksr/internal/crypto"
)

// TestAuthSHA1v4DecodeRejectsPosOutOfRange pins the guard against the
// negative-slice panic: a node-controlled frame whose padding offset exceeds
// the frame payload must produce an error, not a crash.
func TestAuthSHA1v4DecodeRejectsPosOutOfRange(t *testing.T) {
	frame := make([]byte, 12)
	binary.BigEndian.PutUint16(frame[0:2], 12)
	crc := crypto.CalcCRC32(frame, 2, 0xFFFFFFFF)
	binary.LittleEndian.PutUint16(frame[2:4], uint16(crc&0xFFFF))
	// pos byte 200 -> pos 204, far beyond length-4 == 8.
	frame[4] = 200
	adler := crypto.CalcAdler32(frame[:8])
	binary.LittleEndian.PutUint32(frame[8:12], adler)

	a := &authSHA1v4{}
	if _, _, err := a.Decode(frame); !errors.Is(err, ErrAuthSHA1v4PosOutOfRange) {
		t.Fatalf("Decode() error = %v, want ErrAuthSHA1v4PosOutOfRange", err)
	}
}

// TestAuthSHA1v4DecodeRoundTrip makes sure the guard did not break the happy
// path: Decode(packData(x)) must still yield x.
func TestAuthSHA1v4DecodeRoundTrip(t *testing.T) {
	a := &authSHA1v4{}
	payload := []byte("round trip payload")
	frame := a.packData(payload)
	decoded, n, err := a.Decode(frame)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if n != len(frame) {
		t.Fatalf("Decode() consumed %d bytes, want %d", n, len(frame))
	}
	if string(decoded) != string(payload) {
		t.Fatalf("Decode() = %q, want %q", decoded, payload)
	}
}

// TestAuthChainADecodePktRejectsShortRandTail pins the guard on
// in[:len(in)-8-randDataLength]: a validly signed but too-short packet must
// error instead of slicing negatively.
func TestAuthChainADecodePktRejectsShortRandTail(t *testing.T) {
	a := NewAuthChainA().(*authChainA)
	a.ServerInfo = &ServerInfo{Param: "12345:userkey"}
	a.InitWithServerInfo(a.ServerInfo)

	// 9 bytes passes the length gate; the trailing hmac bytes are computed
	// with the same keys the node holds, so the parse reaches the slicing.
	in := make([]byte, 9)
	mac := a.hmac(a.userKey, in[:len(in)-1])
	copy(in[len(in)-1:], mac[:1])

	if _, err := a.DecodePkt(in); !errors.Is(err, ErrAuthChainDataLengthError) {
		t.Fatalf("DecodePkt() error = %v, want ErrAuthChainDataLengthError", err)
	}
}
