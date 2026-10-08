package vmess_test

// True end-to-end coverage for the VMess client stack: an in-test VMess server
// (an independent implementation of the wire protocol, not a copy of
// protocol/vmess) fronting real loopback echo targets, reached through the
// same dialer chains dae builds (direct -> vmess for raw TCP, direct ->
// transport/ws -> vmess for WebSocket, plus one full vmess:// link parse
// through dialer.NewNetproxyDialerFromLink).
//
// Wire-format notes for this repository's client, which speaks only the VMess
// AEAD header variant (verified by reading protocol/vmess/*.go; there is no
// AES-128-CFB command-block path):
//   - The request header is EAuthID(16) + AEAD sealed length(18) + connection
//     nonce(8) + AEAD sealed instruction(len+16). The auth id is one AES-ECB
//     block under KDF(cmdKey, "AES Auth ID Encryption")[:16] carrying
//     BE64(timestamp) + random(4) + CRC32; both AEAD blocks key off
//     KDF(cmdKey, salt, eAuthID, connectionNonce) with the eAuthID as AAD.
//   - The instruction block carries the random body IV/key, the response auth
//     byte V, the options byte (this client always requests chunk stream +
//     length masking + global padding), the security byte (3 = aes-128-gcm,
//     4 = chacha20-poly1305; the AEAD variant has no "none" body security),
//     the command (1 = tcp, 2 = udp), port and address; a P-byte pad sits
//     between the address and the trailing FNV1a-32 checksum.
//   - The response header is AEAD sealed length(18) + AEAD sealed
//     (V, option, cmd, cmdLen)(20) under keys derived from
//     sha256(request key)[:16] / sha256(request IV)[:16].
//   - Body chunks are size(2) + AEAD(payload) + padding. The size field is
//     masked by a SHAKE128 stream keyed with the direction's session IV; per
//     chunk that stream yields the padding length first, then the size mask.
//     The per-chunk AEAD nonce is the BE16 chunk counter over IV[2:12] (both
//     body AEADs are 12-byte-nonce AEADs: AES-128-GCM uses the 16-byte
//     session key directly, chacha20-poly1305 the md5-expanded 32-byte key).
//     A chunk whose payload is empty (size == overhead+padding) is the
//     end-of-stream terminal, which is how half-close travels this protocol.

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"hash/crc32"
	"hash/fnv"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/dialer"
	_ "github.com/daeuniverse/outbound/dialer/v2ray" // registers the vmess:// link creator, as dae consumes it
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/transport/ws"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/sha3"
)

// ---- shared helpers (the per-protocol e2e convention) ----

const (
	e2eVMessUUID = "b831381d-6324-4d53-ad4f-8cda48b30811"
	e2eWrongUUID = "23ad6b10-8d1a-40f4-8b76-7b6b0d5f8f13"
	// e2eIODeadline bounds every socket read/write in the e2e so a hung
	// protocol layer fails the test instead of hanging it.
	e2eIODeadline = 60 * time.Second
	// e2eChunkPlaintext caps one relayed chunk payload; it must stay below
	// the 0xffff size field and, for UDP, below the client's 2KiB datagram
	// read buffer.
	e2eChunkPlaintext = 16 << 10
)

// loopbackEchoTarget starts a TCP echo server; everything received is sent
// back, and a peer half-close (FIN) is propagated back as EOF after the
// remaining output is flushed.
func loopbackEchoTarget(t *testing.T) net.Addr {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(c)
		}
	}()
	return ln.Addr()
}

// startUDPEchoTarget echoes datagrams back to their sender.
func startUDPEchoTarget(t *testing.T) net.Addr {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("udp echo listen: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if _, err := pc.WriteTo(buf[:n], addr); err != nil {
				return
			}
		}
	}()
	return pc.LocalAddr()
}

// deadlineCtx bounds every dial in the e2e.
func deadlineCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// ---- in-test VMess server (independent wire-format implementation) ----

// Wire-format constants, reimplemented here rather than imported from the
// client under test.
const (
	vmessKDFSaltVMessAEAD = "VMess AEAD KDF"
	vmessKDFSaltAuthID    = "AES Auth ID Encryption"
	vmessKDFSaltHdrLenKey = "VMess Header AEAD Key_Length"
	vmessKDFSaltHdrLenIV  = "VMess Header AEAD Nonce_Length"
	vmessKDFSaltHdrPayKey = "VMess Header AEAD Key"
	vmessKDFSaltHdrPayIV  = "VMess Header AEAD Nonce"
	vmessKDFSaltRspLenKey = "AEAD Resp Header Len Key"
	vmessKDFSaltRspLenIV  = "AEAD Resp Header Len IV"
	vmessKDFSaltRspPayKey = "AEAD Resp Header Key"
	vmessKDFSaltRspPayIV  = "AEAD Resp Header IV"

	// vmessCmdKeyMagicUUID is the fixed UUID string the VMess spec folds into
	// every command key.
	vmessCmdKeyMagicUUID = "c48619fe-8f02-49e0-b9e9-edf763e17e21"

	vmessCmdTCP byte = 1
	vmessCmdUDP byte = 2

	vmessSecurityAES128GCM        byte = 3
	vmessSecurityChacha20Poly1305 byte = 4

	vmessAddrTypeIPv4   byte = 1
	vmessAddrTypeDomain byte = 2
	vmessAddrTypeIPv6   byte = 3

	vmessOptionChunkStream        byte = 1
	vmessOptionChunkLengthMasking byte = 4
	vmessOptionGlobalPadding      byte = 8
)

// vmessKDF implements the VMess AEAD KDF: a chain of HMAC-SHA256 calls, each
// keyed by the previous hash instance, seeded with the fixed VMess AEAD salt.
func vmessKDF(key []byte, paths ...[]byte) []byte {
	create := func() hash.Hash { return hmac.New(sha256.New, []byte(vmessKDFSaltVMessAEAD)) }
	for _, p := range paths {
		parent := create
		create = func() hash.Hash { return hmac.New(parent, p) }
	}
	h := create()
	h.Write(key)
	return h.Sum(nil)
}

// vmessCmdKey derives the VMess command key of a UUID (md5 over the UUID
// bytes plus the spec's magic UUID).
func vmessCmdKey(id string) ([]byte, error) {
	u, err := uuid.Parse(id)
	if err != nil {
		return nil, fmt.Errorf("vmess e2e server: parse UUID: %w", err)
	}
	sum := md5.New()
	sum.Write(u[:])
	sum.Write([]byte(vmessCmdKeyMagicUUID))
	return sum.Sum(nil), nil
}

func vmessAESGCM(key []byte) (cipher.AEAD, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}

// vmessExpandChachaKey expands a 16-byte session key to the 32-byte
// chacha20-poly1305 key (two md5 chains), as the wire format requires.
func vmessExpandChachaKey(key []byte) []byte {
	h1 := md5.Sum(key[:16])
	h2 := md5.Sum(h1[:])
	out := make([]byte, 32)
	copy(out[:16], h1[:])
	copy(out[16:], h2[:])
	return out
}

func vmessBodyAEAD(security byte, key []byte) (cipher.AEAD, error) {
	switch security {
	case vmessSecurityAES128GCM:
		return vmessAESGCM(key[:16])
	case vmessSecurityChacha20Poly1305:
		return chacha20poly1305.New(vmessExpandChachaKey(key))
	default:
		return nil, fmt.Errorf("vmess e2e server: unsupported security %#x", security)
	}
}

// vmessCheckAuthID validates one encrypted auth id against the command key.
func vmessCheckAuthID(cmdKey, authID []byte) error {
	blk, err := aes.NewCipher(vmessKDF(cmdKey, []byte(vmessKDFSaltAuthID))[:16])
	if err != nil {
		return err
	}
	plain := make([]byte, 16)
	blk.Decrypt(plain, authID)
	if crc32.ChecksumIEEE(plain[:12]) != binary.BigEndian.Uint32(plain[12:16]) {
		return errors.New("auth id checksum mismatch")
	}
	ts := int64(binary.BigEndian.Uint64(plain[:8]))
	if drift := time.Now().Unix() - ts; drift < -120 || drift > 120 {
		return fmt.Errorf("auth id timestamp drift %ds", drift)
	}
	return nil
}

// vmessOpenHeaderBlock opens one of the AEAD-protected request header blocks.
func vmessOpenHeaderBlock(cmdKey, authID, connNonce []byte, keySalt, ivSalt string, sealed []byte) ([]byte, error) {
	gcm, err := vmessAESGCM(vmessKDF(cmdKey, []byte(keySalt), authID, connNonce)[:16])
	if err != nil {
		return nil, err
	}
	iv := vmessKDF(cmdKey, []byte(ivSalt), authID, connNonce)[:12]
	return gcm.Open(nil, iv, sealed, authID)
}

// vmessE2ERequest is the decoded VMess request instruction.
type vmessE2ERequest struct {
	iv       [16]byte
	key      [16]byte
	v        byte
	options  byte
	security byte
	padding  int
	command  byte
	port     uint16
	host     string
}

// vmessParseInstruction decodes the instruction block, including the FNV1a
// checksum over everything before it.
func vmessParseInstruction(instr []byte) (*vmessE2ERequest, error) {
	if len(instr) < 41 {
		return nil, fmt.Errorf("instruction too short: %d", len(instr))
	}
	if instr[0] != 1 {
		return nil, fmt.Errorf("unsupported version %#x", instr[0])
	}
	h := fnv.New32a()
	h.Write(instr[:len(instr)-4])
	if binary.BigEndian.Uint32(instr[len(instr)-4:]) != h.Sum32() {
		return nil, errors.New("instruction FNV1a checksum mismatch")
	}
	if instr[34]&vmessOptionChunkStream == 0 || instr[34]&vmessOptionChunkLengthMasking == 0 {
		return nil, fmt.Errorf("unsupported request options %#x", instr[34])
	}
	r := &vmessE2ERequest{
		v:        instr[33],
		options:  instr[34],
		security: instr[35] & 0xf,
		padding:  int(instr[35] >> 4),
		command:  instr[37],
		port:     binary.BigEndian.Uint16(instr[38:40]),
	}
	copy(r.iv[:], instr[1:17])
	copy(r.key[:], instr[17:33])
	if r.security != vmessSecurityAES128GCM && r.security != vmessSecurityChacha20Poly1305 {
		return nil, fmt.Errorf("unsupported security %#x", r.security)
	}
	var addrEnd int
	switch instr[40] {
	case vmessAddrTypeIPv4:
		if len(instr) < 45 {
			return nil, errors.New("short ipv4 address")
		}
		r.host = net.IP(instr[41:45]).String()
		addrEnd = 45
	case vmessAddrTypeDomain:
		l := int(instr[41])
		if len(instr) < 42+l {
			return nil, errors.New("short domain address")
		}
		r.host = string(instr[42 : 42+l])
		addrEnd = 42 + l
	case vmessAddrTypeIPv6:
		if len(instr) < 57 {
			return nil, errors.New("short ipv6 address")
		}
		r.host = net.IP(instr[41:57]).String()
		addrEnd = 57
	default:
		return nil, fmt.Errorf("unsupported address type %#x", instr[40])
	}
	if len(instr) < addrEnd+r.padding+4 {
		return nil, errors.New("instruction shorter than its own padding")
	}
	return r, nil
}

// vmessWriteResponseHeader writes the AEAD-encrypted VMess response header:
// the sealed 2-byte length of the payload, then the sealed
// (V, option, cmd, cmdLen) payload.
func vmessWriteResponseHeader(w io.Writer, respKey, respIV []byte, v, respCmd byte) error {
	lenGCM, err := vmessAESGCM(vmessKDF(respKey, []byte(vmessKDFSaltRspLenKey))[:16])
	if err != nil {
		return err
	}
	lenIV := vmessKDF(respIV, []byte(vmessKDFSaltRspLenIV))[:12]
	lenPlain := make([]byte, 2)
	binary.BigEndian.PutUint16(lenPlain, 4)
	out := lenGCM.Seal(nil, lenIV, lenPlain, nil)

	payloadGCM, err := vmessAESGCM(vmessKDF(respKey, []byte(vmessKDFSaltRspPayKey))[:16])
	if err != nil {
		return err
	}
	payloadIV := vmessKDF(respIV, []byte(vmessKDFSaltRspPayIV))[:12]
	out = payloadGCM.Seal(out, payloadIV, []byte{v, 0, respCmd, 0}, nil)
	_, err = w.Write(out)
	return err
}

// vmessChunkCodec codes one direction of the VMess chunk stream. The SHAKE128
// stream yields the padding length first, then the size mask, per chunk.
type vmessChunkCodec struct {
	aead    cipher.AEAD
	shake   sha3.ShakeHash
	iv      []byte
	padded  bool
	counter uint16
}

func newVMessChunkCodec(security byte, key, iv []byte, padded bool) (*vmessChunkCodec, error) {
	aead, err := vmessBodyAEAD(security, key)
	if err != nil {
		return nil, err
	}
	shake := sha3.NewShake128()
	if _, err := shake.Write(iv[:16]); err != nil {
		return nil, err
	}
	return &vmessChunkCodec{
		aead:   aead,
		shake:  shake,
		iv:     append([]byte(nil), iv[:16]...),
		padded: padded,
	}, nil
}

func (c *vmessChunkCodec) draw() uint16 {
	var b [2]byte
	_, _ = c.shake.Read(b[:])
	return binary.BigEndian.Uint16(b[:])
}

// nonce builds the per-chunk AEAD nonce: the BE16 chunk counter over IV[2:12].
func (c *vmessChunkCodec) nonce() []byte {
	n := make([]byte, c.aead.NonceSize())
	binary.BigEndian.PutUint16(n, c.counter)
	copy(n[2:], c.iv[2:c.aead.NonceSize()])
	c.counter++
	return n
}

func (c *vmessChunkCodec) nextPadding() int {
	if !c.padded {
		return 0
	}
	return int(c.draw() % 64)
}

// readChunk decodes one inbound chunk. io.EOF means the peer sent the
// end-of-stream terminal chunk (empty payload).
func (c *vmessChunkCodec) readChunk(r io.Reader) ([]byte, error) {
	padding := c.nextPadding()
	var sizeBuf [2]byte
	if _, err := io.ReadFull(r, sizeBuf[:]); err != nil {
		return nil, fmt.Errorf("read chunk size: %w", err)
	}
	size := int(binary.BigEndian.Uint16(sizeBuf[:]) ^ c.draw())
	if size == c.aead.Overhead()+padding {
		return nil, io.EOF
	}
	if size < c.aead.Overhead()+padding {
		return nil, fmt.Errorf("invalid chunk size %d (padding %d)", size, padding)
	}
	frame := make([]byte, size)
	if _, err := io.ReadFull(r, frame); err != nil {
		return nil, fmt.Errorf("read chunk body: %w", err)
	}
	payload, err := c.aead.Open(nil, c.nonce(), frame[:size-padding], nil)
	if err != nil {
		return nil, fmt.Errorf("open chunk: %w", err)
	}
	// The trailing padding rides after the AEAD tag and carries no meaning.
	return payload, nil
}

// writeChunk seals and writes one outbound chunk. A nil/empty payload writes
// the end-of-stream terminal chunk.
func (c *vmessChunkCodec) writeChunk(w io.Writer, payload []byte) error {
	padding := c.nextPadding()
	size := len(payload) + c.aead.Overhead() + padding
	if size > 0xffff {
		return fmt.Errorf("chunk payload too large: %d", size)
	}
	frame := make([]byte, 2, 2+size)
	binary.BigEndian.PutUint16(frame, uint16(size)^c.draw())
	frame = c.aead.Seal(frame, c.nonce(), payload, nil)
	if padding > 0 {
		pad := make([]byte, padding)
		if _, err := rand.Read(pad); err != nil {
			return err
		}
		frame = append(frame, pad...)
	}
	_, err := w.Write(frame)
	return err
}

// vmessNetConn is the stream surface the VMess server logic needs; it is
// satisfied both by a raw TCP conn and by the WebSocket pipe below.
type vmessNetConn interface {
	io.ReadWriteCloser
	SetDeadline(t time.Time) error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
}

type vmessE2EServerConfig struct {
	// acceptUUID is the UUID the server authenticates clients against.
	acceptUUID string
	// respCmd overrides the response header command byte; 0 is the only value
	// the client accepts.
	respCmd byte
}

func happyVMessE2EServerConfig() vmessE2EServerConfig {
	return vmessE2EServerConfig{acceptUUID: e2eVMessUUID}
}

type vmessE2EServer struct {
	cmdKey  []byte
	respCmd byte
}

func newVMessE2EServer(cfg vmessE2EServerConfig) (*vmessE2EServer, error) {
	cmdKey, err := vmessCmdKey(cfg.acceptUUID)
	if err != nil {
		return nil, err
	}
	return &vmessE2EServer{cmdKey: cmdKey, respCmd: cfg.respCmd}, nil
}

// serveConn handles one accepted stream as a VMess server: it authenticates
// the AEAD request header, replies with the encrypted response header and
// relays the session to a real loopback target. Every rejection is a plain
// session close, exactly like a real server, so the client must surface an
// error rather than a hang.
func (s *vmessE2EServer) serveConn(downstream vmessNetConn) {
	defer downstream.Close()
	_ = downstream.SetDeadline(time.Now().Add(e2eIODeadline))

	authID := make([]byte, 16)
	if _, err := io.ReadFull(downstream, authID); err != nil {
		return
	}
	if err := vmessCheckAuthID(s.cmdKey, authID); err != nil {
		return
	}
	head := make([]byte, 18) // sealed instruction length (2) + tag (16)
	if _, err := io.ReadFull(downstream, head); err != nil {
		return
	}
	connNonce := make([]byte, 8)
	if _, err := io.ReadFull(downstream, connNonce); err != nil {
		return
	}
	lenPlain, err := vmessOpenHeaderBlock(s.cmdKey, authID, connNonce, vmessKDFSaltHdrLenKey, vmessKDFSaltHdrLenIV, head)
	if err != nil {
		// A client keyed with a different UUID (wrong password) fails here.
		return
	}
	instrSealed := make([]byte, int(binary.BigEndian.Uint16(lenPlain))+16)
	if _, err := io.ReadFull(downstream, instrSealed); err != nil {
		return
	}
	instr, err := vmessOpenHeaderBlock(s.cmdKey, authID, connNonce, vmessKDFSaltHdrPayKey, vmessKDFSaltHdrPayIV, instrSealed)
	if err != nil {
		return
	}
	req, err := vmessParseInstruction(instr)
	if err != nil {
		return
	}

	respKey := sha256.Sum256(req.key[:])
	respIV := sha256.Sum256(req.iv[:])
	if err := vmessWriteResponseHeader(downstream, respKey[:16], respIV[:16], req.v, s.respCmd); err != nil {
		return
	}
	clientCodec, err := newVMessChunkCodec(req.security, req.key[:], req.iv[:], req.options&vmessOptionGlobalPadding != 0)
	if err != nil {
		return
	}
	serverCodec, err := newVMessChunkCodec(req.security, respKey[:16], respIV[:16], req.options&vmessOptionGlobalPadding != 0)
	if err != nil {
		return
	}

	destination := net.JoinHostPort(req.host, strconv.Itoa(int(req.port)))
	switch req.command {
	case vmessCmdTCP:
		s.relayTCP(downstream, destination, clientCodec, serverCodec)
	case vmessCmdUDP:
		s.relayUDP(downstream, destination, clientCodec, serverCodec)
	default:
		// Unknown command: reject the session like a real server.
		return
	}
}

// relayTCP pipes a VMess TCP session to the destination over a real TCP
// socket, propagating half-closes in both directions.
func (s *vmessE2EServer) relayTCP(downstream vmessNetConn, destination string, clientCodec, serverCodec *vmessChunkCodec) {
	target, err := net.DialTimeout("tcp", destination, 10*time.Second)
	if err != nil {
		// Destination unreachable: drop the session like a real server.
		return
	}
	defer target.Close()
	_ = target.SetDeadline(time.Now().Add(e2eIODeadline))

	// Client -> target: chunk decode; the terminal chunk propagates as a TCP
	// half-close toward the target.
	go func() {
		for {
			payload, err := clientCodec.readChunk(downstream)
			if err != nil {
				if errors.Is(err, io.EOF) {
					if tcp, ok := target.(*net.TCPConn); ok {
						_ = tcp.CloseWrite()
					}
				}
				return
			}
			if _, err := target.Write(payload); err != nil {
				return
			}
		}
	}()

	// Target -> client: one chunk per read; terminal chunk on target EOF.
	buf := make([]byte, e2eChunkPlaintext)
	for {
		n, err := target.Read(buf)
		if n > 0 {
			if werr := serverCodec.writeChunk(downstream, buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			_ = serverCodec.writeChunk(downstream, nil)
			return
		}
	}
}

// relayUDP pipes a VMess UDP session (command 0x02) to the destination: one
// datagram per chunk in both directions over a real connected UDP socket.
func (s *vmessE2EServer) relayUDP(downstream vmessNetConn, destination string, clientCodec, serverCodec *vmessChunkCodec) {
	target, err := net.Dial("udp", destination)
	if err != nil {
		return
	}
	defer target.Close()
	_ = target.SetDeadline(time.Now().Add(e2eIODeadline))

	// Target -> client: one chunk per datagram. The fixed-target client
	// derives the datagram source from the request destination, which is the
	// loopback echo target here.
	go func() {
		buf := make([]byte, e2eChunkPlaintext)
		for {
			n, err := target.Read(buf)
			if err != nil {
				return
			}
			if werr := serverCodec.writeChunk(downstream, buf[:n]); werr != nil {
				return
			}
		}
	}()

	// Client -> target: one datagram per chunk.
	for {
		payload, err := clientCodec.readChunk(downstream)
		if err != nil {
			return
		}
		if _, err := target.Write(payload); err != nil {
			return
		}
	}
}

// vmessWSPipe adapts a gorilla websocket to the stream surface the VMess
// server logic expects: writes become binary messages, reads stream across
// message boundaries. It mirrors the client-side ws transport conn semantics.
type vmessWSPipe struct {
	conn    *websocket.Conn
	readMu  sync.Mutex
	reader  io.Reader
	writeMu sync.Mutex
}

func (p *vmessWSPipe) Read(b []byte) (int, error) {
	p.readMu.Lock()
	defer p.readMu.Unlock()
	for {
		if p.reader == nil {
			messageType, reader, err := p.conn.NextReader()
			if err != nil {
				return 0, err
			}
			if messageType != websocket.BinaryMessage {
				_, _ = io.Copy(io.Discard, reader)
				continue
			}
			p.reader = reader
		}
		n, err := p.reader.Read(b)
		if errors.Is(err, io.EOF) {
			p.reader = nil
			if n > 0 {
				return n, nil
			}
			continue
		}
		return n, err
	}
}

func (p *vmessWSPipe) Write(b []byte) (int, error) {
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	w, err := p.conn.NextWriter(websocket.BinaryMessage)
	if err != nil {
		return 0, err
	}
	n, err := w.Write(b)
	if cerr := w.Close(); err == nil {
		err = cerr
	}
	return n, err
}

func (p *vmessWSPipe) Close() error { return p.conn.Close() }

func (p *vmessWSPipe) SetDeadline(t time.Time) error {
	_ = p.conn.SetReadDeadline(t)
	return p.conn.SetWriteDeadline(t)
}

func (p *vmessWSPipe) SetReadDeadline(t time.Time) error  { return p.conn.SetReadDeadline(t) }
func (p *vmessWSPipe) SetWriteDeadline(t time.Time) error { return p.conn.SetWriteDeadline(t) }

// startVMessE2EServer runs the in-test VMess server on a real loopback TCP
// listener and returns its address.
func startVMessE2EServer(t *testing.T, cfg vmessE2EServerConfig) string {
	t.Helper()
	srv, err := newVMessE2EServer(cfg)
	if err != nil {
		t.Fatalf("vmess e2e server: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("vmess listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go srv.serveConn(c)
		}
	}()
	return ln.Addr().String()
}

// startVMessE2EWSServer runs the in-test VMess server behind a gorilla
// websocket Upgrader on a real loopback HTTP listener and returns the
// host:port the ws client must dial.
func startVMessE2EWSServer(t *testing.T, cfg vmessE2EServerConfig) string {
	t.Helper()
	srv, err := newVMessE2EServer(cfg)
	if err != nil {
		t.Fatalf("vmess e2e server: %v", err)
	}
	upgrader := websocket.Upgrader{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wsc, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		srv.serveConn(&vmessWSPipe{conn: wsc})
	}))
	t.Cleanup(server.Close)
	return strings.TrimPrefix(server.URL, "http://")
}

// ---- client builders, mirroring dialer/v2ray construction exactly ----

// newVMessClientDialer builds direct -> vmess, the raw-TCP consumer chain,
// with an explicit security for cipher coverage.
func newVMessClientDialer(t *testing.T, proxyAddr, sec, userID string) netproxy.Dialer {
	t.Helper()
	direct, _ := dialer.NewDirectDialer(&dialer.ExtraOption{}, false)
	d, err := protocol.NewDialer("vmess", direct, protocol.Header{
		IsClient:     true,
		ProxyAddress: proxyAddr,
		Password:     userID,
		Cipher:       sec,
		Feature1:     "", // the consumer always passes a string (the flow value)
	})
	if err != nil {
		t.Fatalf("vmess dialer: %v", err)
	}
	return d
}

// newVMessWSClientDialer builds direct -> transport/ws -> vmess exactly the
// way the ws branch of V2Ray.Dialer does (scheme ws, host/sni query,
// allowInsecure off).
func newVMessWSClientDialer(t *testing.T, wsAddr, sec, userID string) netproxy.Dialer {
	t.Helper()
	direct, _ := dialer.NewDirectDialer(&dialer.ExtraOption{}, false)
	u := url.URL{
		Scheme: "ws",
		Host:   wsAddr,
		Path:   "/vmess",
		RawQuery: url.Values{
			"host":          []string{"127.0.0.1"},
			"sni":           []string{"127.0.0.1"},
			"allowInsecure": []string{"false"},
		}.Encode(),
	}
	wsDialer, _, err := ws.NewWs(&dialer.ExtraOption{}, direct, u.String())
	if err != nil {
		t.Fatalf("ws dialer: %v", err)
	}
	d, err := protocol.NewDialer("vmess", wsDialer, protocol.Header{
		IsClient:     true,
		ProxyAddress: wsAddr,
		Password:     userID,
		Cipher:       sec,
		Feature1:     "",
	})
	if err != nil {
		t.Fatalf("vmess dialer: %v", err)
	}
	return d
}

// newVMessConsumerLinkDialer parses a real vmess:// link through the
// production registry entry dae uses (NewNetproxyDialerFromLink -> NewV2Ray
// -> ParseVmessURL -> V2Ray.Dialer), so the whole link-construction chain is
// exercised, including getAutoCipher().
func newVMessConsumerLinkDialer(t *testing.T, proxyAddr, userID string) netproxy.Dialer {
	t.Helper()
	host, port, err := net.SplitHostPort(proxyAddr)
	if err != nil {
		t.Fatalf("split proxy addr: %v", err)
	}
	linkJSON, err := json.Marshal(map[string]string{
		"ps":   "e2e",
		"add":  host,
		"port": port,
		"id":   userID,
		"aid":  "0", // AEAD only: NewV2Ray rejects any other alterId
		"net":  "tcp",
		"type": "none",
		"tls":  "",
		"v":    "2",
	})
	if err != nil {
		t.Fatalf("marshal vmess link: %v", err)
	}
	link := "vmess://" + base64.StdEncoding.EncodeToString(linkJSON)
	direct, _ := dialer.NewDirectDialer(&dialer.ExtraOption{}, false)
	d, _, err := dialer.NewNetproxyDialerFromLink(direct, &dialer.ExtraOption{}, link)
	if err != nil {
		t.Fatalf("dialer from link: %v", err)
	}
	return d
}

// ---- relay verification ----

// e2eDeterministicPayload fills total bytes with a position-dependent pattern
// so loss, reordering and duplication all break byte-exact verification.
func e2eDeterministicPayload(total int) []byte {
	buf := make([]byte, total)
	state := uint32(0x9e3779b9)
	for i := range buf {
		state = state*1664525 + 1013904223
		buf[i] = byte(state >> 24)
	}
	return buf
}

// verifyRelayRoundTrip writes the payload through c while concurrently
// reading it back, then requires byte-exact equality. The volume crosses
// chunk, record and buffer boundaries.
func verifyRelayRoundTrip(t *testing.T, c netproxy.Conn, total int) {
	t.Helper()
	want := e2eDeterministicPayload(total)
	got := make([]byte, total)
	writeErr := make(chan error, 1)
	go func() {
		const writeSize = 64 << 10
		for off := 0; off < total; off += writeSize {
			end := min(off+writeSize, total)
			if _, err := c.Write(want[off:end]); err != nil {
				writeErr <- fmt.Errorf("write at %d: %w", off, err)
				return
			}
		}
		writeErr <- nil
	}()
	if err := c.SetReadDeadline(time.Now().Add(e2eIODeadline)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	for off := 0; off < total; {
		n, err := c.Read(got[off:])
		if err != nil {
			t.Fatalf("read back at %d/%d: %v", off, total, err)
		}
		if n == 0 {
			t.Fatalf("read back at %d/%d: 0-byte read", off, total)
		}
		off += n
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("payload writer: %v", err)
	}
	if !bytes.Equal(got, want) {
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("payload mismatch at %d/%d: got %#x want %#x", i, total, got[i], want[i])
			}
		}
		t.Fatal("payload mismatch")
	}
}

// verifyHalfCloseEOF asserts the half-close contract of this stack: vmess
// CloseWrite emits the chunk-stream terminal (an empty chunk, not a no-op),
// the server propagates it as a FIN toward the echo target, and the end of
// the target's output comes back through a server terminal chunk as EOF.
func verifyHalfCloseEOF(t *testing.T, c netproxy.Conn) {
	t.Helper()
	closeWrite, ok := c.(interface{ CloseWrite() error })
	if !ok {
		t.Fatalf("vmess conn %T lost the CloseWrite capability", c)
	}
	if err := closeWrite.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
	if err := c.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, 1024)
	if n, err := c.Read(buf); n != 0 || err == nil {
		t.Fatalf("read after half-close = %d, %v, want 0, EOF", n, err)
	}
}

// expectReadError requires the client to surface an error in bounded time
// after the server rejected or tore down the session: an error, never a
// panic or a hang.
func expectReadError(t *testing.T, c netproxy.Conn) {
	t.Helper()
	if err := c.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, 128)
	_, _ = c.Write([]byte("hello"))
	for i := 0; i < 10; i++ {
		if _, err := c.Read(buf); err != nil {
			return // an error surfaced: pass
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("the server rejected the session but the client never surfaced an error")
}

// ---- the e2e tests ----

// TestE2EVMessTCPRelay pushes 4MiB through client -> vmess server -> echo
// target -> back over a real TCP session for every security the client can
// request, then half-closes and expects EOF. The AEAD variant has no "none"
// body security; "auto" is resolved dialer-side (getAutoCipher) and lands on
// aes-128-gcm on AES-capable hosts.
func TestE2EVMessTCPRelay(t *testing.T) {
	for _, sec := range []string{"aes-128-gcm", "chacha20-poly1305", "auto"} {
		t.Run(sec, func(t *testing.T) {
			echoAddr := loopbackEchoTarget(t)
			proxyAddr := startVMessE2EServer(t, happyVMessE2EServerConfig())
			d := newVMessClientDialer(t, proxyAddr, sec, e2eVMessUUID)

			ctx := deadlineCtx(t)
			c, err := d.DialContext(ctx, "tcp", echoAddr.String())
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer c.Close()

			verifyRelayRoundTrip(t, c, 4<<20)
			verifyHalfCloseEOF(t, c)
		})
	}
}

// TestE2EVMessTCPRelayOverWebSocket runs the same 4MiB relay through the ws
// transport: the in-test VMess server sits behind a gorilla Upgrader and the
// client is built the way V2Ray.Dialer builds ws links.
func TestE2EVMessTCPRelayOverWebSocket(t *testing.T) {
	echoAddr := loopbackEchoTarget(t)
	wsAddr := startVMessE2EWSServer(t, happyVMessE2EServerConfig())
	d := newVMessWSClientDialer(t, wsAddr, "aes-128-gcm", e2eVMessUUID)

	ctx := deadlineCtx(t)
	c, err := d.DialContext(ctx, "tcp", echoAddr.String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	verifyRelayRoundTrip(t, c, 4<<20)
	verifyHalfCloseEOF(t, c)
}

// TestE2EVMessConsumerLinkChain parses a real vmess:// link through the
// production chain and relays through it.
func TestE2EVMessConsumerLinkChain(t *testing.T) {
	echoAddr := loopbackEchoTarget(t)
	proxyAddr := startVMessE2EServer(t, happyVMessE2EServerConfig())
	d := newVMessConsumerLinkDialer(t, proxyAddr, e2eVMessUUID)

	ctx := deadlineCtx(t)
	c, err := d.DialContext(ctx, "tcp", echoAddr.String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	verifyRelayRoundTrip(t, c, 1<<20)
	verifyHalfCloseEOF(t, c)
}

// TestE2EVMessUDPRelay exercises VMess UDP (command 0x02): datagrams ride the
// chunk stream one per chunk to a real UDP echo target, integrity holds, and
// the client sees the request destination as the datagram source.
func TestE2EVMessUDPRelay(t *testing.T) {
	for _, sec := range []string{"aes-128-gcm", "chacha20-poly1305"} {
		t.Run(sec, func(t *testing.T) {
			udpEcho := startUDPEchoTarget(t)
			proxyAddr := startVMessE2EServer(t, happyVMessE2EServerConfig())
			d := newVMessClientDialer(t, proxyAddr, sec, e2eVMessUUID)

			ctx := deadlineCtx(t)
			pc, err := d.DialContext(ctx, "udp", udpEcho.String())
			if err != nil {
				t.Fatalf("dial udp: %v", err)
			}
			defer pc.Close()

			packetConn, ok := pc.(netproxy.PacketConn)
			if !ok {
				t.Fatalf("DialContext(udp) returned %T, want a PacketConn", pc)
			}
			for i := 0; i < 16; i++ {
				payload := make([]byte, 200+i*31)
				for j := range payload {
					payload[j] = byte(i*131 + j)
				}
				if _, err := packetConn.WriteTo(payload, udpEcho.String()); err != nil {
					t.Fatalf("WriteTo: %v", err)
				}
				buf := make([]byte, 65535)
				if err := pc.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
					t.Fatalf("SetReadDeadline: %v", err)
				}
				n, from, err := packetConn.ReadFrom(buf)
				if err != nil {
					t.Fatalf("ReadFrom: %v", err)
				}
				if n != len(payload) || !bytes.Equal(buf[:n], payload) {
					t.Fatalf("datagram %d mismatch: n=%d", i, n)
				}
				if from.String() != udpEcho.String() {
					t.Fatalf("datagram %d source = %v, want %v", i, from, udpEcho.String())
				}
			}
		})
	}
}

// TestE2EVMessHandshakeFailuresAreErrorsNotPanics checks the auth-failure
// paths: a wrong UUID (fails the encrypted auth id / header AEAD) and a
// response command the client never accepts. The client must surface an
// error in bounded time, never panic or hang.
func TestE2EVMessHandshakeFailuresAreErrorsNotPanics(t *testing.T) {
	t.Run("wrong uuid", func(t *testing.T) {
		echoAddr := loopbackEchoTarget(t)
		proxyAddr := startVMessE2EServer(t, vmessE2EServerConfig{acceptUUID: e2eVMessUUID})
		d := newVMessClientDialer(t, proxyAddr, "aes-128-gcm", e2eWrongUUID)

		ctx := deadlineCtx(t)
		c, err := d.DialContext(ctx, "tcp", echoAddr.String())
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer c.Close()
		expectReadError(t, c)
	})

	t.Run("bad response command", func(t *testing.T) {
		echoAddr := loopbackEchoTarget(t)
		proxyAddr := startVMessE2EServer(t, vmessE2EServerConfig{acceptUUID: e2eVMessUUID, respCmd: 1})
		d := newVMessClientDialer(t, proxyAddr, "aes-128-gcm", e2eVMessUUID)

		ctx := deadlineCtx(t)
		c, err := d.DialContext(ctx, "tcp", echoAddr.String())
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer c.Close()
		expectReadError(t, c)
	})
}
