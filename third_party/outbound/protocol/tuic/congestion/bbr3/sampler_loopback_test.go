package bbr3_test

// sampler_loopback_test.go drives the production upload path end to end instead
// of feeding synthetic ack vectors: a real quic-go connection on loopback
// through a one-way delay, with congestion.UseBbr3 installed on the live
// connection after OpenStreamSync, exactly as the hysteria2 client installs it,
// and a client that writes 24 MiB. The controller has to move all of it.
//
// The history matters here. This test was written as the regression guard for a
// local sampler that permanently stopped registering sends once the send head
// passed its ring; that sampler has since been replaced by the shared reference
// estimator (bbr.RefSampler), which is what the unit tests could never see
// because they inspected bookkeeping rather than the sending stack. The
// end-to-end assertion is kept as the guard that the controller sustains an
// upload far past its own estimate window: the unfixed sender was a hard fixed
// point at the cwnd/pacing floors (~50 KB/s), while a healthy controller moves
// 24 MiB over the same 50 ms path in a couple of seconds.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/protocol/tuic/congestion"
	"github.com/olicesx/quic-go"
)

const (
	uploadBytes    = 24 << 20
	uploadChunk    = 32 << 10
	uploadDeadline = 30 * time.Second
	// oneWayDelay is the client->server leg delay of the emulated path. 50 ms is
	// the configuration the diagnosis used to reproduce the collapse; it gives
	// the path the bandwidth-delay product that puts the sampler window into
	// play on loopback.
	oneWayDelay = 50 * time.Millisecond
	// maxPayloadPerPacket is a deliberately loose upper bound on the stream data
	// one packet can carry, used only to turn the upload volume into a lower
	// bound on the number of packets sent. The MTU this fork ships is 1280 bytes,
	// so the real packet count is higher than uploadBytes/maxPayloadPerPacket.
	maxPayloadPerPacket = 1400
)

// TestBbr3UploadPastTheSamplerWindowCompletes requires a full 24 MiB upload
// through the production sender to finish. It was written as the regression
// guard for the local sampler's registration lockout; the sampler is now the
// shared reference estimator, and the assertion still holds as the end-to-end
// guard that the controller can sustain an upload far past its estimate window.
func TestBbr3UploadPastTheSamplerWindowCompletes(t *testing.T) {
	serverConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("net.ListenUDP() error = %v", err)
	}
	defer func() { _ = serverConn.Close() }()
	listener, err := quic.Listen(serverConn, serverTLSConfig(t), &quic.Config{})
	if err != nil {
		t.Fatalf("quic.Listen() error = %v", err)
	}
	defer func() { _ = listener.Close() }()

	// The client dials the relay instead of the server, so its datagrams reach
	// the server one way delay later.
	relayAddr, closeRelay := startDelayRelay(t, listener.Addr(), oneWayDelay)
	defer closeRelay()

	var received atomic.Int64
	serverDone := make(chan error, 1)
	go func() {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			serverDone <- err
			return
		}
		defer func() { _ = conn.CloseWithError(0, "done") }()
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			serverDone <- err
			return
		}
		buf := make([]byte, 256<<10)
		for {
			n, err := stream.Read(buf)
			if n > 0 {
				received.Add(int64(n))
			}
			if err != nil {
				if err == io.EOF {
					err = nil
				}
				serverDone <- err
				return
			}
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), uploadDeadline)
	defer cancel()
	conn, err := quic.DialAddr(ctx, relayAddr.String(), clientTLSConfig(), &quic.Config{})
	if err != nil {
		t.Fatalf("quic.DialAddr() error = %v", err)
	}
	defer func() { _ = conn.CloseWithError(0, "done") }()

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatalf("OpenStreamSync() error = %v", err)
	}
	// The hysteria2 client installs the controller on the live connection after
	// the stream is open (protocol/hysteria2/client/client.go:196), not through
	// the dial config.
	congestion.UseBbr3(conn, 0)

	payload := make([]byte, uploadChunk)
	for i := range payload {
		payload[i] = byte(i)
	}
	// quic-go's stream write blocks on an internal channel that the dial context
	// does not unblock, so a controller that stops granting window parks the
	// caller for ever. Bound the transfer from outside, the way a relay's own
	// teardown does.
	var written atomic.Int64
	writeDone := make(chan error, 1)
	start := time.Now()
	go func() {
		for written.Load() < uploadBytes {
			n, err := stream.Write(payload)
			written.Add(int64(n))
			if err != nil {
				writeDone <- err
				return
			}
		}
		writeDone <- stream.Close()
	}()

	select {
	case err := <-writeDone:
		if err != nil {
			t.Fatalf("upload write failed after %d of %d bytes: %v", written.Load(), uploadBytes, err)
		}
	case <-time.After(uploadDeadline):
		_ = conn.CloseWithError(0, "stalled")
		t.Fatalf("upload stalled: congestion.UseBbr3 moved %d of %d bytes (%.1f MiB) in %v and never finished; "+
			"before the sampler fix it froze here at ~48 KB/s", written.Load(), uploadBytes,
			float64(written.Load())/(1<<20), uploadDeadline)
	}

	// Written is not delivered: wait for the server to drain the stream.
	drainDeadline := time.Now().Add(uploadDeadline)
	for received.Load() < uploadBytes && time.Now().Before(drainDeadline) {
		select {
		case err := <-serverDone:
			if err != nil {
				t.Fatalf("server stream error = %v", err)
			}
		case <-time.After(50 * time.Millisecond):
		}
	}
	if got := received.Load(); got < uploadBytes {
		t.Fatalf("server received %d of %d bytes: the upload did not complete", got, uploadBytes)
	}

	elapsed := time.Since(start)
	t.Logf("moved %d bytes in %v (%.1f MiB/s) across at least %d packet numbers",
		uploadBytes, elapsed.Round(time.Millisecond),
		float64(uploadBytes)/(1<<20)/elapsed.Seconds(),
		uploadBytes/maxPayloadPerPacket)
}

// startDelayRelay listens on a UDP socket the client can dial instead of the
// server, forwarding client datagrams to serverAddr one delay later and server
// datagrams straight back. It is the client->server leg of the emulated path, so
// the path RTT is about oneWayDelay.
//
// The delay exists because the sampler window only matters once the path holds
// enough in flight to span it: on plain loopback the RTT is microseconds and the
// span never gets near the window. It is a relay rather than a net.PacketConn
// wrapper because quic-go's Transport stops its listen loop by setting the read
// deadline on its conn, and a wrapper that polls would swallow that signal.
func startDelayRelay(t *testing.T, serverAddr net.Addr, delay time.Duration) (net.Addr, func()) {
	t.Helper()
	relay, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("net.ListenUDP() error = %v", err)
	}
	go func() {
		buf := make([]byte, 65536)
		var clientAddr net.Addr
		for {
			n, from, err := relay.ReadFrom(buf)
			if err != nil {
				// The socket was closed; stop relaying.
				return
			}
			data := make([]byte, n)
			copy(data, buf[:n])
			if from.String() == serverAddr.String() {
				if clientAddr != nil {
					_, _ = relay.WriteTo(data, clientAddr)
				}
				continue
			}
			clientAddr = from
			time.AfterFunc(delay, func() { _, _ = relay.WriteTo(data, serverAddr) })
		}
	}()
	return relay.LocalAddr(), func() { _ = relay.Close() }
}

func serverTLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey() error = %v", err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "loopback"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("x509.CreateCertificate() error = %v", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		NextProtos:   []string{"bbr3-sampler-test"},
		MinVersion:   tls.VersionTLS13,
	}
}

func clientTLSConfig() *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"bbr3-sampler-test"},
		MinVersion:         tls.VersionTLS13,
	}
}
