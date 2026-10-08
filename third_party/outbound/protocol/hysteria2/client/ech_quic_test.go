package client

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"math/big"
	"testing"
	"time"

	"github.com/olicesx/quic-go"
)

func TestTLSConfigECHNegotiatesOverQUIC(t *testing.T) {
	key, configList := buildTestECHKey(t, "decoy.example.com")
	listener := startECHTestListener(t, key)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	serverResult := acceptECHTestConnection(ctx, listener)

	clientConn, err := quic.DialAddr(ctx, listener.Addr().String(), newECHTestClientTLS(configList), &quic.Config{})
	if err != nil {
		t.Fatalf("quic.DialAddr() error = %v", err)
	}
	defer clientConn.CloseWithError(0, "test complete")

	result := <-serverResult
	if result.err != nil {
		t.Fatalf("server Accept() error = %v", result.err)
	}
	defer result.conn.CloseWithError(0, "test complete")
	if !clientConn.ConnectionState().TLS.ECHAccepted {
		t.Fatal("client TLS state reports ECHAccepted=false")
	}
	if !result.conn.ConnectionState().TLS.ECHAccepted {
		t.Fatal("server TLS state reports ECHAccepted=false")
	}
}

func TestTLSConfigECHRejectsStaleConfigWithoutFallback(t *testing.T) {
	serverKey, _ := buildTestECHKey(t, "decoy.example.com")
	_, staleConfigList := buildTestECHKey(t, "decoy.example.com")
	listener := startECHTestListener(t, serverKey)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	serverResult := acceptECHTestConnection(ctx, listener)

	if _, err := quic.DialAddr(ctx, listener.Addr().String(), newECHTestClientTLS(staleConfigList), &quic.Config{}); err == nil {
		t.Fatal("quic.DialAddr() unexpectedly succeeded with a stale ECH config list")
	}
	_ = listener.Close()
	select {
	case <-serverResult:
	case <-time.After(time.Second):
		t.Fatal("server accept did not stop after listener close")
	}
}

type echTestAcceptResult struct {
	conn quic.Connection
	err  error
}

func acceptECHTestConnection(ctx context.Context, listener *quic.Listener) <-chan echTestAcceptResult {
	result := make(chan echTestAcceptResult, 1)
	go func() {
		conn, err := listener.Accept(ctx)
		result <- echTestAcceptResult{conn: conn, err: err}
	}()
	return result
}

func startECHTestListener(t *testing.T, key tls.EncryptedClientHelloKey) *quic.Listener {
	t.Helper()
	listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{
		Certificates:             []tls.Certificate{testECHCertificate(t)},
		EncryptedClientHelloKeys: []tls.EncryptedClientHelloKey{key},
		MinVersion:               tls.VersionTLS13,
		NextProtos:               []string{"h3"},
	}, &quic.Config{})
	if err != nil {
		t.Fatalf("quic.ListenAddr() error = %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	return listener
}

func newECHTestClientTLS(configList []byte) *tls.Config {
	config := (TLSConfig{
		ServerName:                     "secret.internal",
		InsecureSkipVerify:             true,
		EncryptedClientHelloConfigList: configList,
	}).toTLSConfig()
	config.NextProtos = []string{"h3"}
	return config
}

func buildTestECHKey(t *testing.T, publicName string) (tls.EncryptedClientHelloKey, []byte) {
	t.Helper()
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ecdh.GenerateKey() error = %v", err)
	}

	contents := []byte{0x00}
	contents = binary.BigEndian.AppendUint16(contents, 0x0020)
	publicKey := privateKey.PublicKey().Bytes()
	contents = binary.BigEndian.AppendUint16(contents, uint16(len(publicKey)))
	contents = append(contents, publicKey...)
	cipherSuites := []byte{0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x03}
	contents = binary.BigEndian.AppendUint16(contents, uint16(len(cipherSuites)))
	contents = append(contents, cipherSuites...)
	contents = append(contents, 0x00, byte(len(publicName)))
	contents = append(contents, publicName...)
	contents = binary.BigEndian.AppendUint16(contents, 0)

	config := binary.BigEndian.AppendUint16(nil, 0xfe0d)
	config = binary.BigEndian.AppendUint16(config, uint16(len(contents)))
	config = append(config, contents...)
	configList := binary.BigEndian.AppendUint16(nil, uint16(len(config)))
	configList = append(configList, config...)

	return tls.EncryptedClientHelloKey{
		Config:     config,
		PrivateKey: privateKey.Bytes(),
	}, configList
}

func testECHCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey() error = %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "secret.internal"},
		DNSNames:     []string{"secret.internal", "decoy.example.com"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Minute),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("x509.CreateCertificate() error = %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
