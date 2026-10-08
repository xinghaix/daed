package juicity

import (
	"strconv"
	"testing"

	"github.com/daeuniverse/outbound/ciphers"
	"github.com/daeuniverse/outbound/pkg/fastrand"
	"github.com/daeuniverse/outbound/protocol/infra/bench"
	"github.com/daeuniverse/outbound/protocol/shadowsocks"
)

// juicityDatagramHarness adapts the Juicity UDP encrypt/decrypt hot path to the
// unified bench framework. Juicity reuses shadowsocks UDP AEAD primitives; this
// measures the per-datagram decrypt cost that runs once per inbound UDP packet.
type juicityDatagramHarness struct {
	key  *shadowsocks.Key
	salt []byte
	info []byte
}

func newJuicityDatagramHarness() *juicityDatagramHarness {
	conf := CipherConf
	masterKey := make([]byte, conf.KeyLen)
	_, _ = fastrand.Read(masterKey)
	salt := make([]byte, conf.SaltLen)
	_, _ = fastrand.Read(salt)
	return &juicityDatagramHarness{
		key:  &shadowsocks.Key{CipherConf: conf, MasterKey: masterKey},
		salt: salt,
		info: ciphers.JuicityReusedInfo,
	}
}

func (juicityDatagramHarness) Name() string { return "juicity" }

func (h *juicityDatagramHarness) BuildDatagram(b *testing.B, payloadSize int) []byte {
	b.Helper()
	plaintext := make([]byte, payloadSize)
	enc, err := shadowsocks.EncryptUDPFromPoolZeroNonce(h.key, plaintext, h.salt, h.info)
	if err != nil {
		b.Fatalf("encrypt: %v", err)
	}
	return enc
}

func (h *juicityDatagramHarness) ProcessDatagram(msg []byte) {
	dec, err := shadowsocks.DecryptUDPFromPool(h.key, msg, h.info)
	if err != nil {
		panic(err)
	}
	dec.Put()
}

var _ bench.UDPDatagramHarness = (*juicityDatagramHarness)(nil)

var juicityDatagramSizes = []int{8, 100, 512, 1024}

// BenchmarkJuicityDatagramUnified measures the Juicity UDP decrypt hot path
// through the unified framework.
func BenchmarkJuicityDatagramUnified(b *testing.B) {
	h := newJuicityDatagramHarness()
	for _, size := range juicityDatagramSizes {
		b.Run("payload/"+strconv.Itoa(size), func(b *testing.B) {
			bench.RunUDPDatagramBench(b, h, size)
		})
	}
}
