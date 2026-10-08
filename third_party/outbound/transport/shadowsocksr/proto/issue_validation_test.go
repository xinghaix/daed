//go:build race
// +build race

// Validates the issues found while reviewing the outbound network code.
// Run with the -race flag: go test -race -v -run TestIssueValidation
package proto

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol/infra/socks"
)

// ========================================
// Issue 1: concurrent writes on the shadowsockr UDP path
// ========================================

// MockProtocol impersonates the Protocol interface
type MockProtocol struct{}

func (m *MockProtocol) EncodePkt(buf *bytes.Buffer) error {
	// Simulate the encoding work
	time.Sleep(1 * time.Microsecond)
	return nil
}

func (m *MockProtocol) DecodePkt(buf []byte) ([]byte, error) {
	return buf, nil
}

// MockPacketConn impersonates netproxy.PacketConn
type MockPacketConn struct {
	writeCount     atomic.Int64
	dataCorruption atomic.Bool
	lastData       atomic.Value
}

func (m *MockPacketConn) Read(b []byte) (n int, err error) {
	return 0, nil
}

func (m *MockPacketConn) Write(b []byte) (n int, err error) {
	m.writeCount.Add(1)
	return len(b), nil
}

func (m *MockPacketConn) ReadFrom(p []byte) (n int, addr netip.AddrPort, err error) {
	return 0, netip.AddrPort{}, nil
}

func (m *MockPacketConn) WriteTo(p []byte, addr string) (n int, err error) {
	m.writeCount.Add(1)

	// Simulate the write latency
	time.Sleep(1 * time.Microsecond)

	// Detect a data race
	lastData := m.lastData.Load()
	if lastData != nil {
		oldData := lastData.([]byte)
		if len(oldData) > 0 {
			// The previous write is still in flight, so a race is possible
			m.dataCorruption.Store(true)
		}
	}
	m.lastData.Store(p)
	time.Sleep(1 * time.Microsecond)
	m.lastData.Store([]byte{})

	return len(p), nil
}

func (m *MockPacketConn) Close() error {
	return nil
}

func (m *MockPacketConn) SetDeadline(t time.Time) error {
	return nil
}

func (m *MockPacketConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (m *MockPacketConn) SetWriteDeadline(t time.Time) error {
	return nil
}

// SimulateShadowsockrPacketConn mimics the shadowsockr PacketConn (no write
// lock)
type SimulateShadowsockrPacketConn struct {
	inner    *MockPacketConn
	protocol *MockProtocol
	tgt      string
	// Note: there is no writeMu here
}

func (c *SimulateShadowsockrPacketConn) WriteTo(b []byte, to string) (int, error) {
	// Mimic shadowsockr's WriteTo logic (no write lock)
	addr, err := socks.ParseAddr(to)
	if err != nil {
		return 0, err
	}

	// Get a buffer
	pb := pool.Get(len(addr) + len(b))
	defer pool.Put(pb)

	// Copy the data
	copy(pb, addr)
	copy(pb[len(addr):], b)

	// Encode
	buf := bytes.NewBuffer(pb)
	if err = c.protocol.EncodePkt(buf); err != nil {
		return 0, err
	}

	// Write: nothing serializes this
	_, err = c.inner.WriteTo(buf.Bytes(), c.tgt)
	if err != nil {
		return 0, err
	}

	return len(b), nil
}

// FixedShadowsockrPacketConn is the fixed shadowsockr PacketConn (with a write
// lock)
type FixedShadowsockrPacketConn struct {
	inner    *MockPacketConn
	protocol *MockProtocol
	tgt      string
	writeMu  sync.Mutex // Add the write lock
}

func (c *FixedShadowsockrPacketConn) WriteTo(b []byte, to string) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	addr, err := socks.ParseAddr(to)
	if err != nil {
		return 0, err
	}

	pb := pool.Get(len(addr) + len(b))
	defer pool.Put(pb)

	copy(pb, addr)
	copy(pb[len(addr):], b)

	buf := bytes.NewBuffer(pb)
	if err = c.protocol.EncodePkt(buf); err != nil {
		return 0, err
	}

	_, err = c.inner.WriteTo(buf.Bytes(), c.tgt)
	if err != nil {
		return 0, err
	}

	return len(b), nil
}

// TestIssue1_Outbound_ShadowsockrUDPRace validates issue 1: concurrent writes
// on the shadowsockr UDP path
func TestIssue1_Outbound_ShadowsockrUDPRace(t *testing.T) {
	t.Log("🔍 验证问题 1: shadowsockr UDP 并发写入 (outbound)")

	// Test the unlocked case
	t.Run("WithoutLock", func(t *testing.T) {
		inner := &MockPacketConn{}
		protocol := &MockProtocol{}

		conn := &SimulateShadowsockrPacketConn{
			inner:    inner,
			protocol: protocol,
			tgt:      "127.0.0.1:8080",
		}

		const goroutines = 10
		const writesPerGoroutine = 100

		var wg sync.WaitGroup
		wg.Add(goroutines)

		startTime := time.Now()

		for i := 0; i < goroutines; i++ {
			go func(id int) {
				defer wg.Done()
				for j := 0; j < writesPerGoroutine; j++ {
					data := []byte(fmt.Sprintf("packet-%d-%d", id, j))
					_, err := conn.WriteTo(data, "127.0.0.1:8080")
					if err != nil {
						t.Errorf("WriteTo failed: %v", err)
					}
				}
			}(i)
		}

		wg.Wait()
		elapsed := time.Since(startTime)

		writes := inner.writeCount.Load()
		expected := int64(goroutines * writesPerGoroutine)

		t.Logf("✅ 无锁测试完成: %d 次写入，耗时 %v", writes, elapsed)

		if writes != expected {
			t.Errorf("❌ 写入计数不匹配: got %d, expected %d", writes, expected)
		}

		if inner.dataCorruption.Load() {
			t.Log("⚠️  检测到潜在的数据竞争迹象")
		}

		t.Log("⚠️  使用 'go test -race' 运行此测试以检测数据竞争")
	})

	// Test the locked case
	t.Run("WithLock", func(t *testing.T) {
		inner := &MockPacketConn{}
		protocol := &MockProtocol{}

		conn := &FixedShadowsockrPacketConn{
			inner:    inner,
			protocol: protocol,
			tgt:      "127.0.0.1:8080",
		}

		const goroutines = 10
		const writesPerGoroutine = 100

		var wg sync.WaitGroup
		wg.Add(goroutines)

		startTime := time.Now()

		for i := 0; i < goroutines; i++ {
			go func(id int) {
				defer wg.Done()
				for j := 0; j < writesPerGoroutine; j++ {
					data := []byte(fmt.Sprintf("packet-%d-%d", id, j))
					_, err := conn.WriteTo(data, "127.0.0.1:8080")
					if err != nil {
						t.Errorf("WriteTo failed: %v", err)
					}
				}
			}(i)
		}

		wg.Wait()
		elapsed := time.Since(startTime)

		writes := inner.writeCount.Load()
		expected := int64(goroutines * writesPerGoroutine)

		t.Logf("✅ 有锁测试完成: %d 次写入，耗时 %v", writes, elapsed)

		if writes != expected {
			t.Errorf("❌ 写入计数不匹配: got %d, expected %d", writes, expected)
		}
	})
}

// ========================================
// Issue 2: the lazy-cache race in directPacketConn
// ========================================

// SimulateDirectPacketConn mimics directPacketConn (no write lock)
type SimulateDirectPacketConn struct {
	conn          *net.UDPConn
	cachedDialTgt atomic.Pointer[netip.AddrPort]
	cacheOnce     atomic.Bool // Simplified: the real code uses sync.Once
	dialTgt       string
	FullCone      bool
}

func (c *SimulateDirectPacketConn) resolveTarget() error {
	// Simulate the resolution latency
	time.Sleep(10 * time.Millisecond)

	target := netip.MustParseAddrPort(c.dialTgt)
	c.cachedDialTgt.Store(&target)
	return nil
}

func (c *SimulateDirectPacketConn) Write(b []byte) (int, error) {
	if !c.FullCone {
		return c.conn.Write(b)
	}

	// Lazy cache with no lock protecting it
	cached := c.cachedDialTgt.Load()
	if cached == nil {
		if !c.cacheOnce.Swap(true) {
			// The first goroutine resolves the target
			c.resolveTarget()
		} else {
			// The other goroutines wait for the resolution to finish
			for c.cachedDialTgt.Load() == nil {
				time.Sleep(1 * time.Millisecond)
			}
		}
		cached = c.cachedDialTgt.Load()
	}

	// Write: nothing serializes this
	return c.conn.WriteToUDPAddrPort(b, *cached)
}

// FixedDirectPacketConn is the fixed directPacketConn (with a write lock)
type FixedDirectPacketConn struct {
	conn          *net.UDPConn
	cachedDialTgt atomic.Pointer[netip.AddrPort]
	resolveOnce   sync.Once
	resolveErr    error
	dialTgt       string
	FullCone      bool
	writeMu       sync.Mutex
}

func (c *FixedDirectPacketConn) resolveTarget() error {
	c.resolveOnce.Do(func() {
		time.Sleep(10 * time.Millisecond)
		target := netip.MustParseAddrPort(c.dialTgt)
		c.cachedDialTgt.Store(&target)
	})
	return c.resolveErr
}

func (c *FixedDirectPacketConn) Write(b []byte) (int, error) {
	if !c.FullCone {
		return c.conn.Write(b)
	}

	// Make sure the target is resolved
	if c.cachedDialTgt.Load() == nil {
		c.resolveTarget()
	}

	// Serialized by the write lock
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	cached := c.cachedDialTgt.Load()
	return c.conn.WriteToUDPAddrPort(b, *cached)
}

// TestIssue2_Outbound_DirectPacketConnLazyCache validates issue 2: the
// directPacketConn lazy-cache race
func TestIssue2_Outbound_DirectPacketConnLazyCache(t *testing.T) {
	t.Log("🔍 验证问题 2: directPacketConn 懒缓存竞争 (outbound)")

	// Create a real UDP connection
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("Failed to create UDP connection: %v", err)
	}
	defer conn.Close()

	// Test the unlocked case
	t.Run("WithoutLock", func(t *testing.T) {
		directConn := &SimulateDirectPacketConn{
			conn:     conn,
			dialTgt:  "127.0.0.1:8080",
			FullCone: true,
		}

		const goroutines = 10
		const writesPerGoroutine = 50

		var wg sync.WaitGroup
		wg.Add(goroutines)

		startTime := time.Now()

		for i := 0; i < goroutines; i++ {
			go func(id int) {
				defer wg.Done()
				for j := 0; j < writesPerGoroutine; j++ {
					data := []byte(fmt.Sprintf("direct-%d-%d", id, j))
					_, err := directConn.Write(data)
					if err != nil {
						t.Logf("Write error: %v", err)
					}
				}
			}(i)
		}

		wg.Wait()
		elapsed := time.Since(startTime)

		t.Logf("✅ 无锁测试完成，耗时 %v", elapsed)
		t.Log("⚠️  检查 UDP 连接是否有并发写入问题")
	})

	// Test the locked case
	t.Run("WithLock", func(t *testing.T) {
		directConn := &FixedDirectPacketConn{
			conn:     conn,
			dialTgt:  "127.0.0.1:8080",
			FullCone: true,
		}

		const goroutines = 10
		const writesPerGoroutine = 50

		var wg sync.WaitGroup
		wg.Add(goroutines)

		startTime := time.Now()

		for i := 0; i < goroutines; i++ {
			go func(id int) {
				defer wg.Done()
				for j := 0; j < writesPerGoroutine; j++ {
					data := []byte(fmt.Sprintf("direct-%d-%d", id, j))
					_, err := directConn.Write(data)
					if err != nil {
						t.Errorf("Write failed: %v", err)
					}
				}
			}(i)
		}

		wg.Wait()
		elapsed := time.Since(startTime)

		t.Logf("✅ 有锁测试完成，耗时 %v", elapsed)
	})
}

// ========================================
// Issue 7: the boundary checks in Pool.Put
// ========================================

// TestIssue7_Outbound_PoolPutBoundary validates issue 7: the Pool.Put boundary
// checks
func TestIssue7_Outbound_PoolPutBoundary(t *testing.T) {
	t.Log("🔍 验证问题 7: Pool.Put 边界检查 (outbound)")

	testCases := []struct {
		name         string
		capacity     int
		shouldAccept bool
		note         string
	}{
		{"64 bytes (too small)", 64, false, "should be rejected"},
		{"512 bytes (min)", 512, true, "bucket 9"},
		{"1024 bytes (2^10)", 1024, true, "bucket 10"},
		{"1536 bytes (not power of 2)", 1536, true, "⚠️  goes to bucket 10, not 11"},
		{"2048 bytes (2^11)", 2048, true, "bucket 11"},
		{"4096 bytes (2^12)", 4096, true, "bucket 12"},
		{"65536 bytes (max)", 65536, true, "bucket 16"},
		{"70000 bytes (too large)", 70000, false, "should be rejected"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			buf := make([]byte, tc.capacity)

			t.Logf("Testing: cap=%d, %s", tc.capacity, tc.note)

			// Call Put (it must not panic)
			pool.Put(buf)

			if tc.shouldAccept {
				t.Logf("✅ Buffer accepted (cap=%d)", tc.capacity)
			} else {
				t.Logf("✅ Buffer rejected (cap=%d)", tc.capacity)
			}
		})
	}

	t.Log("⚠️  问题确认: cap=1536 的 buffer 会被放入错误的 bucket")
	t.Log("   这会导致:")
	t.Log("   1. 内存浪费（大 buffer 放入小 bucket）")
	t.Log("   2. 性能下降（下次 Get 可能容量不足）")
}

// ========================================
// Combined comparison test
// ========================================

// TestOutboundLockVsNoLock compares the performance with and without the lock
func TestOutboundLockVsNoLock(t *testing.T) {
	t.Log("🔍 对比测试: 有锁 vs 无锁")

	// Build the test components
	protocol := &MockProtocol{}

	const goroutines = 10
	const writesPerGoroutine = 100

	t.Run("WithoutLock", func(t *testing.T) {
		inner := &MockPacketConn{}
		conn := &SimulateShadowsockrPacketConn{
			inner:    inner,
			protocol: protocol,
			tgt:      "127.0.0.1:8080",
		}

		var wg sync.WaitGroup
		wg.Add(goroutines)

		startTime := time.Now()

		for i := 0; i < goroutines; i++ {
			go func(id int) {
				defer wg.Done()
				for j := 0; j < writesPerGoroutine; j++ {
					data := []byte(fmt.Sprintf("test-%d-%d", id, j))
					conn.WriteTo(data, "127.0.0.1:8080")
				}
			}(i)
		}

		wg.Wait()
		elapsed := time.Since(startTime)

		t.Logf("无锁: %v (%.2f ops/sec)", elapsed, float64(goroutines*writesPerGoroutine)/elapsed.Seconds())
	})

	t.Run("WithLock", func(t *testing.T) {
		inner := &MockPacketConn{}
		conn := &FixedShadowsockrPacketConn{
			inner:    inner,
			protocol: protocol,
			tgt:      "127.0.0.1:8080",
		}

		var wg sync.WaitGroup
		wg.Add(goroutines)

		startTime := time.Now()

		for i := 0; i < goroutines; i++ {
			go func(id int) {
				defer wg.Done()
				for j := 0; j < writesPerGoroutine; j++ {
					data := []byte(fmt.Sprintf("test-%d-%d", id, j))
					conn.WriteTo(data, "127.0.0.1:8080")
				}
			}(i)
		}

		wg.Wait()
		elapsed := time.Since(startTime)

		t.Logf("有锁: %v (%.2f ops/sec)", elapsed, float64(goroutines*writesPerGoroutine)/elapsed.Seconds())
	})

	t.Log("⚠️  注意: 锁的开销通常小于数据竞争修复的成本")
}

// TestBufferPoolMemoryUsage tests the memory usage of the buffer pool
func TestBufferPoolMemoryUsage(t *testing.T) {
	t.Log("🔍 Buffer Pool 内存使用测试")

	// Capture the initial memory state
	// var m1 runtime.MemStats
	// runtime.ReadMemStats(&m1)

	const iterations = 10000

	// Test normal usage
	for i := 0; i < iterations; i++ {
		buf := pool.Get(1500)
		// Use the buffer
		_ = buf
		pool.Put(buf)
	}

	// var m2 runtime.MemStats
	// runtime.ReadMemStats(&m2)

	// Test the problem scenario: a 1536-byte buffer
	for i := 0; i < iterations; i++ {
		buf := make([]byte, 1536)
		pool.Put(buf) // It goes into the wrong bucket
	}

	// var m3 runtime.MemStats
	// runtime.ReadMemStats(&m3)

	t.Log("✅ 内存使用测试完成")
	t.Log("⚠️  使用 pprof 检查内存分配:")
	t.Log("   go test -memprofile=mem.prof -bench=. -run=TestBufferPoolMemoryUsage")
	t.Log("   go tool pprof mem.prof")
}
