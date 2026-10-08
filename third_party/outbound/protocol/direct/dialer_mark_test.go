//go:build linux

package direct

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"syscall"
	"testing"

	"github.com/daeuniverse/outbound/netproxy"
	"golang.org/x/sys/unix"
)

func TestDirectUDPDialAppliesSocketMark(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	const mark = 0x100
	dialer := NewDirectDialerLaddr(netip.Addr{}, Option{})
	conn, err := dialer.DialContext(
		context.Background(),
		netproxy.MagicNetwork{Network: "udp", Mark: mark}.Encode(),
		server.LocalAddr().String(),
	)
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			t.Skipf("SO_MARK requires CAP_NET_ADMIN: %v", err)
		}
		t.Fatal(err)
	}
	defer conn.Close()

	rawConn, ok := conn.(interface {
		SyscallConn() (syscall.RawConn, error)
	})
	if !ok {
		t.Fatalf("direct UDP connection %T does not expose SyscallConn", conn)
	}
	raw, err := rawConn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var got int
	if err := raw.Control(func(fd uintptr) {
		got, err = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK)
	}); err != nil {
		t.Fatal(err)
	}
	if got != mark {
		t.Fatalf("SO_MARK = %#x, want %#x", got, mark)
	}
}
