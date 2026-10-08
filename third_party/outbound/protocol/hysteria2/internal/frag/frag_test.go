package frag

import (
	"reflect"
	"strings"
	"testing"

	"github.com/daeuniverse/outbound/protocol/hysteria2/internal/protocol"
)

func TestFragUDPMessage(t *testing.T) {
	type args struct {
		m       *protocol.UDPMessage
		maxSize int
	}
	tests := []struct {
		name string
		args args
		want []protocol.UDPMessage
	}{
		{
			"no frag",
			args{
				&protocol.UDPMessage{
					SessionID: 123,
					PacketID:  123,
					FragID:    0,
					FragCount: 1,
					Addr:      []byte("test:123"),
					Data:      []byte("hello"),
				},
				100,
			},
			[]protocol.UDPMessage{
				{
					SessionID: 123,
					PacketID:  123,
					FragID:    0,
					FragCount: 1,
					Addr:      []byte("test:123"),
					Data:      []byte("hello"),
				},
			},
		},
		{
			"2 frags",
			args{
				&protocol.UDPMessage{
					SessionID: 123,
					PacketID:  123,
					FragID:    0,
					FragCount: 1,
					Addr:      []byte("test:123"),
					Data:      []byte("hello"),
				},
				20,
			},
			[]protocol.UDPMessage{
				{
					SessionID: 123,
					PacketID:  123,
					FragID:    0,
					FragCount: 2,
					Addr:      []byte("test:123"),
					Data:      []byte("hel"),
				},
				{
					SessionID: 123,
					PacketID:  123,
					FragID:    1,
					FragCount: 2,
					Addr:      []byte("test:123"),
					Data:      []byte("lo"),
				},
			},
		},
		{
			"4 frags",
			args{
				&protocol.UDPMessage{
					SessionID: 123,
					PacketID:  123,
					FragID:    0,
					FragCount: 1,
					Addr:      []byte("test:123"),
					Data:      []byte("abcdefgh"),
				},
				19,
			},
			[]protocol.UDPMessage{
				{
					SessionID: 123,
					PacketID:  123,
					FragID:    0,
					FragCount: 4,
					Addr:      []byte("test:123"),
					Data:      []byte("ab"),
				},
				{
					SessionID: 123,
					PacketID:  123,
					FragID:    1,
					FragCount: 4,
					Addr:      []byte("test:123"),
					Data:      []byte("cd"),
				},
				{
					SessionID: 123,
					PacketID:  123,
					FragID:    2,
					FragCount: 4,
					Addr:      []byte("test:123"),
					Data:      []byte("ef"),
				},
				{
					SessionID: 123,
					PacketID:  123,
					FragID:    3,
					FragCount: 4,
					Addr:      []byte("test:123"),
					Data:      []byte("gh"),
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := FragUDPMessage(tt.args.m, tt.args.maxSize)
			if err != nil {
				t.Fatalf("FragUDPMessage() error = %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("FragUDPMessage() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFragUDPMessageNoFragAliasesAddrAndData(t *testing.T) {
	addr := []byte("test:123")
	data := []byte("hello")
	msg := &protocol.UDPMessage{
		SessionID: 123,
		PacketID:  123,
		FragID:    0,
		FragCount: 1,
		Addr:      addr,
		Data:      data,
	}
	got, err := FragUDPMessage(msg, 100)
	if err != nil {
		t.Fatalf("FragUDPMessage: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("len(got) = %d, want 1", len(got))
	}
	if len(got[0].Addr) == 0 || &got[0].Addr[0] != &addr[0] {
		t.Fatal("non-fragment Addr was copied; zero-copy alias required")
	}
	if len(got[0].Data) == 0 || &got[0].Data[0] != &data[0] {
		t.Fatal("non-fragment Data was copied; zero-copy alias required")
	}
}

func TestFragUDPMessageRejectsIllegalCapacity(t *testing.T) {
	msg := &protocol.UDPMessage{
		SessionID: 1,
		PacketID:  1,
		FragID:    0,
		FragCount: 1,
		Addr:      []byte("1.1.1.1:53"),
		Data:      []byte("hello"),
	}

	t.Run("header-only max size", func(t *testing.T) {
		got, err := FragUDPMessage(msg, msg.HeaderSize())
		if err == nil {
			t.Fatal("expected error for maxSize == HeaderSize")
		}
		if got != nil {
			t.Fatalf("got fragments %v, want nil", got)
		}
		if !strings.Contains(err.Error(), "cannot hold UDP header") {
			t.Fatalf("err = %v, want header-capacity message", err)
		}
	})

	t.Run("negative payload capacity", func(t *testing.T) {
		got, err := FragUDPMessage(msg, 1)
		if err == nil {
			t.Fatal("expected error for maxSize < HeaderSize")
		}
		if got != nil {
			t.Fatalf("got fragments %v, want nil", got)
		}
	})

	t.Run("fragCount overflow", func(t *testing.T) {
		big := *msg
		big.Data = make([]byte, 256)
		got, err := FragUDPMessage(&big, big.HeaderSize()+1)
		if err == nil {
			t.Fatal("expected error for FragCount overflow")
		}
		if got != nil {
			t.Fatalf("got fragments %v, want nil", got)
		}
		if !strings.Contains(err.Error(), "exceeds uint8 FragCount") {
			t.Fatalf("err = %v, want FragCount overflow message", err)
		}
	})
}

func TestDefragger(t *testing.T) {
	type args struct {
		m *protocol.UDPMessage
	}
	tests := []struct {
		name string
		args args
		want *protocol.UDPMessage
	}{
		{
			"no frag",
			args{
				&protocol.UDPMessage{
					SessionID: 123,
					PacketID:  987,
					FragID:    0,
					FragCount: 1,
					Addr:      []byte("test:123"),
					Data:      []byte("hello"),
				},
			},
			&protocol.UDPMessage{
				SessionID: 123,
				PacketID:  987,
				FragID:    0,
				FragCount: 1,
				Addr:      []byte("test:123"),
				Data:      []byte("hello"),
			},
		},
		{
			"frag 0 - 1/2",
			args{
				&protocol.UDPMessage{
					SessionID: 123,
					PacketID:  987,
					FragID:    0,
					FragCount: 2,
					Addr:      []byte("test:123"),
					Data:      []byte("hello "),
				},
			},
			nil,
		},
		{
			"frag 0 - 2/2",
			args{
				&protocol.UDPMessage{
					SessionID: 123,
					PacketID:  987,
					FragID:    1,
					FragCount: 2,
					Addr:      []byte("test:123"),
					Data:      []byte("moto"),
				},
			},
			&protocol.UDPMessage{
				SessionID: 123,
				PacketID:  987,
				FragID:    0,
				FragCount: 1,
				Addr:      []byte("test:123"),
				Data:      []byte("hello moto"),
			},
		},
		{
			"frag 1 - 1/3",
			args{
				&protocol.UDPMessage{
					SessionID: 123,
					PacketID:  987,
					FragID:    0,
					FragCount: 3,
					Addr:      []byte("test:123"),
					Data:      []byte("deco"),
				},
			},
			nil,
		},
		{
			"frag 1 - 2/3",
			args{
				&protocol.UDPMessage{
					SessionID: 123,
					PacketID:  987,
					FragID:    1,
					FragCount: 3,
					Addr:      []byte("test:123"),
					Data:      []byte("*"),
				},
			},
			nil,
		},
		{
			"frag 1 - 3/3",
			args{
				&protocol.UDPMessage{
					SessionID: 123,
					PacketID:  987,
					FragID:    2,
					FragCount: 3,
					Addr:      []byte("test:123"),
					Data:      []byte("27"),
				},
			},
			&protocol.UDPMessage{
				SessionID: 123,
				PacketID:  987,
				FragID:    0,
				FragCount: 1,
				Addr:      []byte("test:123"),
				Data:      []byte("deco*27"),
			},
		},
		{
			"frag 2 - 1/2",
			args{
				&protocol.UDPMessage{
					SessionID: 123,
					PacketID:  233,
					FragID:    1,
					FragCount: 2,
					Addr:      []byte("test:123"),
					Data:      []byte("shinsekai"),
				},
			},
			nil,
		},
		{
			"frag 3 - 2/2",
			args{
				&protocol.UDPMessage{
					SessionID: 123,
					PacketID:  244,
					FragID:    1,
					FragCount: 2,
					Addr:      []byte("test:123"),
					Data:      []byte("what???"),
				},
			},
			nil,
		},
		{
			"frag 2 - 2/2",
			args{
				&protocol.UDPMessage{
					SessionID: 123,
					PacketID:  233,
					FragID:    1,
					FragCount: 2,
					Addr:      []byte("test:123"),
					Data:      []byte(" annaijo"),
				},
			},
			nil,
		},
		{
			"invalid id",
			args{
				&protocol.UDPMessage{
					SessionID: 123,
					PacketID:  233,
					FragID:    88,
					FragCount: 2,
					Addr:      []byte("test:123"),
					Data:      []byte("shinsekai"),
				},
			},
			nil,
		},
		{
			"frag 2 - 1/2 re",
			args{
				&protocol.UDPMessage{
					SessionID: 123,
					PacketID:  233,
					FragID:    0,
					FragCount: 2,
					Addr:      []byte("test:123"),
					Data:      []byte("shinsekai"),
				},
			},
			&protocol.UDPMessage{
				SessionID: 123,
				PacketID:  233,
				FragID:    0,
				FragCount: 1,
				Addr:      []byte("test:123"),
				Data:      []byte("shinsekai annaijo"),
			},
		},
	}

	d := &Defragger{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := d.Feed(tt.args.m); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Feed() = %v, want %v", got, tt.want)
			}
		})
	}
}
