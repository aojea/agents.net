package netnsproxy

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

func TestConfigValidation(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Fatal("missing forwarder accepted")
	}
}

func TestRedirectRules(t *testing.T) {
	for _, udp := range []bool{false, true} {
		var messages []netlink.Message
		sent := errors.New("test transport")
		conn := &nftables.Conn{TestDial: func(requests []netlink.Message) ([]netlink.Message, error) {
			messages = requests
			return nil, sent
		}}
		table := &nftables.Table{Name: "test", Family: nftables.TableFamilyINet}
		redirectRules(conn, table, 7, []ports{{unix.NFPROTO_IPV4, 1234, 5678}, {unix.NFPROTO_IPV6, 1235, 5679}}, udp)
		err := conn.Flush()
		if !errors.Is(err, sent) || len(messages) == 0 {
			t.Fatalf("marshal rules: %v (messages=%d)", err, len(messages))
		}
	}
	match := interfaceMatch(7)
	if match[0].(*expr.Meta).Key != expr.MetaKeyIIF || binary.NativeEndian.Uint32(match[1].(*expr.Cmp).Data) != 7 {
		t.Fatal("rules must match the ingress interface")
	}
}

func TestPacketDestinationRejectsMissingMetadata(t *testing.T) {
	for _, control := range [][]byte{nil, {1, 2, 3}, unix.PktInfo4(&unix.Inet4Pktinfo{Ifindex: 1})} {
		if _, err := packetDestination(control); err == nil {
			t.Fatal("missing original destination accepted")
		}
	}
}

func TestPacketFlowDeadlineAndClose(t *testing.T) {
	flow := &packetFlow{packets: make(chan []byte, 1), done: make(chan struct{}), changed: make(chan struct{})}
	flow.packets <- []byte("packet")
	buf := make([]byte, 20)
	if count, err := flow.Read(buf); err != nil || string(buf[:count]) != "packet" {
		t.Fatalf("read packet: %q, %v", buf[:count], err)
	}
	flow.SetReadDeadline(time.Now().Add(-time.Second))
	if _, err := flow.Read(buf); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("deadline error: %v", err)
	}
	flow.SetReadDeadline(time.Time{})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := flow.Read(buf); done <- err }()
	flow.Close()
	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("close error: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("close did not unblock read")
	}
}
