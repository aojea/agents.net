package qemuproxy

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/aojea/agents.net/sdk/pkg/tun2connect"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/link/ethernet"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

func TestFrames(t *testing.T) {
	frame := bytes.Repeat([]byte{42}, maxFrameSize)
	client, server := net.Pipe()
	defer client.Close()
	go func() {
		defer server.Close()
		var prefix [4]byte
		binary.BigEndian.PutUint32(prefix[:], uint32(len(frame)))
		for _, value := range prefix {
			server.Write([]byte{value})
		}
		server.Write(frame)
		writeFrame(server, frame)
	}()
	for count := 0; count < 2; count++ {
		got, err := readFrame(client)
		if err != nil || !bytes.Equal(got, frame) {
			t.Fatalf("frame %d: %d bytes, %v", count, len(got), err)
		}
	}
}

func TestInvalidFrames(t *testing.T) {
	for _, length := range []uint32{0, 13, maxFrameSize + 1, ^uint32(0)} {
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			var prefix [4]byte
			binary.BigEndian.PutUint32(prefix[:], length)
			server.Write(prefix[:])
		}()
		if _, err := readFrame(client); err == nil {
			t.Errorf("accepted length %d", length)
		}
		client.Close()
	}
	for _, wire := range [][]byte{{0, 0}, {0, 0, 0, 14, 1, 2}} {
		client, server := net.Pipe()
		go func() { server.Write(wire); server.Close() }()
		if _, err := readFrame(client); err == nil {
			t.Error("accepted truncated frame")
		}
		client.Close()
	}
}

type testDialer struct {
	targets chan string
}

func (dialer *testDialer) DialTCP(ctx context.Context, host string, port uint16) (net.Conn, error) {
	dialer.targets <- netip.AddrPortFrom(netip.MustParseAddr(host), port).String()
	client, server := net.Pipe()
	go func() { io.Copy(server, server); server.Close() }()
	return client, nil
}

func (*testDialer) DialUDP(context.Context, string, uint16) (tun2connect.DatagramConn, error) {
	return nil, net.ErrClosed
}

func TestEthernetTCPAndShutdown(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var pumps sync.WaitGroup
	client, server := net.Pipe()
	defer client.Close()
	defer func() { cancel(); client.Close(); pumps.Wait() }()
	dialer := &testDialer{targets: make(chan string, 4)}
	finished := make(chan error, 1)
	go func() {
		finished <- Run(ctx, server, Config{
			MAC:       net.HardwareAddr{2, 0, 0, 0, 0, 1},
			Addresses: []netip.Prefix{netip.MustParsePrefix("10.0.2.1/24"), netip.MustParsePrefix("fd00::1/64")},
			Dialer:    dialer,
		})
	}()
	endpoint := channel.New(256, maxFrameSize, tcpip.LinkAddress("\x02\x00\x00\x00\x00\x02"))
	defer endpoint.Close()
	guest := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{arp.NewProtocol, ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	})
	defer guest.Wait()
	defer guest.Close()
	if err := guest.CreateNIC(1, ethernet.New(endpoint)); err != nil {
		t.Fatal(err)
	}
	for _, address := range []netip.Prefix{netip.MustParsePrefix("10.0.2.2/24"), netip.MustParsePrefix("fd00::2/64")} {
		protocol := ipv6.ProtocolNumber
		if address.Addr().Is4() {
			protocol = ipv4.ProtocolNumber
		}
		if err := guest.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: protocol,
			AddressWithPrefix: tcpip.AddressWithPrefix{Address: tcpip.AddrFromSlice(address.Addr().AsSlice()), PrefixLen: address.Bits()},
		}, stack.AddressProperties{}); err != nil {
			t.Fatal(err)
		}
	}
	guest.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, Gateway: tcpip.AddrFrom4([4]byte{10, 0, 2, 1}), NIC: 1},
		{Destination: header.IPv6EmptySubnet, Gateway: tcpip.AddrFrom16(netip.MustParseAddr("fd00::1").As16()), NIC: 1},
	})
	pumps.Add(2)
	go func() {
		defer pumps.Done()
		for {
			packet := endpoint.ReadContext(ctx)
			if packet == nil {
				return
			}
			view := packet.ToView()
			packet.DecRef()
			err := writeFrame(client, view.AsSlice())
			view.Release()
			if err != nil {
				return
			}
		}
	}()
	go func() {
		defer pumps.Done()
		for {
			frame, err := readFrame(client)
			if err != nil {
				return
			}
			packet := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(frame)})
			endpoint.InjectInbound(0, packet)
			packet.DecRef()
		}
	}()
	for _, destination := range []string{"203.0.113.10", "2001:db8::10"} {
		address := netip.MustParseAddr(destination)
		protocol := ipv6.ProtocolNumber
		if address.Is4() {
			protocol = ipv4.ProtocolNumber
		}
		conn, err := gonet.DialContextTCP(ctx, guest, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(address.AsSlice()), Port: 80}, protocol)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		payload := []byte("GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n")
		if _, err := conn.Write(payload); err != nil {
			t.Fatal(err)
		}
		reply := make([]byte, len(payload))
		if _, err := io.ReadFull(conn, reply); err != nil || !bytes.Equal(reply, payload) {
			t.Fatalf("echo: %q, %v", reply, err)
		}
		if target := <-dialer.targets; target != net.JoinHostPort(destination, "80") {
			t.Fatalf("target = %s", target)
		}
	}
	client.Close()
	select {
	case <-finished:
	case <-time.After(3 * time.Second):
		t.Fatal("adapter did not stop after packet-channel loss")
	}
}

func TestCancellationClosesIdleChannel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client, server := net.Pipe()
	defer client.Close()
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, server, Config{
			MAC:       net.HardwareAddr{2, 0, 0, 0, 0, 1},
			Addresses: []netip.Prefix{netip.MustParsePrefix("10.0.2.1/24")},
			Dialer:    &testDialer{targets: make(chan string, 1)},
		})
	}()
	cancel()
	select {
	case err := <-done:
		if err != context.Canceled {
			t.Fatalf("Run = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("idle packet reader survived cancellation")
	}
}
