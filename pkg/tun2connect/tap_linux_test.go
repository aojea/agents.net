// Copyright 2026 The Kubernetes Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build linux

package tun2connect

import (
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// TestTAPDeviceARPOutboundAndInboundDial proves NewTAPDevice + DialGuestTCP
// work end to end over an L2 Ethernet AF_UNIX SOCK_DGRAM socketpair (identical
// wire framing to kernel IFF_TAP|IFF_NO_PI and QEMU -netdev dgram):
//   - Guest resolves gateway via ARP and opens outbound TCP through Engine.
//   - Host calls Engine.DialGuestTCP to reach a TCP listener inside the guest.
func TestTAPDeviceARPOutboundAndInboundDial(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("socketpair(AF_UNIX, SOCK_DGRAM): %v", err)
	}
	guestFD, engFD := fds[0], fds[1]
	t.Cleanup(func() {
		_ = unix.Close(guestFD)
		_ = unix.Close(engFD)
	})

	// Build guest L2 stack with ARP + IPv4 + TCP/UDP (emulating a microVM's eth0).
	guestEP, err := fdbased.New(&fdbased.Options{
		FDs:            []int{guestFD},
		MTU:            1500,
		Address:        tcpip.LinkAddress("\x02\x61\x67\x6e\x74\x02"),
		EthernetHeader: true,
	})
	if err != nil {
		t.Fatalf("guest fdbased.New: %v", err)
	}
	guest := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{arp.NewProtocol, ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	t.Cleanup(func() {
		guest.Close()
		guest.Wait()
	})
	if err := guest.CreateNIC(1, guestEP); err != nil {
		t.Fatalf("guest CreateNIC: %v", err)
	}
	guestIP := netip.MustParseAddr(DefaultGuestAddr4)
	gwIP := netip.MustParseAddr(DefaultResolverAddr)
	if err := guest.AddProtocolAddress(1, tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFrom4(guestIP.As4()),
			PrefixLen: DefaultPool4Bits,
		},
	}, stack.AddressProperties{}); err != nil {
		t.Fatalf("guest AddProtocolAddress: %v", err)
	}
	guest.SetRouteTable([]tcpip.Route{{
		Destination: header.IPv4EmptySubnet,
		Gateway:     tcpip.AddrFrom4(gwIP.As4()),
		NIC:         1,
	}})

	// Build Engine on the peer end using NewTAPDevice.
	engEP, err := NewTAPDevice(engFD, 1500, "")
	if err != nil {
		t.Fatalf("NewTAPDevice: %v", err)
	}
	vdns := NewVirtualDNS()
	var dialedTarget string
	dialer := &stubDialer{
		onTCP: func(_ context.Context, name string, port uint16) (net.Conn, error) {
			dialedTarget = name
			c1, c2 := net.Pipe()
			go func() {
				defer c2.Close()
				_, _ = io.Copy(c2, c2)
			}()
			return c1, nil
		},
	}
	eng, err := New(Config{
		Device:    engEP,
		Addresses: []netip.Prefix{netip.MustParsePrefix("198.19.255.253/15")},
		Dialer:    dialer,
		DNS:       vdns,
		EnableUDP: true,
	})
	if err != nil {
		t.Fatalf("New Engine: %v", err)
	}
	t.Cleanup(eng.Close)

	// 1. Outbound TCP from guest over L2 ARP -> Engine -> boundary.
	targetIP, err := vdns.Resolve4("microvm.example.test")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	outConn, err := gonet.DialContextTCP(ctx, guest, tcpip.FullAddress{
		Addr: tcpip.AddrFrom4(targetIP.As4()),
		Port: 443,
	}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("guest outbound TCP over L2 TAP: %v", err)
	}
	if _, err := outConn.Write([]byte("hello-l2")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 8)
	if _, err := io.ReadFull(outConn, buf); err != nil {
		t.Fatal(err)
	}
	_ = outConn.Close()
	if string(buf) != "hello-l2" || dialedTarget != "microvm.example.test" {
		t.Fatalf("outbound L2 echo=%q target=%q", string(buf), dialedTarget)
	}

	// 2. Inbound TCP from Engine.DialGuestTCP -> L2 ARP -> guest TCP listener on :8080.
	guestLn, err := gonet.ListenTCP(guest, tcpip.FullAddress{NIC: 1, Port: 8080}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("guest ListenTCP: %v", err)
	}
	defer guestLn.Close()
	go func() {
		c, err := guestLn.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = c.Write([]byte("inbound-from-vm"))
	}()

	inConn, err := eng.DialGuestTCP(ctx, guestIP, 8080)
	if err != nil {
		t.Fatalf("Engine.DialGuestTCP: %v", err)
	}
	defer inConn.Close()
	reply, err := io.ReadAll(inConn)
	if err != nil {
		t.Fatalf("read inbound from guest: %v", err)
	}
	if string(reply) != "inbound-from-vm" {
		t.Fatalf("inbound reply = %q, want inbound-from-vm", string(reply))
	}
}

type stubDialer struct {
	onTCP func(ctx context.Context, name string, port uint16) (net.Conn, error)
}

func (s *stubDialer) DialTCP(ctx context.Context, name string, port uint16) (net.Conn, error) {
	return s.onTCP(ctx, name, port)
}

func (s *stubDialer) DialUDP(context.Context, string, uint16) (DatagramConn, error) {
	return nil, io.EOF
}
