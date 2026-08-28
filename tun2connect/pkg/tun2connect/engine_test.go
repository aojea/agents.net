package tun2connect

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// recordingDialer answers TCP dials with an echoing pipe and UDP dials
// with an echoing datagram session, recording every requested name.
type recordingDialer struct {
	mu     sync.Mutex
	dials  []string
	refuse bool
}

func (d *recordingDialer) record(kind, name string, port uint16) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.dials = append(d.dials, fmt.Sprintf("%s/%s:%d", kind, name, port))
	return !d.refuse
}

func (d *recordingDialer) DialTCP(ctx context.Context, name string, port uint16) (net.Conn, error) {
	if !d.record("tcp", name, port) {
		return nil, &DialError{StatusCode: 403, Status: "403 Forbidden"}
	}
	c, s := net.Pipe()
	go func() {
		io.Copy(s, s)
		s.Close()
	}()
	return c, nil
}

type echoDatagramConn struct {
	ch     chan []byte
	closed chan struct{}
	once   sync.Once
}

func (c *echoDatagramConn) WriteDatagram(p []byte) error {
	cp := append([]byte(nil), p...)
	select {
	case c.ch <- cp:
		return nil
	case <-c.closed:
		return net.ErrClosed
	}
}

func (c *echoDatagramConn) ReadDatagram() ([]byte, error) {
	select {
	case p := <-c.ch:
		return p, nil
	case <-c.closed:
		return nil, net.ErrClosed
	}
}

func (c *echoDatagramConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func (d *recordingDialer) DialUDP(ctx context.Context, name string, port uint16) (DatagramConn, error) {
	if !d.record("udp", name, port) {
		return nil, &DialError{StatusCode: 403, Status: "403 Forbidden"}
	}
	return &echoDatagramConn{ch: make(chan []byte, 16), closed: make(chan struct{})}, nil
}

// pump shuttles packets between the two halves of the virtual wire.
func pump(ctx context.Context, src, dst *channel.Endpoint) {
	for {
		pkt := src.ReadContext(ctx)
		if pkt == nil {
			return
		}
		proto := pkt.NetworkProtocolNumber
		view := stack.PayloadSince(pkt.NetworkHeader())
		pkt.DecRef()
		if view == nil {
			continue
		}
		np := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(view.AsSlice()),
		})
		dst.InjectInbound(proto, np)
		np.DecRef()
	}
}

type testNet struct {
	eng    *Engine
	dns    *VirtualDNS
	dialer *recordingDialer
	guest  *stack.Stack
}

func newTestNet(t *testing.T) *testNet {
	t.Helper()
	engEP := channel.New(512, 1500, "")
	guestEP := channel.New(512, 1500, "")

	dns := NewVirtualDNS()
	dialer := &recordingDialer{}
	eng, err := New(Config{
		Device:         engEP,
		Dialer:         dialer,
		DNS:            dns,
		EnableUDP:      true,
		DialTimeout:    5 * time.Second,
		UDPIdleTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}

	guest := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	if err := guest.CreateNIC(1, guestEP); err != nil {
		t.Fatalf("guest NIC: %s", err)
	}
	if err := guest.AddProtocolAddress(1, tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address: tcpip.AddrFrom4([4]byte{10, 0, 0, 2}), PrefixLen: 24,
		},
	}, stack.AddressProperties{}); err != nil {
		t.Fatalf("guest address: %s", err)
	}
	guest.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})

	ctx, cancel := context.WithCancel(context.Background())
	go pump(ctx, guestEP, engEP)
	go pump(ctx, engEP, guestEP)
	t.Cleanup(func() {
		cancel()
		eng.Close()
		guest.Close()
		guest.Wait()
	})
	return &testNet{eng: eng, dns: dns, dialer: dialer, guest: guest}
}

func fullAddr(a netip.Addr, port uint16) tcpip.FullAddress {
	return tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(a.AsSlice()), Port: port}
}

func TestEngineTCPEchoCarriesName(t *testing.T) {
	n := newTestNet(t)
	addr, err := n.dns.Resolve4("api.example.test")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := gonet.DialContextTCP(ctx, n.guest, fullAddr(addr, 443), ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "ping" {
		t.Fatalf("echo = %q", buf)
	}
	n.dialer.mu.Lock()
	defer n.dialer.mu.Unlock()
	if len(n.dialer.dials) != 1 || n.dialer.dials[0] != "tcp/api.example.test:443" {
		t.Fatalf("boundary saw %v, want the NAME api.example.test", n.dialer.dials)
	}
}

func TestEngineRefusesUnresolvedDestination(t *testing.T) {
	n := newTestNet(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// 100.64.9.9 is in the synthetic range but was never handed out.
	_, err := gonet.DialContextTCP(ctx, n.guest,
		fullAddr(netip.MustParseAddr("100.64.9.9"), 443), ipv4.ProtocolNumber)
	if err == nil {
		t.Fatal("flow to an address the guest never resolved must be refused")
	}
	n.dialer.mu.Lock()
	defer n.dialer.mu.Unlock()
	if len(n.dialer.dials) != 0 {
		t.Fatalf("boundary must never be dialed without a name, saw %v", n.dialer.dials)
	}
}

func TestEngineBoundaryRefusalBecomesConnectError(t *testing.T) {
	n := newTestNet(t)
	n.dialer.refuse = true
	addr, err := n.dns.Resolve4("evil.example.test")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := gonet.DialContextTCP(ctx, n.guest, fullAddr(addr, 443), ipv4.ProtocolNumber); err == nil {
		t.Fatal("a 403 from the boundary must surface as a failed connect")
	}
}

func TestEngineUDPEchoCarriesName(t *testing.T) {
	n := newTestNet(t)
	addr, err := n.dns.Resolve4("stun.example.test")
	if err != nil {
		t.Fatal(err)
	}
	raddr := fullAddr(addr, 3478)
	conn, err := gonet.DialUDP(n.guest, nil, &raddr, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("probe")); err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 64)
	nn, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:nn]) != "probe" {
		t.Fatalf("echo = %q", buf[:nn])
	}
	n.dialer.mu.Lock()
	defer n.dialer.mu.Unlock()
	if len(n.dialer.dials) != 1 || n.dialer.dials[0] != "udp/stun.example.test:3478" {
		t.Fatalf("boundary saw %v, want the NAME stun.example.test", n.dialer.dials)
	}
}

func TestEngineAnswersDNSLocally(t *testing.T) {
	n := newTestNet(t)
	// Any destination works: port 53 is always intercepted, never tunneled.
	raddr := fullAddr(netip.MustParseAddr("10.0.0.1"), 53)
	conn, err := gonet.DialUDP(n.guest, nil, &raddr, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write(buildQuery(t, "model.example.", dnsmessage.TypeA)); err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 512)
	nn, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	var p dnsmessage.Parser
	if _, err := p.Start(buf[:nn]); err != nil {
		t.Fatal(err)
	}
	if err := p.SkipAllQuestions(); err != nil {
		t.Fatal(err)
	}
	answers, err := p.AllAnswers()
	if err != nil {
		t.Fatal(err)
	}
	if len(answers) != 1 {
		t.Fatalf("want 1 answer, got %d", len(answers))
	}
	got := netip.AddrFrom4(answers[0].Body.(*dnsmessage.AResource).A)
	if name, ok := n.dns.Reverse(got); !ok || name != "model.example" {
		t.Fatalf("virtual answer %v does not reverse to model.example (got %q, %v)", got, name, ok)
	}
	if len(n.dialer.dials) != 0 {
		t.Fatalf("DNS must never reach the boundary, saw %v", n.dialer.dials)
	}
}
