package tun2connect

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	nicID           = 1
	maxInFlight     = 1024 // pending TCP forwarder requests
	maxDatagramSize = 65535
	dnsIdleTimeout  = 3 * time.Second
)

type Config struct {
	// Device is the guest-facing link, e.g. NewTUNDevice(fd, mtu).
	Device stack.LinkEndpoint
	// Dialer opens one boundary tunnel per authorized flow.
	Dialer Dialer
	// DNS supplies synthetic answers and the dial-time reverse lookup.
	DNS *VirtualDNS
	// EnableUDP tunnels UDP sessions via connect-udp. Off by default:
	// UDP to port 53 is always answered locally by DNS either way, and
	// everything else is silently dropped.
	EnableUDP bool
	// UDPIdleTimeout ends a UDP session with no guest traffic (default 30s).
	UDPIdleTimeout time.Duration
	// DialTimeout bounds one boundary dial (default 15s).
	DialTimeout time.Duration
}

// Engine terminates guest TCP/IP and turns each flow into one named
// tunnel dial. Flows whose destination has no virtual-DNS mapping are
// refused: an address the guest never resolved has no name to authorize.
type Engine struct {
	cfg   Config
	stack *stack.Stack
}

func New(cfg Config) (*Engine, error) {
	if cfg.Device == nil || cfg.Dialer == nil || cfg.DNS == nil {
		return nil, errors.New("tun2connect: Device, Dialer and DNS are all required")
	}
	if cfg.UDPIdleTimeout <= 0 {
		cfg.UDPIdleTimeout = 30 * time.Second
	}
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = 15 * time.Second
	}

	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	e := &Engine{cfg: cfg, stack: s}

	sack := tcpip.TCPSACKEnabled(true)
	if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &sack); err != nil {
		return nil, fmt.Errorf("tun2connect: enable SACK: %s", err)
	}
	if err := s.CreateNIC(nicID, cfg.Device); err != nil {
		return nil, fmt.Errorf("tun2connect: create NIC: %s", err)
	}
	// Promiscuous + spoofing: the NIC owns no addresses; it must accept
	// flows to any synthetic destination and answer as that destination.
	if err := s.SetPromiscuousMode(nicID, true); err != nil {
		return nil, fmt.Errorf("tun2connect: promiscuous mode: %s", err)
	}
	if err := s.SetSpoofing(nicID, true); err != nil {
		return nil, fmt.Errorf("tun2connect: spoofing: %s", err)
	}
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: nicID},
		{Destination: header.IPv6EmptySubnet, NIC: nicID},
	})

	s.SetTransportProtocolHandler(tcp.ProtocolNumber,
		tcp.NewForwarder(s, 0, maxInFlight, e.handleTCP).HandlePacket)
	s.SetTransportProtocolHandler(udp.ProtocolNumber,
		udp.NewForwarder(s, e.handleUDP).HandlePacket)
	return e, nil
}

// Close tears the netstack down; in-flight relays end with their conns.
func (e *Engine) Close() {
	e.stack.Close()
	e.stack.Wait()
}

func toNetip(a tcpip.Address) (netip.Addr, bool) {
	addr, ok := netip.AddrFromSlice(a.AsSlice())
	return addr.Unmap(), ok
}

func (e *Engine) handleTCP(r *tcp.ForwarderRequest) {
	id := r.ID()
	dst, ok := toNetip(id.LocalAddress)
	if !ok {
		r.Complete(true)
		return
	}
	name, ok := e.cfg.DNS.Reverse(dst)
	if !ok {
		r.Complete(true) // no name, never authorized: RST -> ECONNREFUSED
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), e.cfg.DialTimeout)
		defer cancel()
		// Dial before completing the guest handshake so a boundary
		// refusal surfaces as a connect() failure, not a later reset.
		upstream, err := e.cfg.Dialer.DialTCP(ctx, name, id.LocalPort)
		if err != nil {
			r.Complete(true)
			return
		}
		var wq waiter.Queue
		ep, tcpErr := r.CreateEndpoint(&wq)
		if tcpErr != nil {
			upstream.Close()
			r.Complete(true)
			return
		}
		r.Complete(false)
		relay(gonet.NewTCPConn(&wq, ep), upstream)
	}()
}

func (e *Engine) handleUDP(r *udp.ForwarderRequest) bool {
	id := r.ID()
	if id.LocalPort == 53 {
		var wq waiter.Queue
		ep, err := r.CreateEndpoint(&wq)
		if err != nil {
			return false
		}
		go e.serveDNS(gonet.NewUDPConn(&wq, ep))
		return true
	}
	// Unhandled requests get an ICMP port unreachable from the stack:
	// refusals surface to the guest immediately instead of timing out.
	if !e.cfg.EnableUDP {
		return false
	}
	dst, ok := toNetip(id.LocalAddress)
	if !ok {
		return false
	}
	name, ok := e.cfg.DNS.Reverse(dst)
	if !ok {
		return false // no name, never authorized
	}
	var wq waiter.Queue
	ep, err := r.CreateEndpoint(&wq)
	if err != nil {
		return false
	}
	guest := gonet.NewUDPConn(&wq, ep)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), e.cfg.DialTimeout)
		defer cancel()
		sess, err := e.cfg.Dialer.DialUDP(ctx, name, id.LocalPort)
		if err != nil {
			guest.Close()
			return
		}
		e.tunnelUDP(guest, sess)
	}()
	return true
}

// tunnelUDP pumps one UDP session until the guest goes idle or either
// side fails; the session's end is what delimits its audit record.
func (e *Engine) tunnelUDP(guest *gonet.UDPConn, sess DatagramConn) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, maxDatagramSize)
		for {
			guest.SetReadDeadline(time.Now().Add(e.cfg.UDPIdleTimeout))
			n, err := guest.Read(buf)
			if err != nil {
				return
			}
			if sess.WriteDatagram(buf[:n]) != nil {
				return
			}
		}
	}()
	go func() {
		for {
			p, err := sess.ReadDatagram()
			if err != nil {
				guest.Close()
				return
			}
			if _, err := guest.Write(p); err != nil {
				return
			}
		}
	}()
	<-done
	sess.Close()
	guest.Close()
}

func (e *Engine) serveDNS(conn *gonet.UDPConn) {
	defer conn.Close()
	buf := make([]byte, 1500)
	for {
		conn.SetReadDeadline(time.Now().Add(dnsIdleTimeout))
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		resp, err := e.cfg.DNS.HandleQuery(buf[:n])
		if err != nil {
			continue // unparseable query: drop, never forward
		}
		if _, err := conn.Write(resp); err != nil {
			return
		}
	}
}
