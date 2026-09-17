package tun2connect

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	nicID       = 1
	maxInFlight = 1024 // pending TCP forwarder requests
)

type Config struct {
	// Device is the guest-facing link, e.g. NewTUNDevice(fd, mtu).
	Device         stack.LinkEndpoint
	Addresses      []netip.Prefix
	MaxConnections int
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

// Engine terminates guest TCP/IP and tunnels each flow to the boundary,
// preserving a DNS name when known and otherwise using the destination IP.
type Engine struct {
	cfg       Config
	stack     *stack.Stack
	forwarder *Forwarder
	ctx       context.Context
	cancel    context.CancelFunc
	mu        sync.Mutex
	closed    bool
	workers   sync.WaitGroup
	closeOnce sync.Once
	sessions  chan struct{}
}

func New(cfg Config) (*Engine, error) {
	if cfg.Device == nil || cfg.Dialer == nil || cfg.DNS == nil {
		return nil, errors.New("tun2connect: Device, Dialer and DNS are all required")
	}
	for _, address := range cfg.Addresses {
		if !address.IsValid() || address.Addr().Is4In6() {
			return nil, fmt.Errorf("tun2connect: invalid interface address %s", address)
		}
	}
	if cfg.UDPIdleTimeout <= 0 {
		cfg.UDPIdleTimeout = 30 * time.Second
	}
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = 15 * time.Second
	}
	if cfg.MaxConnections <= 0 {
		cfg.MaxConnections = 1024
	}

	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{arp.NewProtocol, ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	e := &Engine{cfg: cfg, stack: s, forwarder: &Forwarder{
		Dialer:         cfg.Dialer,
		DNS:            cfg.DNS,
		DialTimeout:    cfg.DialTimeout,
		UDPIdleTimeout: cfg.UDPIdleTimeout,
	}}
	e.ctx, e.cancel = context.WithCancel(context.Background())
	e.sessions = make(chan struct{}, cfg.MaxConnections)
	initialized := false
	defer func() {
		if !initialized {
			e.cancel()
			s.Close()
			s.Wait()
		}
	}()

	sack := tcpip.TCPSACKEnabled(true)
	if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &sack); err != nil {
		return nil, fmt.Errorf("tun2connect: enable SACK: %s", err)
	}
	if err := s.CreateNIC(nicID, cfg.Device); err != nil {
		return nil, fmt.Errorf("tun2connect: create NIC: %s", err)
	}
	for _, address := range cfg.Addresses {
		protocol := ipv6.ProtocolNumber
		if address.Addr().Is4() {
			protocol = ipv4.ProtocolNumber
		}
		if err := s.AddProtocolAddress(nicID, tcpip.ProtocolAddress{
			Protocol: protocol,
			AddressWithPrefix: tcpip.AddressWithPrefix{
				Address: tcpip.AddrFromSlice(address.Addr().AsSlice()), PrefixLen: address.Bits(),
			},
		}, stack.AddressProperties{}); err != nil {
			return nil, fmt.Errorf("tun2connect: add interface address: %s", err)
		}
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
	initialized = true
	return e, nil
}

// Close tears the netstack down; in-flight relays end with their conns.
func (e *Engine) Close() {
	e.closeOnce.Do(func() {
		e.mu.Lock()
		e.closed = true
		e.mu.Unlock()
		e.cancel()
		e.workers.Wait()
		e.stack.Close()
		e.stack.Wait()
	})
}

func (e *Engine) acquire() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return false
	}
	select {
	case e.sessions <- struct{}{}:
		e.workers.Add(1)
		return true
	default:
		return false
	}
}

func (e *Engine) release() {
	<-e.sessions
	e.workers.Done()
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
	if !e.acquire() {
		r.Complete(true)
		return
	}
	go func() {
		defer e.release()
		ctx, cancel := context.WithTimeout(e.ctx, e.cfg.DialTimeout)
		defer cancel()
		// Dial before completing the guest handshake so a boundary
		// refusal surfaces as a connect() failure, not a later reset.
		upstream, err := e.forwarder.DialTCP(ctx, netip.AddrPortFrom(dst, id.LocalPort))
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
		e.forwarder.RelayTCP(e.ctx, gonet.NewTCPConn(&wq, ep), upstream)
	}()
}

func (e *Engine) handleUDP(r *udp.ForwarderRequest) bool {
	id := r.ID()
	if !e.acquire() {
		return false
	}
	if id.LocalPort == 53 {
		var wq waiter.Queue
		ep, err := r.CreateEndpoint(&wq)
		if err != nil {
			e.release()
			return false
		}
		go func() {
			defer e.release()
			e.forwarder.ServeDNS(e.ctx, gonet.NewUDPConn(&wq, ep))
		}()
		return true
	}
	// Unhandled requests get an ICMP port unreachable from the stack:
	// refusals surface to the guest immediately instead of timing out.
	if !e.cfg.EnableUDP {
		e.release()
		return false
	}
	dst, ok := toNetip(id.LocalAddress)
	if !ok {
		e.release()
		return false
	}
	var wq waiter.Queue
	ep, err := r.CreateEndpoint(&wq)
	if err != nil {
		e.release()
		return false
	}
	guest := gonet.NewUDPConn(&wq, ep)
	go func() {
		defer e.release()
		ctx, cancel := context.WithTimeout(e.ctx, e.cfg.DialTimeout)
		defer cancel()
		sess, err := e.forwarder.DialUDP(ctx, netip.AddrPortFrom(dst, id.LocalPort))
		if err != nil {
			guest.Close()
			return
		}
		e.forwarder.RelayUDP(e.ctx, guest, sess)
	}()
	return true
}
