package netnsproxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/google/nftables"
	"golang.org/x/sys/unix"

	"github.com/aojea/agents.net/sdk/pkg/tun2connect"
)

type Config struct {
	Interface      string
	Table          string
	Forwarder      *tun2connect.Forwarder
	EnableUDP      bool
	EnableIPv6     bool
	MaxConnections int
}

type Proxy struct {
	cfg       Config
	ctx       context.Context
	cancel    context.CancelFunc
	tcp       []*net.TCPListener
	udp       []*net.UDPConn
	slots     chan struct{}
	closeOnce sync.Once
	running   atomic.Bool
}

func New(cfg Config) (*Proxy, error) {
	if cfg.Forwarder == nil || cfg.Forwarder.Dialer == nil || cfg.Forwarder.DNS == nil {
		return nil, errors.New("netnsproxy: Forwarder, Dialer and DNS are required")
	}
	if cfg.Interface == "" {
		return nil, errors.New("netnsproxy: ingress interface is required")
	}
	link, err := net.InterfaceByName(cfg.Interface)
	if err != nil {
		return nil, err
	}
	if link.Flags&net.FlagLoopback != 0 || link.Flags&net.FlagUp == 0 {
		return nil, errors.New("netnsproxy: ingress interface must be up and not loopback")
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, candidate := range interfaces {
		if candidate.Index != link.Index && candidate.Flags&net.FlagLoopback == 0 {
			return nil, fmt.Errorf("netnsproxy: unexpected interface %q; use a dedicated namespace", candidate.Name)
		}
	}
	if cfg.Table == "" {
		cfg.Table = "agents_net"
	}
	if cfg.MaxConnections <= 0 {
		cfg.MaxConnections = 1024
	}
	forwarder := *cfg.Forwarder
	cfg.Forwarder = &forwarder
	ctx, cancel := context.WithCancel(context.Background())
	proxy := &Proxy{cfg: cfg, ctx: ctx, cancel: cancel, slots: make(chan struct{}, cfg.MaxConnections)}
	families := []string{"4"}
	if cfg.EnableIPv6 {
		families = append(families, "6")
	}
	var listeners []ports
	for _, family := range families {
		address, protocol := "0.0.0.0:0", byte(unix.NFPROTO_IPV4)
		if family == "6" {
			address, protocol = "[::]:0", unix.NFPROTO_IPV6
		}
		listener, err := net.Listen("tcp"+family, address)
		if err != nil {
			proxy.Close()
			return nil, err
		}
		proxy.tcp = append(proxy.tcp, listener.(*net.TCPListener))
		config := net.ListenConfig{Control: udpOptions(family == "6")}
		packetListener, err := config.ListenPacket(ctx, "udp"+family, address)
		if err != nil {
			proxy.Close()
			return nil, err
		}
		proxy.udp = append(proxy.udp, packetListener.(*net.UDPConn))
		listeners = append(listeners, ports{
			family: protocol,
			tcp:    uint16(listener.Addr().(*net.TCPAddr).Port),
			udp:    uint16(packetListener.LocalAddr().(*net.UDPAddr).Port),
		})
	}
	conn, err := nftables.New(nftables.AsLasting())
	if err != nil {
		proxy.Close()
		return nil, err
	}
	defer conn.CloseLasting()
	table := conn.CreateTable(&nftables.Table{Name: cfg.Table, Family: nftables.TableFamilyINet})
	redirectRules(conn, table, link.Index, listeners, cfg.EnableUDP)
	if err := conn.Flush(); err != nil {
		proxy.Close()
		return nil, fmt.Errorf("netnsproxy: install nftables table %s: %w", cfg.Table, err)
	}
	if err := installRoutes(cfg.EnableIPv6); err != nil {
		conn.DelTable(table)
		cleanupErr := conn.Flush()
		proxy.Close()
		return nil, errors.Join(fmt.Errorf("netnsproxy: install UDP policy routes: %w", err), cleanupErr)
	}
	return proxy, nil
}

func (p *Proxy) Run(ctx context.Context) error {
	if !p.running.CompareAndSwap(false, true) {
		return errors.New("netnsproxy: Run called more than once")
	}
	stop := context.AfterFunc(ctx, func() { p.Close() })
	defer stop()
	defer p.Close()
	results := make(chan error, len(p.tcp)+len(p.udp))
	for _, listener := range p.tcp {
		go func() { results <- p.serveTCP(listener) }()
	}
	for _, listener := range p.udp {
		go func() { results <- p.serveUDP(listener) }()
	}
	var result error
	for range len(p.tcp) + len(p.udp) {
		err := <-results
		if err != nil && !errors.Is(err, net.ErrClosed) {
			result = errors.Join(result, err)
		}
		p.Close()
	}
	return result
}

func (p *Proxy) Close() error {
	p.closeOnce.Do(func() {
		p.cancel()
		for _, listener := range p.tcp {
			listener.Close()
		}
		for _, listener := range p.udp {
			listener.Close()
		}
	})
	return nil
}

func (p *Proxy) serveTCP(listener *net.TCPListener) error {
	var workers sync.WaitGroup
	defer workers.Wait()
	defer p.Close()
	for {
		guest, err := listener.AcceptTCP()
		if err != nil {
			return err
		}
		select {
		case p.slots <- struct{}{}:
		default:
			guest.SetLinger(0)
			guest.Close()
			continue
		}
		workers.Add(1)
		go func() {
			defer workers.Done()
			defer func() { <-p.slots }()
			defer guest.Close()
			stop := context.AfterFunc(p.ctx, func() { guest.Close() })
			defer stop()
			destination, err := originalDestination(guest)
			if err != nil {
				guest.SetLinger(0)
				return
			}
			upstream, err := p.cfg.Forwarder.DialTCP(p.ctx, destination)
			if err != nil {
				guest.SetLinger(0)
				return
			}
			p.cfg.Forwarder.RelayTCP(p.ctx, guest, upstream)
		}()
	}
}

type flowKey struct {
	peer        netip.AddrPort
	destination netip.AddrPort
}

func (p *Proxy) serveUDP(listener *net.UDPConn) error {
	var workers sync.WaitGroup
	defer workers.Wait()
	defer p.Close()
	var mu sync.Mutex
	flows := make(map[flowKey]*packetFlow)
	packet, control := make([]byte, 65535), make([]byte, 256)
	for {
		count, controlCount, flags, peer, err := listener.ReadMsgUDP(packet, control)
		if err != nil {
			return err
		}
		if flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 {
			continue
		}
		destination, err := packetDestination(control[:controlCount])
		if err != nil {
			continue
		}
		if destination.Port() != 53 && !p.cfg.EnableUDP {
			continue
		}
		key := flowKey{peer: peer.AddrPort(), destination: destination}
		mu.Lock()
		flow := flows[key]
		if flow == nil {
			select {
			case p.slots <- struct{}{}:
			default:
				mu.Unlock()
				continue
			}
			socket, err := replySocket(peer, destination)
			if err != nil {
				<-p.slots
				mu.Unlock()
				continue
			}
			flow = &packetFlow{socket: socket, peer: peer,
				packets: make(chan []byte, 16), done: make(chan struct{}), changed: make(chan struct{})}
			flows[key] = flow
			workers.Add(2)
			go func() {
				defer workers.Done()
				defer flow.Close()
				buffer := make([]byte, 65535)
				for {
					count, err := socket.Read(buffer)
					if err != nil {
						return
					}
					select {
					case flow.packets <- append([]byte(nil), buffer[:count]...):
					case <-flow.done:
						return
					default:
					}
				}
			}()
			go func() {
				defer workers.Done()
				defer func() { <-p.slots }()
				defer func() {
					flow.Close()
					mu.Lock()
					delete(flows, key)
					mu.Unlock()
				}()
				if destination.Port() == 53 {
					p.cfg.Forwarder.ServeDNS(p.ctx, flow)
					return
				}
				session, err := p.cfg.Forwarder.DialUDP(p.ctx, destination)
				if err == nil {
					p.cfg.Forwarder.RelayUDP(p.ctx, flow, session)
				}
			}()
		}
		mu.Unlock()
		select {
		case flow.packets <- append([]byte(nil), packet[:count]...):
		case <-flow.done:
		default:
		}
	}
}
