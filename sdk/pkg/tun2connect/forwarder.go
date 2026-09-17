package tun2connect

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"
)

const (
	maxDatagramSize = 65535
	dnsIdleTimeout  = 3 * time.Second
)

var ErrInvalidDestination = errors.New("tun2connect: invalid destination")

type Forwarder struct {
	Dialer         Dialer
	DNS            *VirtualDNS
	DialTimeout    time.Duration
	UDPIdleTimeout time.Duration
}

func (f *Forwarder) dialContext(ctx context.Context) (context.Context, context.CancelFunc) {
	timeout := f.DialTimeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	return context.WithTimeout(ctx, timeout)
}

func (f *Forwarder) targetHost(destination netip.AddrPort) (string, error) {
	if !destination.IsValid() || destination.Port() == 0 {
		return "", ErrInvalidDestination
	}
	address := destination.Addr().Unmap()
	if name, ok := f.DNS.Reverse(address); ok {
		return name, nil
	}
	return address.String(), nil
}

func (f *Forwarder) DialTCP(ctx context.Context, destination netip.AddrPort) (net.Conn, error) {
	host, err := f.targetHost(destination)
	if err != nil {
		return nil, err
	}
	ctx, cancel := f.dialContext(ctx)
	defer cancel()
	return f.Dialer.DialTCP(ctx, host, destination.Port())
}

func (f *Forwarder) DialUDP(ctx context.Context, destination netip.AddrPort) (DatagramConn, error) {
	host, err := f.targetHost(destination)
	if err != nil {
		return nil, err
	}
	ctx, cancel := f.dialContext(ctx)
	defer cancel()
	return f.Dialer.DialUDP(ctx, host, destination.Port())
}

func (f *Forwarder) RelayTCP(ctx context.Context, guest, upstream net.Conn) {
	stop := context.AfterFunc(ctx, func() {
		guest.Close()
		upstream.Close()
	})
	defer stop()
	relay(guest, upstream)
}

func (f *Forwarder) RelayUDP(ctx context.Context, guest net.Conn, session DatagramConn) {
	stop := context.AfterFunc(ctx, func() {
		guest.Close()
		session.Close()
	})
	defer stop()
	idleTimeout := f.UDPIdleTimeout
	if idleTimeout <= 0 {
		idleTimeout = 30 * time.Second
	}
	var workers sync.WaitGroup
	workers.Add(2)
	go func() {
		defer workers.Done()
		defer guest.Close()
		defer session.Close()
		buf := make([]byte, maxDatagramSize)
		for {
			guest.SetReadDeadline(time.Now().Add(idleTimeout))
			count, err := guest.Read(buf)
			if err != nil || session.WriteDatagram(buf[:count]) != nil {
				return
			}
		}
	}()
	go func() {
		defer workers.Done()
		defer guest.Close()
		defer session.Close()
		for {
			packet, err := session.ReadDatagram()
			if err != nil {
				return
			}
			if _, err := guest.Write(packet); err != nil {
				return
			}
		}
	}()
	workers.Wait()
}

func (f *Forwarder) ServeDNS(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	buf := make([]byte, 1500)
	for {
		conn.SetReadDeadline(time.Now().Add(dnsIdleTimeout))
		count, err := conn.Read(buf)
		if err != nil {
			return
		}
		response, err := f.DNS.HandleQuery(buf[:count])
		if err != nil {
			continue
		}
		if _, err := conn.Write(response); err != nil {
			return
		}
	}
}
