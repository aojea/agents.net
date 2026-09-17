package qemuproxy

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"time"

	"github.com/aojea/agents.net/sdk/pkg/tun2connect"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/link/ethernet"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const (
	MTU          = 1500
	maxFrameSize = MTU + header.EthernetMinimumSize
	frameTimeout = 15 * time.Second
)

type Config struct {
	MAC            net.HardwareAddr
	Addresses      []netip.Prefix
	Dialer         tun2connect.Dialer
	EnableUDP      bool
	MaxConnections int
}

func Run(ctx context.Context, conn net.Conn, cfg Config) error {
	defer conn.Close()
	if len(cfg.MAC) != 6 || cfg.MAC[0]&1 != 0 || len(cfg.Addresses) == 0 {
		return errors.New("qemuproxy: unicast Ethernet MAC and gateway addresses required")
	}
	endpoint := channel.New(256, maxFrameSize, tcpip.LinkAddress(cfg.MAC))
	defer endpoint.Close()
	engine, err := tun2connect.New(tun2connect.Config{
		Device: ethernet.New(endpoint), Addresses: cfg.Addresses,
		DNS: tun2connect.NewVirtualDNS(), Dialer: cfg.Dialer,
		EnableUDP: cfg.EnableUDP, MaxConnections: cfg.MaxConnections,
	})
	if err != nil {
		return err
	}
	defer engine.Close()
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(runCtx, func() { conn.Close() })
	defer stop()
	results := make(chan error, 2)
	go func() {
		for {
			frame, err := readFrame(conn)
			if err != nil {
				results <- err
				return
			}
			eth := header.Ethernet(frame)
			switch eth.Type() {
			case header.ARPProtocolNumber, header.IPv4ProtocolNumber, header.IPv6ProtocolNumber:
			default:
				continue
			}
			destination := eth.DestinationAddress()
			if destination != tcpip.LinkAddress(cfg.MAC) && destination != header.EthernetBroadcastAddress && !header.IsMulticastEthernetAddress(destination) {
				continue
			}
			packet := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(frame)})
			endpoint.InjectInbound(eth.Type(), packet)
			packet.DecRef()
		}
	}()
	go func() {
		for {
			packet := endpoint.ReadContext(runCtx)
			if packet == nil {
				results <- runCtx.Err()
				return
			}
			view := packet.ToView()
			packet.DecRef()
			err := writeFrame(conn, view.AsSlice())
			view.Release()
			if err != nil {
				results <- err
				return
			}
		}
	}()
	err = <-results
	cancel()
	conn.Close()
	<-results
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

func readFrame(conn net.Conn) ([]byte, error) {
	var prefix [4]byte
	conn.SetReadDeadline(time.Time{})
	if _, err := io.ReadFull(conn, prefix[:1]); err != nil {
		return nil, err
	}
	conn.SetReadDeadline(time.Now().Add(frameTimeout))
	if _, err := io.ReadFull(conn, prefix[1:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(prefix[:])
	if length < header.EthernetMinimumSize || length > maxFrameSize {
		return nil, fmt.Errorf("qemuproxy: invalid Ethernet frame length %d", length)
	}
	frame := make([]byte, int(length))
	_, err := io.ReadFull(conn, frame)
	return frame, err
}

func writeFrame(conn net.Conn, frame []byte) error {
	if len(frame) < header.EthernetMinimumSize || len(frame) > maxFrameSize {
		return fmt.Errorf("qemuproxy: invalid outbound frame length %d", len(frame))
	}
	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], uint32(len(frame)))
	conn.SetWriteDeadline(time.Now().Add(frameTimeout))
	parts := net.Buffers{prefix[:], frame}
	_, err := parts.WriteTo(conn)
	return err
}
