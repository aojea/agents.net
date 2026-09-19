package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/aojea/agents.net/sdk/pkg/qemuproxy"
	"github.com/aojea/agents.net/sdk/pkg/tun2connect"
)

func run() error {
	listen := flag.String("listen", "", "dedicated QEMU packet Unix socket path (must not exist)")
	proxy := flag.String("proxy", "", "dedicated boundary URL: unix:///absolute/path")
	addresses := flag.String("addresses", "10.0.2.1/24,fd00::1/64", "comma-separated gateway addresses; guest configuration is static")
	mac := flag.String("mac", "02:00:00:00:00:01", "gateway MAC address")
	limit := flag.Int("max-connections", 1024, "maximum combined TCP, UDP and DNS sessions")
	udp := flag.Bool("udp", false, "enable CONNECT-UDP; UDP DNS is always local")
	flag.Parse()
	boundary, err := url.Parse(*proxy)
	if err != nil || boundary.Scheme != "unix" || boundary.Host != "" || !filepath.IsAbs(boundary.Path) || boundary.RawQuery != "" || boundary.Fragment != "" || boundary.User != nil {
		return fmt.Errorf("-proxy must be unix:///absolute/path")
	}
	if !filepath.IsAbs(*listen) || *listen == boundary.Path || *limit <= 0 {
		return fmt.Errorf("distinct absolute -listen path and positive -max-connections required")
	}
	hardware, err := net.ParseMAC(*mac)
	if err != nil || len(hardware) != 6 || hardware[0]&1 != 0 {
		return fmt.Errorf("-mac must be a unicast Ethernet MAC")
	}
	var prefixes []netip.Prefix
	for _, value := range strings.Split(*addresses, ",") {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix.Addr().Is4In6() || !prefix.Addr().IsGlobalUnicast() {
			return fmt.Errorf("invalid gateway address %q", value)
		}
		prefixes = append(prefixes, prefix)
	}
	syscall.Umask(0077)
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: *listen, Net: "unix"})
	if err != nil {
		return err
	}
	defer listener.Close()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { listener.Close() })
	defer stop()
	log.Printf("qemuproxy ready: packets=%s boundary=%s mtu=%d", *listen, boundary.Path, qemuproxy.MTU)
	conn, err := listener.AcceptUnix()
	if err != nil {
		return err
	}
	listener.Close()
	log.Print("QEMU packet channel connected; reconnect is disabled")
	return qemuproxy.Run(ctx, conn, qemuproxy.Config{
		MAC: hardware, Addresses: prefixes, MaxConnections: *limit, EnableUDP: *udp,
		Dialer: &tun2connect.BoundaryClient{DialBoundary: func(ctx context.Context) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, "unix", boundary.Path)
		}},
	})
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
