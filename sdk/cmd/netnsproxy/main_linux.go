package main

import (
	"context"
	"flag"
	"log"
	"net"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/aojea/agents.net/sdk/pkg/netnsproxy"
	"github.com/aojea/agents.net/sdk/pkg/tun2connect"
)

func main() {
	device := flag.String("interface", "", "workload-facing veth or TAP in the current dedicated network namespace")
	boundary := flag.String("proxy", "unix:///run/agents.net/boundary.sock", "boundary Unix socket URL")
	table := flag.String("table", "agents_net", "new nftables table; retained on exit until namespace teardown")
	udp := flag.Bool("udp", false, "enable UDP tunnels; UDP DNS is always local")
	ipv6 := flag.Bool("ipv6", false, "also redirect IPv6; requires an IPv6 address on the ingress interface")
	h2 := flag.Bool("h2", false, "use HTTP/2 prior knowledge on the boundary channel")
	limit := flag.Int("max-connections", 1024, "maximum combined TCP, UDP, and DNS sessions")
	dialTimeout := flag.Duration("dial-timeout", 15*time.Second, "boundary connection setup timeout")
	idleTimeout := flag.Duration("udp-idle-timeout", 30*time.Second, "UDP session idle timeout")
	flag.Parse()
	address, err := url.Parse(*boundary)
	if err != nil || address.Scheme != "unix" || address.Path == "" || address.Host != "" {
		log.Fatal("-proxy must be unix:///absolute/path")
	}
	dial := func(ctx context.Context) (net.Conn, error) {
		var dialer net.Dialer
		return dialer.DialContext(ctx, "unix", address.Path)
	}
	var dialer tun2connect.Dialer = &tun2connect.BoundaryClient{DialBoundary: dial}
	if *h2 {
		dialer = &tun2connect.BoundaryClientH2{DialBoundary: dial}
	}
	proxy, err := netnsproxy.New(netnsproxy.Config{
		Interface: *device, Table: *table, EnableUDP: *udp, EnableIPv6: *ipv6, MaxConnections: *limit,
		Forwarder: &tun2connect.Forwarder{Dialer: dialer, DNS: tun2connect.NewVirtualDNS(),
			DialTimeout: *dialTimeout, UDPIdleTimeout: *idleTimeout},
	})
	if err != nil {
		log.Fatal(err)
	}
	defer proxy.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log.Printf("netnsproxy ready: interface=%s proxy=%s udp=%v ipv6=%v table=%s", *device, *boundary, *udp, *ipv6, *table)
	if err := proxy.Run(ctx); err != nil {
		log.Fatal(err)
	}
}
