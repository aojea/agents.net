// Command tun2connect runs the guest side of the boundary: it opens a
// TUN device, terminates TCP/IP in userspace, answers DNS with synthetic
// addresses, and carries supported flows to the boundary as HTTP CONNECT
// (TCP) or connect-udp (UDP), using hostnames or literal IP destinations.
//
// Demo (as root, with connect-proxy running on the other end):
//
//	tun2connect -device tun2c0 -proxy unix:///tmp/boundary.sock -udp
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/mdlayher/vsock"
	"golang.org/x/sys/unix"

	"github.com/aojea/agents.net/sdk/pkg/tun2connect"
)

func openTUN(name string, mtu uint32) (int, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR, 0)
	if err != nil {
		return -1, fmt.Errorf("open /dev/net/tun: %w (need root or CAP_NET_ADMIN)", err)
	}
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		unix.Close(fd)
		return -1, err
	}
	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		unix.Close(fd)
		return -1, fmt.Errorf("TUNSETIFF %s: %w", name, err)
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

// parseVSOCK splits "cid:port". In a Firecracker guest the boundary is
// CID 2 (the host); Firecracker delivers the connection to the host Unix
// socket "<uds_path>_<port>", which the boundary listens on directly.
func parseVSOCK(addr string) (cid, port uint32, err error) {
	rawCID, rawPort, found := strings.Cut(addr, ":")
	if !found {
		return 0, 0, fmt.Errorf("invalid vsock address %q (want cid:port)", addr)
	}
	parsedCID, err := strconv.ParseUint(rawCID, 10, 32)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid vsock cid %q: %w", rawCID, err)
	}
	parsedPort, err := strconv.ParseUint(rawPort, 10, 32)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid vsock port %q: %w", rawPort, err)
	}
	return uint32(parsedCID), uint32(parsedPort), nil
}

// dialVSOCK opens one AF_VSOCK stream. The library returns a pollable
// net.Conn: wrapping a blocking descriptor in os.NewFile silently loses
// deadlines and Close cannot interrupt a blocked Read.
func dialVSOCK(addr string) (net.Conn, error) {
	cid, port, err := parseVSOCK(addr)
	if err != nil {
		return nil, err
	}
	return vsock.Dial(cid, port, nil)
}

// boundaryDialer returns a per-flow dial function for unix://, tcp://, or vsock://.
func boundaryDialer(proxy string) (func(ctx context.Context) (net.Conn, error), error) {
	u, err := url.Parse(proxy)
	if err != nil {
		return nil, err
	}
	switch u.Scheme {
	case "unix":
		network, addr := "unix", u.Path
		var d net.Dialer
		return func(ctx context.Context) (net.Conn, error) {
			return d.DialContext(ctx, network, addr)
		}, nil
	case "tcp":
		network, addr := "tcp", u.Host
		var d net.Dialer
		return func(ctx context.Context) (net.Conn, error) {
			return d.DialContext(ctx, network, addr)
		}, nil
	case "vsock":
		addr := u.Host
		if _, _, err := parseVSOCK(addr); err != nil {
			return nil, err
		}
		return func(ctx context.Context) (net.Conn, error) {
			return dialVSOCK(addr)
		}, nil
	default:
		return nil, fmt.Errorf("unsupported proxy scheme %q (want unix://, tcp://, or vsock://)", u.Scheme)
	}
}

func main() {
	// Launcher mode: build the TUN, become the agent's supervisor, and
	// exit with its status. Daemon mode (below) only runs the engine.
	if len(os.Args) > 1 && os.Args[1] == "run" {
		runLauncher(os.Args[2:])
		return
	}

	device := flag.String("device", "tun2c0", "TUN device name to create")
	mtu := flag.Uint("mtu", 1500, "TUN MTU")
	proxy := flag.String("proxy", "unix:///tmp/boundary.sock", "boundary address (unix:///path or tcp://host:port)")
	udp := flag.Bool("udp", false, "tunnel UDP sessions via connect-udp (DNS is always answered locally)")
	sandboxID := flag.String("sandbox-id", "", "value for the Sandbox-Id header on every tunnel request")
	flag.Parse()

	dial, err := boundaryDialer(*proxy)
	if err != nil {
		log.Fatal(err)
	}
	fd, err := openTUN(*device, uint32(*mtu))
	if err != nil {
		log.Fatal(err)
	}
	dev, err := tun2connect.NewTUNDevice(fd, uint32(*mtu))
	if err != nil {
		log.Fatalf("link endpoint: %v", err)
	}
	client := &tun2connect.BoundaryClient{DialBoundary: dial}
	if *sandboxID != "" {
		client.Header = map[string][]string{"Sandbox-Id": {*sandboxID}}
	}
	eng, err := tun2connect.New(tun2connect.Config{
		Device:    dev,
		Dialer:    client,
		DNS:       tun2connect.NewVirtualDNS(),
		EnableUDP: *udp,
	})
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("engine up: device=%s proxy=%s udp=%v", *device, *proxy, *udp)
	fmt.Printf(`route the synthetic pools through the device:

  sudo ip link set %[1]s up
  sudo ip addr add 10.255.255.2/32 dev %[1]s
  sudo ip route add 100.64.0.0/10 dev %[1]s src 10.255.255.2
  sudo ip -6 route add 100::/64 dev %[1]s

then point DNS at the virtual resolver (any pool address works: the
engine answers port 53 wherever the query is sent):

  echo "nameserver %[2]s" | sudo tee /etc/resolv.conf

No default route here: this mode runs on a normal host that still needs
its own network. Only the sandbox launcher (run mode) makes the device
the only way out.

`, *device, resolverAddr)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	eng.Close()
}
