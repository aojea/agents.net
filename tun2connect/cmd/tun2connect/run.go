// Launcher mode: `tun2connect run <boundary-socket> <cmd> [args...]`
// builds the sandbox's only route (a TUN terminated in userspace, every
// flow leaving as a named HTTP CONNECT tunnel on the boundary socket),
// then runs the agent as its child with the PID 1 duties: reap orphans,
// forward signals, exit with the agent's status.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/aojea/agents.net/tun2connect/pkg/tun2connect"
)

// Guest addresses sit at the TOP of the synthetic pools: VirtualDNS hands
// out addresses from the bottom up, so these can never collide with an
// invented answer. The /10 and /64 prefix lengths make the kernel install
// the connected routes that cover every synthetic address, and the
// resolver needs no route of its own -- any pool address works, because
// the engine answers port 53 locally wherever the query is sent. The
// device is also made the default route; see configureTUN for why.
const (
	guestAddr4     = "100.127.255.254"
	pool4PrefixLen = 10
	resolverAddr   = "100.127.255.253"
	guestAddr6     = "100::ffff:ffff:ffff:fffe"
	pool6PrefixLen = 64
)

func runUsage(fs *flag.FlagSet) func() {
	return func() {
		fmt.Fprintf(os.Stderr, `Usage: tun2connect run [flags] <boundary-socket> <command> [args...]

Runs <command> in a sandbox whose only network path is a TUN device
terminated in userspace; every flow reaches the boundary socket as a
named HTTP CONNECT tunnel. Flags stop at the first positional argument:
everything after the boundary socket belongs to the command.

The boundary socket is a Unix socket path (or unix:///path, tcp://host:port).

Flags:
`)
		fs.PrintDefaults()
	}
}

func runLauncher(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	device := fs.String("device", "tun0", "TUN device name to create")
	mtu := fs.Uint("mtu", 1500, "TUN MTU")
	udp := fs.Bool("udp", false, "tunnel UDP sessions via connect-udp (DNS is always answered locally)")
	ingress := fs.String("ingress-socket", "", "serve the ingress handshake (CONNECT <port> -> OK) on this Unix socket")
	sandboxID := fs.String("sandbox-id", "", "value for the Sandbox-Id header on every tunnel request")
	fs.Usage = runUsage(fs)
	fs.Parse(args)
	rest := fs.Args()
	if len(rest) < 2 {
		fs.Usage()
		os.Exit(2)
	}
	boundary, argv := rest[0], rest[1:]
	if !strings.Contains(boundary, "://") {
		boundary = "unix://" + boundary
	}

	// Refuse to start if the namespace has any interface besides loopback:
	// a half-configured sandbox must be a startup error, not a second route.
	ifaces, err := net.Interfaces()
	if err != nil {
		log.Fatalf("listing interfaces: %v", err)
	}
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagLoopback != 0 || ifc.Name == *device {
			continue
		}
		log.Fatalf("refusing to start: unexpected interface %q (the sandbox must have loopback only)", ifc.Name)
	}

	dial, err := boundaryDialer(boundary)
	if err != nil {
		log.Fatal(err)
	}
	fd, err := openTUN(*device, uint32(*mtu))
	if err != nil {
		log.Fatal(err)
	}
	if err := configureTUN(*device); err != nil {
		log.Fatalf("configuring %s: %v", *device, err)
	}
	if err := os.WriteFile("/etc/resolv.conf", []byte("nameserver "+resolverAddr+"\n"), 0o644); err != nil {
		log.Printf("[!] writing /etc/resolv.conf: %v (lookups may not reach the virtual DNS)", err)
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
	defer eng.Close()

	if *ingress != "" {
		go serveIngress(*ingress)
	}

	log.Printf("launcher up: device=%s boundary=%s agent=%q", *device, boundary, argv)
	os.Exit(runChild(argv))
}

// configureTUN gives the device the guest addresses, brings it up, and
// installs default routes through it.
//
// The /10 and /64 prefixes already give the kernel connected routes that
// cover the synthetic pools, so normal traffic does not need the default
// routes. They exist so that everything else also reaches the engine: an
// agent that hardcodes its own DNS server (say 8.8.8.8) still gets an
// answer, because the engine serves port 53 on any address routed to it,
// and a dial to an unrelated literal IP fails with a clear refusal from
// the engine instead of a routing error.
func configureTUN(name string) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return err
	}
	for _, cidr := range []string{
		fmt.Sprintf("%s/%d", guestAddr4, pool4PrefixLen),
		fmt.Sprintf("%s/%d", guestAddr6, pool6PrefixLen),
	} {
		addr, err := netlink.ParseAddr(cidr)
		if err != nil {
			return err
		}
		if err := netlink.AddrAdd(link, addr); err != nil {
			return fmt.Errorf("address %s: %w", cidr, err)
		}
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("link up: %w", err)
	}
	// Device routes with no gateway: there is nothing to name on the other
	// side of the tun. Dst must be set explicitly because netlink treats a
	// nil Dst as "no route given".
	for _, dst := range []*net.IPNet{
		{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
		{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)},
	} {
		if err := netlink.RouteAdd(&netlink.Route{
			LinkIndex: link.Attrs().Index,
			Scope:     netlink.SCOPE_LINK,
			Dst:       dst,
		}); err != nil {
			return fmt.Errorf("default route for %s: %w", dst, err)
		}
	}
	return nil
}

// runChild runs argv as this process's child and does the PID 1 duties:
// reap whatever re-parents to us, forward the fatal signals to the
// child's process group, and return the child's exit status.
func runChild(argv []string) int {
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		log.Fatalf("starting %q: %v", argv[0], err)
	}
	child := cmd.Process.Pid

	sig := make(chan os.Signal, 16)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGCHLD)
	for s := range sig {
		if s != syscall.SIGCHLD {
			unix.Kill(-child, s.(syscall.Signal)) // whole process group
			continue
		}
		for {
			var ws unix.WaitStatus
			pid, err := unix.Wait4(-1, &ws, unix.WNOHANG, nil)
			if pid <= 0 || err != nil {
				break
			}
			if pid == child {
				if ws.Signaled() {
					return 128 + int(ws.Signal())
				}
				return ws.ExitStatus()
			}
		}
	}
	return 0
}

// serveIngress answers the hybrid-vsock handshake ("CONNECT <port>\n" ->
// "OK\n") and joins each accepted stream to the agent's loopback
// listener, so the host can deliver inbound requests without the sandbox
// exposing any port.
func serveIngress(path string) {
	os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		log.Printf("[!] ingress socket %s: %v", path, err)
		return
	}
	// The host-side gateway may run unprivileged; the socket file is
	// created by container root.
	os.Chmod(path, 0o666)
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go func(conn net.Conn) {
			defer conn.Close()
			br := bufio.NewReader(conn)
			line, err := br.ReadString('\n')
			if err != nil {
				return
			}
			var port int
			if _, err := fmt.Sscanf(strings.TrimSpace(line), "CONNECT %d", &port); err != nil {
				io.WriteString(conn, "ERR malformed handshake\n")
				return
			}
			upstream, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
			if err != nil {
				io.WriteString(conn, "ERR the agent is not listening\n")
				return
			}
			defer upstream.Close()
			io.WriteString(conn, "OK\n")
			go io.Copy(upstream, br)
			io.Copy(conn, upstream)
		}(conn)
	}
}
