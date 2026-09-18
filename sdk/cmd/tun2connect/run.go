// Launcher mode: `tun2connect run <boundary-socket> <cmd> [args...]`
// builds the sandbox's only route (a TUN terminated in userspace, every
// flow leaving as an HTTP CONNECT tunnel on the boundary socket),
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
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/mdlayher/vsock"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/aojea/agents.net/sdk/pkg/tun2connect"
)

// Guest addresses sit at the TOP of the synthetic pools, inside the /24
// and /120 that VirtualDNS reserves and never hands out, so they cannot
// collide with an invented answer. The /10 and /64 prefix lengths make
// the kernel install the connected routes that cover every synthetic
// address, and the resolver needs no route of its own -- any pool address
// works, because the engine answers port 53 locally wherever the query is
// sent. The device is also made the default route; see configureTUN for why.
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
HTTP CONNECT tunnel with a hostname or IP target. Flags stop at the first positional argument:
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
	ingress := fs.String("ingress-socket", "", "serve the ingress channel (HTTP CONNECT 127.0.0.1:<port>) on this Unix socket path or vsock://PORT; requires -ingress-port")
	ingressPort := fs.Uint("ingress-port", 0, "the only loopback port ingress streams may be joined to (1-65535)")
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
	if *ingress != "" && (*ingressPort == 0 || *ingressPort > 65535) {
		log.Fatal("-ingress-socket requires -ingress-port in the range 1-65535: the controller, not the caller, chooses which local service ingress reaches")
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
	var ingressListener net.Listener
	if *ingress != "" {
		if ingressListener, err = listenIngress(*ingress); err != nil {
			log.Fatalf("ingress listener %s: %v", *ingress, err)
		}
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
	if err := dropNetAdmin(); err != nil {
		log.Fatalf("dropping CAP_NET_ADMIN after TUN setup: %v", err)
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

	if ingressListener != nil {
		go serveIngress(ingressListener, uint16(*ingressPort))
	}

	log.Printf("launcher up: device=%s boundary=%s agent=%q", *device, boundary, argv)
	os.Exit(runChild(argv))
}

// dropNetAdmin removes CAP_NET_ADMIN, which only TUN setup needed, from
// every launcher thread and from the bounding set the agent inherits, so
// neither a compromised launcher nor the agent can reconfigure networking.
// Capability sets are per thread; the child is cloned from whichever thread
// runs the goroutine, so all threads must agree (needs a cgo-free build).
func dropNetAdmin() error {
	if _, _, errno := syscall.AllThreadsSyscall6(unix.SYS_PRCTL, unix.PR_CAPBSET_DROP, unix.CAP_NET_ADMIN, 0, 0, 0, 0); errno != 0 {
		return fmt.Errorf("bounding set: %w (needs CAP_SETPCAP and CGO_ENABLED=0)", errno)
	}
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(&header, &data[0]); err != nil {
		return fmt.Errorf("capget: %w", err)
	}
	const mask = ^uint32(1 << unix.CAP_NET_ADMIN)
	data[0].Effective &= mask
	data[0].Permitted &= mask
	data[0].Inheritable &= mask
	if _, _, errno := syscall.AllThreadsSyscall(unix.SYS_CAPSET, uintptr(unsafe.Pointer(&header)), uintptr(unsafe.Pointer(&data[0])), 0); errno != 0 {
		return fmt.Errorf("capset: %w", errno)
	}
	if kept, err := unix.PrctlRetInt(unix.PR_CAPBSET_READ, unix.CAP_NET_ADMIN, 0, 0, 0); err != nil || kept != 0 {
		return fmt.Errorf("CAP_NET_ADMIN still in bounding set (%d, %v)", kept, err)
	}
	return nil
}

// configureTUN gives the device the guest addresses, brings it up, and
// installs default routes through it.
//
// The /10 and /64 prefixes already give the kernel connected routes that
// cover the synthetic pools, so normal traffic does not need the default
// routes. They exist so that everything else also reaches the engine: an
// agent that hardcodes its own DNS server (say 8.8.8.8) still gets an
// answer, because the engine serves port 53 on any address routed to it,
// and a dial to a literal IP reaches the boundary for authorization.
func configureTUN(name string) error {
	// As a VM init nothing else brings loopback up; left down, the default
	// route below would send 127.0.0.1 into the TUN instead of the guest stack.
	if lo, err := netlink.LinkByName("lo"); err == nil {
		if err := netlink.LinkSetUp(lo); err != nil {
			return fmt.Errorf("loopback up: %w", err)
		}
	}
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

// listenIngress opens the reverse channel: a Unix socket path, or
// vsock://PORT for a VM whose VMM delivers host connections to a guest
// AF_VSOCK listener (Firecracker performs its own CONNECT/OK exchange on
// the host side before handing the stream to this port).
func listenIngress(spec string) (net.Listener, error) {
	if rawPort, ok := strings.CutPrefix(spec, "vsock://"); ok {
		port, err := strconv.ParseUint(strings.TrimPrefix(rawPort, ":"), 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid vsock port %q: %w", rawPort, err)
		}
		return vsock.Listen(uint32(port), nil)
	}
	path := strings.TrimPrefix(spec, "unix://")
	os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	// The host-side gateway may run unprivileged; the socket file is
	// created by container root.
	os.Chmod(path, 0o666)
	return ln, nil
}

// serveIngress answers HTTP CONNECT on the reverse channel
// (spec/draft/ingress.md Section 2) and joins each accepted stream to the
// agent's loopback listener, so the host can deliver inbound requests
// without the sandbox exposing any port. Only the pinned port is
// reachable: the request names it, it does not choose it.
func serveIngress(ln net.Listener, pinned uint16) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go func(conn net.Conn) {
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			br := bufio.NewReader(io.LimitReader(conn, maxIngressHead))
			status, reason := ingressTarget(br, pinned)
			if reason != "" {
				fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\nProxy-Status: %s\r\nContent-Length: 0\r\n\r\n",
					status, http.StatusText(status), tun2connect.ProxyStatus("ingress", reason))
				return
			}
			upstream, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", pinned), 5*time.Second)
			if err != nil {
				fmt.Fprintf(conn, "HTTP/1.1 502 Bad Gateway\r\nProxy-Status: %s\r\nContent-Length: 0\r\n\r\n",
					tun2connect.ProxyStatus("ingress", "dial-failed"))
				return
			}
			defer upstream.Close()
			conn.SetDeadline(time.Time{})
			io.WriteString(conn, "HTTP/1.1 200 OK\r\n\r\n")
			// Bytes the gateway sent after the head are tunnel data; the
			// limited reader no longer applies once the head is consumed.
			go func() {
				io.Copy(upstream, io.MultiReader(bufferedBytes(br), conn))
				if cw, ok := upstream.(interface{ CloseWrite() error }); ok {
					cw.CloseWrite()
				}
			}()
			io.Copy(conn, upstream)
		}(conn)
	}
}

// maxIngressHead bounds the request head read from the gateway.
const maxIngressHead = 8 << 10

// bufferedBytes returns a reader over what br has already buffered.
func bufferedBytes(br *bufio.Reader) io.Reader {
	buffered, _ := br.Peek(br.Buffered())
	return strings.NewReader(string(buffered))
}

// ingressTarget parses one HTTP/1.1 CONNECT head and checks that it names
// the pinned loopback port. A non-empty reason is the refusal token; status
// is its HTTP status (spec/draft/registries.md Section 2). The head is read
// here rather than with net/http, which discards the Host field before it
// can be compared with the request-target.
func ingressTarget(br *bufio.Reader, pinned uint16) (status int, reason string) {
	line, err := br.ReadString('\n')
	if err != nil {
		return http.StatusBadRequest, "malformed-request-line"
	}
	fields := strings.Split(strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r"), " ")
	if len(fields) != 3 || fields[0] == "" || fields[1] == "" {
		return http.StatusBadRequest, "malformed-request-line"
	}
	method, target, version := fields[0], fields[1], fields[2]
	if version != "HTTP/1.1" && version != "HTTP/1.0" {
		if strings.HasPrefix(version, "HTTP/") {
			return http.StatusHTTPVersionNotSupported, "unsupported-version"
		}
		return http.StatusBadRequest, "malformed-request-line"
	}
	var host string
	hosts := 0
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return http.StatusBadRequest, "malformed-header"
		}
		line = strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
		if line == "" {
			break
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok || name == "" || strings.ContainsAny(name, " \t") {
			return http.StatusBadRequest, "malformed-header"
		}
		if strings.EqualFold(name, "Host") {
			hosts++
			host = strings.TrimSpace(value)
		}
	}
	if hosts > 1 {
		return http.StatusBadRequest, "duplicate-host"
	}
	if method != http.MethodConnect {
		return http.StatusMethodNotAllowed, "connect-only"
	}
	if version == "HTTP/1.1" && hosts == 0 {
		return http.StatusBadRequest, "missing-host"
	}
	addr, port, err := net.SplitHostPort(target)
	if err != nil || addr != "127.0.0.1" {
		return http.StatusBadRequest, "malformed-target"
	}
	number, err := strconv.ParseUint(port, 10, 16)
	if err != nil || number == 0 {
		return http.StatusBadRequest, "malformed-port"
	}
	if hosts == 1 && host != target {
		return http.StatusBadRequest, "authority-mismatch"
	}
	if uint16(number) != pinned {
		return http.StatusForbidden, "port-not-permitted"
	}
	return 0, ""
}
