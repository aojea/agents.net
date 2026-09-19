package netnsproxy

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"

	"github.com/aojea/agents.net/sdk/pkg/tun2connect"
)

func TestNamespaceIntegration(t *testing.T) {
	if os.Getenv("NETNS_PROXY_INTEGRATION") != "1" {
		t.Skip("set NETNS_PROXY_INTEGRATION=1 for Linux user/netns and nftables tests")
	}
	switch os.Getenv("NETNS_PROXY_ROLE") {
	case "proxy":
		testProxyNamespace(t)
		return
	case "client", "offline":
		testClientNamespace(t)
		return
	}
	for _, udp := range []string{"0", "1"} {
		t.Run("udp="+udp, func(t *testing.T) {
			path, calls := testBoundary(t)
			ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, "unshare", "--user", "--map-root-user", "--net",
				os.Args[0], "-test.run=^TestNamespaceIntegration$", "-test.v")
			command.Env = append(os.Environ(), "NETNS_PROXY_ROLE=proxy", "NETNS_BOUNDARY="+path, "NETNS_UDP="+udp)
			output, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("namespace execution: %v\n%s", err, output)
			}
			t.Logf("%s", output)
			seen := make(map[string]bool)
			for {
				select {
				case call := <-calls:
					seen[call] = true
				default:
					for _, expected := range []string{
						"allowed.test:8080", "denied.test:8080",
						"203.0.113.10:8080", "[2001:db8::10]:8080",
						"203.0.113.11:8080", "[2001:db8::11]:8080",
					} {
						if !seen[expected] {
							t.Errorf("boundary did not receive %s: %v", expected, seen)
						}
					}
					if udp == "1" {
						for _, host := range []string{"allowed.test", "203.0.113.10", "2001:db8::10"} {
							if !seen["/.well-known/masque/udp/"+host+"/9001/"] {
								t.Errorf("boundary did not receive UDP for %s: %v", host, seen)
							}
						}
					}
					return
				}
			}
		})
	}
}

func testBoundary(t *testing.T) (string, chan string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "boundary.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	calls := make(chan string, 64)
	var workers sync.WaitGroup
	workers.Add(1)
	go func() {
		defer workers.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(40 * time.Second))
				reader := bufio.NewReader(conn)
				request, err := http.ReadRequest(reader)
				if err != nil {
					return
				}
				if request.Method == http.MethodConnect {
					calls <- request.Host
					if request.Host != "allowed.test:8080" && request.Host != "203.0.113.10:8080" && request.Host != "[2001:db8::10]:8080" {
						io.WriteString(conn, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
						return
					}
					io.WriteString(conn, "HTTP/1.1 200 OK\r\n\r\n")
					io.Copy(conn, reader)
					return
				}
				path, err := url.PathUnescape(request.URL.Path)
				if err != nil {
					return
				}
				calls <- path
				if !strings.HasPrefix(path, "/.well-known/masque/udp/allowed.test/") &&
					!strings.HasPrefix(path, "/.well-known/masque/udp/203.0.113.10/") &&
					!strings.HasPrefix(path, "/.well-known/masque/udp/2001:db8::10/") {
					io.WriteString(conn, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
					return
				}
				io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: connect-udp\r\nCapsule-Protocol: ?1\r\n\r\n")
				capsules := tun2connect.NewCapsuleStream(struct {
					io.Reader
					io.Writer
				}{reader, conn})
				for {
					packet, err := capsules.ReadDatagram()
					if err != nil || capsules.WriteDatagram(packet) != nil {
						return
					}
				}
			}()
		}
	}()
	t.Cleanup(func() { listener.Close(); workers.Wait() })
	return path, calls
}

func testProxyNamespace(t *testing.T) {
	peer := testVeth(t)
	defer peer.Close()
	var trace bytes.Buffer
	capture := exec.Command("tcpdump", "-n", "-l", "-Z", "root", "-i", "proxy0")
	capture.Stdout, capture.Stderr = &trace, &trace
	if err := capture.Start(); err == nil {
		t.Cleanup(func() {
			capture.Process.Signal(os.Interrupt)
			capture.Wait()
			if t.Failed() {
				t.Logf("packet trace:\n%s", trace.String())
			}
		})
	}
	t.Cleanup(func() {
		if t.Failed() {
			output, _ := exec.Command("nft", "list", "ruleset").CombinedOutput()
			t.Logf("nftables:\n%s", output)
		}
	})
	conn := &nftables.Conn{}
	conn.AddTable(&nftables.Table{Name: "unrelated", Family: nftables.TableFamilyINet})
	if err := conn.Flush(); err != nil {
		t.Fatal(err)
	}
	forwarder := &tun2connect.Forwarder{
		DNS: tun2connect.NewVirtualDNS(), DialTimeout: 2 * time.Second, UDPIdleTimeout: 2 * time.Second,
		Dialer: &tun2connect.BoundaryClient{DialBoundary: func(ctx context.Context) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, "unix", os.Getenv("NETNS_BOUNDARY"))
		}},
	}
	cfg := Config{Interface: "proxy0", Forwarder: forwarder, EnableUDP: os.Getenv("NETNS_UDP") == "1", EnableIPv6: true}
	proxy, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	done := make(chan error, 1)
	go func() { done <- proxy.Run(context.Background()) }()
	if second, err := New(cfg); err == nil {
		second.Close()
		t.Fatal("existing rules were overwritten")
	}
	testRunClient(t, peer, "client")
	proxy.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("proxy shutdown hung")
	}
	testRunClient(t, peer, "offline")
	tables, err := conn.ListTables()
	if err != nil {
		t.Fatal(err)
	}
	names := make(map[string]bool)
	for _, table := range tables {
		names[table.Name] = true
	}
	if !names["unrelated"] || !names["agents_net"] {
		t.Fatalf("unrelated or fail-closed table missing: %v", names)
	}
}

func testVeth(t *testing.T) netns.NsHandle {
	t.Helper()
	runtime.LockOSThread()
	original, err := netns.Get()
	if err != nil {
		runtime.UnlockOSThread()
		t.Fatal(err)
	}
	peer, createErr := netns.New()
	restoreErr := netns.Set(original)
	original.Close()
	if restoreErr != nil {
		t.Fatal(restoreErr)
	}
	runtime.UnlockOSThread()
	if createErr != nil {
		t.Fatal(createErr)
	}
	if err := netlink.LinkAdd(&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "proxy0"},
		PeerName: "client0", PeerNamespace: netlink.NsFd(peer)}); err != nil {
		peer.Close()
		t.Fatal(err)
	}
	proxyHandle, err := netlink.NewHandle()
	if err != nil {
		t.Fatal(err)
	}
	defer proxyHandle.Close()
	clientHandle, err := netlink.NewHandleAt(peer)
	if err != nil {
		t.Fatal(err)
	}
	defer clientHandle.Close()
	for _, side := range []struct {
		handle    *netlink.Handle
		name      string
		addresses []string
	}{{proxyHandle, "proxy0", []string{"192.0.2.1/30", "fd00:1234::1/64"}},
		{clientHandle, "client0", []string{"192.0.2.2/30", "fd00:1234::2/64"}}} {
		link, err := side.handle.LinkByName(side.name)
		if err != nil {
			t.Fatal(err)
		}
		for _, cidr := range side.addresses {
			address, err := netlink.ParseAddr(cidr)
			if err != nil {
				t.Fatal(err)
			}
			address.Flags = 2
			if err := side.handle.AddrAdd(link, address); err != nil {
				t.Fatal(err)
			}
		}
		if err := side.handle.LinkSetUp(link); err != nil {
			t.Fatal(err)
		}
		loopback, err := side.handle.LinkByName("lo")
		if err != nil {
			t.Fatal(err)
		}
		if err := side.handle.LinkSetUp(loopback); err != nil {
			t.Fatal(err)
		}
	}
	for _, route := range []netlink.Route{
		{Gw: net.ParseIP("192.0.2.1")}, {Gw: net.ParseIP("fd00:1234::1")},
	} {
		if err := clientHandle.RouteAdd(&route); err != nil {
			t.Fatal(err)
		}
	}
	return peer
}

func testRunClient(t *testing.T, namespace netns.NsHandle, role string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	file, err := os.Open(fmt.Sprintf("/proc/self/fd/%d", namespace))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	command := exec.CommandContext(ctx, "nsenter", "--net=/proc/self/fd/3", os.Args[0], "-test.run=^TestNamespaceIntegration$", "-test.v")
	command.ExtraFiles = []*os.File{file}
	command.Env = append(os.Environ(), "NETNS_PROXY_ROLE="+role)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("client: %v\n%s", err, output)
	} else {
		t.Logf("%s", output)
	}
}

func testClientNamespace(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if os.Getenv("NETNS_PROXY_ROLE") == "offline" {
		conn, err := net.DialTimeout("tcp", "100.64.0.1:8080", time.Second)
		if err == nil {
			conn.Close()
			t.Fatal("connection succeeded after proxy shutdown")
		}
		return
	}
	for _, family := range []string{"4", "6"} {
		t.Run("IPv"+family, func(t *testing.T) {
			resolverAddress := "192.0.2.1:53"
			if family == "6" {
				resolverAddress = "[fd00:1234::1]:53"
			}
			resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				var dialer net.Dialer
				return dialer.DialContext(ctx, "udp"+family, resolverAddress)
			}}
			resolve := func(name string) netip.Addr {
				addresses, err := resolver.LookupNetIP(ctx, "ip"+family, name)
				if err != nil || len(addresses) != 1 {
					t.Fatalf("DNS %s: %v, %v", name, addresses, err)
				}
				return addresses[0]
			}
			allowed := resolve("allowed.test")
			literal, deniedLiteral := netip.MustParseAddr("203.0.113.10"), netip.MustParseAddr("203.0.113.11")
			if family == "6" {
				literal, deniedLiteral = netip.MustParseAddr("2001:db8::10"), netip.MustParseAddr("2001:db8::11")
			}
			for _, destination := range []netip.Addr{allowed, literal} {
				conn, err := net.DialTimeout("tcp"+family, netip.AddrPortFrom(destination, 8080).String(), 2*time.Second)
				if err != nil {
					t.Fatal(err)
				}
				conn.SetDeadline(time.Now().Add(2 * time.Second))
				payload := strings.Repeat("stream", 2048)
				if _, err := io.WriteString(conn, payload); err != nil {
					t.Fatal(err)
				}
				conn.(*net.TCPConn).CloseWrite()
				response, err := io.ReadAll(conn)
				conn.Close()
				if err != nil || string(response) != payload {
					t.Fatalf("TCP echo/half-close for %s: %d bytes, %v", destination, len(response), err)
				}
			}
			for _, denied := range []netip.Addr{resolve("denied.test"), deniedLiteral} {
				conn, err := net.DialTimeout("tcp", netip.AddrPortFrom(denied, 8080).String(), time.Second)
				if err == nil {
					conn.SetDeadline(time.Now().Add(time.Second))
					_, err = conn.Read(make([]byte, 1))
					conn.Close()
				}
				if err == nil {
					t.Fatal("denied destination accepted")
				}
				if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
					t.Fatalf("denial timed out instead of refusing: %v", err)
				}
			}
			socket, err := net.ListenUDP("udp"+family, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer socket.Close()
			for _, target := range []netip.AddrPort{
				netip.AddrPortFrom(allowed, 9001), netip.AddrPortFrom(literal, 9001),
				netip.AddrPortFrom(literal, 9002), netip.AddrPortFrom(literal, 9001),
			} {
				packet := []byte(fmt.Sprintf("datagram-%s", target))
				socket.SetDeadline(time.Now().Add(time.Second))
				if _, err := socket.WriteToUDPAddrPort(packet, target); err != nil {
					t.Fatal(err)
				}
				buf := make([]byte, 100)
				count, source, err := socket.ReadFromUDPAddrPort(buf)
				if os.Getenv("NETNS_UDP") == "0" {
					if err == nil {
						t.Fatal("disabled UDP returned a response")
					}
					break
				}
				if err != nil || source != target || string(buf[:count]) != string(packet) {
					t.Fatalf("UDP echo: source=%s want=%s packet=%q err=%v", source, target, buf[:count], err)
				}
			}
		})
	}
}
