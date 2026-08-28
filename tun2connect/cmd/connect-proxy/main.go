// Command connect-proxy is a minimal reference boundary: an HTTP/1.1
// server speaking CONNECT for TCP and connect-udp (RFC 9298) for UDP,
// applying deny-by-default policy on destination NAMES and writing one
// audit line per decision.
//
// It pairs with cmd/tun2connect for the full demo, and is curl-testable
// alone (curl uses CONNECT through an HTTP proxy):
//
//	connect-proxy -listen tcp://127.0.0.1:8080 -allow example.com
//	curl --proxy http://127.0.0.1:8080 https://example.com
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/aojea/agents.net/tun2connect/pkg/tun2connect"
)

const dialTimeout = 15 * time.Second

var (
	allowAll  bool
	allowed   = map[string]bool{}
	enableUDP bool
)

func audit(decision, target string) {
	log.Printf("%s %s", decision, target)
}

// authorize applies policy to a destination name. IP literals are
// refused outright: policy reasons about names, and a flow that arrives
// without one was never authorized.
func authorize(host string) (reason string, ok bool) {
	host = strings.ToLower(host)
	if _, err := netip.ParseAddr(host); err == nil {
		return "ip-literal", false
	}
	if allowAll || allowed[host] {
		return "", true
	}
	return "not-on-allowlist", false
}

func refuse(conn net.Conn, reason string) {
	fmt.Fprintf(conn, "HTTP/1.1 403 Forbidden\r\nBoundary-Reason: %s\r\nContent-Length: 0\r\n\r\n", reason)
}

func handleConnect(conn net.Conn, br *bufio.Reader, req *http.Request) {
	target := req.Host
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		refuse(conn, "malformed-target")
		return
	}
	if reason, ok := authorize(host); !ok {
		audit("BLOCK "+reason, target)
		refuse(conn, reason)
		return
	}
	upstream, err := net.DialTimeout("tcp", target, dialTimeout)
	if err != nil {
		audit("DIAL-FAIL", target)
		fmt.Fprintf(conn, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		return
	}
	defer upstream.Close()
	audit("ALLOW tcp", target)
	io.WriteString(conn, "HTTP/1.1 200 OK\r\n\r\n")
	go io.Copy(upstream, br) // br first: it may hold pipelined bytes
	io.Copy(conn, upstream)
}

func handleConnectUDP(conn net.Conn, br *bufio.Reader, req *http.Request) {
	// Default URI template: /.well-known/masque/udp/{host}/{port}/
	seg := strings.Split(strings.Trim(req.URL.Path, "/"), "/")
	if len(seg) != 5 || seg[0] != ".well-known" || seg[1] != "masque" || seg[2] != "udp" {
		refuse(conn, "malformed-template")
		return
	}
	host, err := url.PathUnescape(seg[3])
	if err != nil {
		refuse(conn, "malformed-template")
		return
	}
	target := net.JoinHostPort(host, seg[4])
	if reason, ok := authorize(host); !ok {
		audit("BLOCK "+reason, target)
		refuse(conn, reason)
		return
	}
	if !enableUDP {
		audit("BLOCK udp-disabled", target)
		refuse(conn, "udp-disabled")
		return
	}
	upstream, err := net.DialTimeout("udp", target, dialTimeout)
	if err != nil {
		audit("DIAL-FAIL", target)
		fmt.Fprintf(conn, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		return
	}
	defer upstream.Close()
	audit("ALLOW udp", target)
	io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: connect-udp\r\nCapsule-Protocol: ?1\r\n\r\n")

	cs := tun2connect.NewCapsuleStream(struct {
		io.Reader
		io.Writer
	}{br, conn})
	go func() {
		defer upstream.Close()
		for {
			p, err := cs.ReadDatagram()
			if err != nil {
				return
			}
			if _, err := upstream.Write(p); err != nil {
				return
			}
		}
	}()
	buf := make([]byte, 65535)
	for {
		n, err := upstream.Read(buf)
		if err != nil {
			return
		}
		if cs.WriteDatagram(buf[:n]) != nil {
			return
		}
	}
}

func serve(conn net.Conn) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	switch {
	case req.Method == http.MethodConnect:
		handleConnect(conn, br, req)
	case req.Method == http.MethodGet && strings.EqualFold(req.Header.Get("Upgrade"), "connect-udp"):
		handleConnectUDP(conn, br, req)
	default:
		fmt.Fprintf(conn, "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n")
	}
}

func main() {
	listen := flag.String("listen", "unix:///tmp/boundary.sock", "listen address (unix:///path or tcp://host:port)")
	allow := flag.String("allow", "", "comma-separated destination names to allow; '*' allows all (default: deny everything)")
	udp := flag.Bool("udp", false, "serve connect-udp tunnels")
	flag.Parse()
	enableUDP = *udp

	for _, h := range strings.Split(*allow, ",") {
		if h = strings.ToLower(strings.TrimSpace(h)); h == "*" {
			allowAll = true
		} else if h != "" {
			allowed[h] = true
		}
	}

	u, err := url.Parse(*listen)
	if err != nil {
		log.Fatal(err)
	}
	var ln net.Listener
	switch u.Scheme {
	case "unix":
		os.Remove(u.Path)
		ln, err = net.Listen("unix", u.Path)
	case "tcp":
		ln, err = net.Listen("tcp", u.Host)
	default:
		log.Fatalf("unsupported listen scheme %q (want unix:// or tcp://)", u.Scheme)
	}
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("boundary listening on %s (allow=%q udp=%v)", *listen, *allow, *udp)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go serve(conn)
	}
}
