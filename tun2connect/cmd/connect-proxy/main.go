// Command connect-proxy is a minimal reference boundary: CONNECT for
// TCP and connect-udp (RFC 9298) for UDP, applying deny-by-default
// policy on destination NAMES and writing one audit line per decision.
// -h2 switches from HTTP/1.1 (one connection per flow) to a single
// multiplexed cleartext HTTP/2 session (prior knowledge, HBONE-shaped):
// TCP flows are CONNECT streams, UDP sessions extended CONNECT streams.
//
// It pairs with cmd/tun2connect for the full demo, and is curl-testable
// alone (curl uses CONNECT through an HTTP proxy):
//
//	connect-proxy -listen tcp://127.0.0.1:8080 -allow example.com
//	curl --proxy http://127.0.0.1:8080 https://example.com
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
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
	"syscall"
	"time"

	"golang.org/x/net/http2"

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
	host, target, ok := masqueTarget(req.URL.Path)
	if !ok {
		refuse(conn, "malformed-template")
		return
	}
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
	pumpUDP(tun2connect.NewCapsuleStream(struct {
		io.Reader
		io.Writer
	}{br, conn}), upstream)
}

// masqueTarget parses the default connect-udp URI template
// /.well-known/masque/udp/{host}/{port}/.
func masqueTarget(path string) (host, target string, ok bool) {
	seg := strings.Split(strings.Trim(path, "/"), "/")
	if len(seg) != 5 || seg[0] != ".well-known" || seg[1] != "masque" || seg[2] != "udp" {
		return "", "", false
	}
	host, err := url.PathUnescape(seg[3])
	if err != nil {
		return "", "", false
	}
	return host, net.JoinHostPort(host, seg[4]), true
}

func pumpUDP(cs *tun2connect.CapsuleStream, upstream net.Conn) {
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

// flushWriter flushes each write so tunneled bytes are not buffered
// behind the h2 frame scheduler.
type flushWriter struct {
	w http.ResponseWriter
	f http.Flusher
}

func (fw flushWriter) Write(p []byte) (int, error) {
	n, err := fw.w.Write(p)
	if err == nil {
		fw.f.Flush()
	}
	return n, err
}

// peerIdentity is whatever the client certificate asserts, PKI-agnostic:
// first URI SAN (SPIFFE in a mesh, but any scheme), else first DNS SAN,
// else the CN. Empty without mTLS.
func peerIdentity(cs *tls.ConnectionState) string {
	if cs == nil || len(cs.PeerCertificates) == 0 {
		return ""
	}
	leaf := cs.PeerCertificates[0]
	if len(leaf.URIs) > 0 {
		return leaf.URIs[0].String()
	}
	if len(leaf.DNSNames) > 0 {
		return leaf.DNSNames[0]
	}
	return leaf.Subject.CommonName
}

func withPeer(target, peer string) string {
	if peer != "" {
		return target + " peer=" + peer
	}
	return target
}

// sessionPeer extracts the mTLS identity at session level: CONNECT
// streams carry no :scheme, so x/net never populates r.TLS for them.
func sessionPeer(conn net.Conn) (string, error) {
	tc, ok := conn.(*tls.Conn)
	if !ok {
		return "", nil
	}
	if err := tc.HandshakeContext(context.Background()); err != nil {
		return "", err
	}
	cs := tc.ConnectionState()
	return peerIdentity(&cs), nil
}

func refuseH2(w http.ResponseWriter, reason string) {
	w.Header().Set("Boundary-Reason", reason)
	w.WriteHeader(http.StatusForbidden)
}

// serveH2 handles one stream of the multiplexed session: CONNECT is a
// TCP tunnel, extended CONNECT (:protocol connect-udp) a UDP session.
// peer is the session's mTLS identity, audit-only.
func serveH2(peer string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		f, _ := w.(http.Flusher)
		if proto := r.Header.Get(":protocol"); proto != "" {
			if proto != "connect-udp" {
				refuseH2(w, "unsupported-protocol")
				return
			}
			host, target, ok := masqueTarget(r.URL.Path)
			if !ok {
				refuseH2(w, "malformed-template")
				return
			}
			label := withPeer(target, peer)
			if reason, ok := authorize(host); !ok {
				audit("BLOCK "+reason, label)
				refuseH2(w, reason)
				return
			}
			if !enableUDP {
				audit("BLOCK udp-disabled", label)
				refuseH2(w, "udp-disabled")
				return
			}
			upstream, err := net.DialTimeout("udp", target, dialTimeout)
			if err != nil {
				audit("DIAL-FAIL", label)
				w.WriteHeader(http.StatusBadGateway)
				return
			}
			defer upstream.Close()
			audit("ALLOW udp/h2", label)
			w.Header().Set("Capsule-Protocol", "?1")
			w.WriteHeader(http.StatusOK)
			f.Flush()
			pumpUDP(tun2connect.NewCapsuleStream(struct {
				io.Reader
				io.Writer
			}{r.Body, flushWriter{w, f}}), upstream)
			return
		}

		target := r.Host
		host, _, err := net.SplitHostPort(target)
		if err != nil {
			refuseH2(w, "malformed-target")
			return
		}
		label := withPeer(target, peer)
		if reason, ok := authorize(host); !ok {
			audit("BLOCK "+reason, label)
			refuseH2(w, reason)
			return
		}
		upstream, err := net.DialTimeout("tcp", target, dialTimeout)
		if err != nil {
			audit("DIAL-FAIL", label)
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		defer upstream.Close()
		audit("ALLOW tcp/h2", label)
		w.WriteHeader(http.StatusOK)
		f.Flush()
		go io.Copy(upstream, r.Body)
		io.Copy(flushWriter{w, f}, upstream)
	}
}

func main() {
	listen := flag.String("listen", "unix:///tmp/boundary.sock", "listen address (unix:///path or tcp://host:port)")
	allow := flag.String("allow", "", "comma-separated destination names to allow; '*' allows all (default: deny everything)")
	udp := flag.Bool("udp", false, "serve connect-udp tunnels")
	h2 := flag.Bool("h2", false, "speak multiplexed cleartext HTTP/2 (prior knowledge) instead of HTTP/1.1")
	tlsCert := flag.String("tls-cert", "", "PEM server certificate; enables TLS (with -h2: the HBONE-style mTLS+h2 arrangement)")
	tlsKey := flag.String("tls-key", "", "PEM server key")
	clientCA := flag.String("tls-client-ca", "", "PEM CA bundle; when set, REQUIRE verified client certificates and audit their identity")
	flag.Parse()
	enableUDP = *udp

	// x/net's h2 server only advertises extended CONNECT (UDP over h2)
	// under GODEBUG=http2xconnect=1 (golang/go#71128), read at init --
	// re-exec once with it set.
	if *h2 && !strings.Contains(os.Getenv("GODEBUG"), "http2xconnect=1") {
		godebug := os.Getenv("GODEBUG")
		if godebug != "" {
			godebug += ","
		}
		env := append(os.Environ(), "GODEBUG="+godebug+"http2xconnect=1")
		if exe, err := os.Executable(); err == nil {
			syscall.Exec(exe, os.Args, env)
		}
		log.Print("[!] re-exec failed; UDP over h2 (extended CONNECT) will be refused")
	}

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
	if *tlsCert != "" {
		cert, err := tls.LoadX509KeyPair(*tlsCert, *tlsKey)
		if err != nil {
			log.Fatal(err)
		}
		cfg := &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{"h2", "http/1.1"},
		}
		if *clientCA != "" {
			pem, err := os.ReadFile(*clientCA)
			if err != nil {
				log.Fatal(err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pem) {
				log.Fatalf("no CA certificates in %s", *clientCA)
			}
			cfg.ClientCAs = pool
			cfg.ClientAuth = tls.RequireAndVerifyClientCert
		}
		ln = tls.NewListener(ln, cfg)
	}
	log.Printf("boundary listening on %s (allow=%q udp=%v h2=%v tls=%v mtls=%v)", *listen, *allow, *udp, *h2, *tlsCert != "", *clientCA != "")

	h2s := &http2.Server{}
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Fatal(err)
		}
		if *h2 {
			go func() {
				peer, err := sessionPeer(conn)
				if err != nil {
					audit("TLS-FAIL", err.Error())
					conn.Close()
					return
				}
				h2s.ServeConn(conn, &http2.ServeConnOpts{Handler: serveH2(peer)})
			}()
		} else {
			go serve(conn)
		}
	}
}
