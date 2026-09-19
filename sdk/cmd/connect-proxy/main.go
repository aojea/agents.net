// Command connect-proxy is the reference boundary: CONNECT for TCP and
// connect-udp (RFC 9298) for UDP, applying a deny-by-default policy
// descriptor (spec/draft/policy.md) on destination names, addresses,
// ports, and transports, with one JSON audit record per decision.
// Hostnames are resolved by the boundary and only public or explicitly
// listed resolved addresses are dialed, so an allowed name cannot reach
// loopback, private, link-local, or metadata addresses. Failures carry an
// RFC 9209 Proxy-Status field with the reason token.
// -h2 switches from HTTP/1.1 (one connection per flow) to a single
// multiplexed cleartext HTTP/2 session (prior knowledge, HBONE-shaped):
// TCP flows are CONNECT streams, UDP sessions extended CONNECT streams.
//
// It pairs with cmd/tun2connect for the full demo, and is curl-testable
// alone (curl uses CONNECT through an HTTP proxy):
//
//	connect-proxy -listen tcp://127.0.0.1:8080 -policy policy.json
//	curl --proxy http://127.0.0.1:8080 https://example.com
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/textproto"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/net/http/httpguts"
	"golang.org/x/net/http2"

	"github.com/aojea/agents.net/sdk/pkg/tun2connect"
)

const dialTimeout = 15 * time.Second

// atomicDuration is a timeout that tests change while handlers from an
// earlier test may still be running.
type atomicDuration struct{ ns atomic.Int64 }

func newDuration(d time.Duration) *atomicDuration {
	v := &atomicDuration{}
	v.Store(d)
	return v
}

func (d *atomicDuration) Load() time.Duration   { return time.Duration(d.ns.Load()) }
func (d *atomicDuration) Store(v time.Duration) { d.ns.Store(int64(v)) }

// headTimeout bounds how long a client may take to send a request head.
var headTimeout = newDuration(dialTimeout)

// idleTimeout closes a tunnel that has carried no data in either
// direction for this long; zero disables the check.
var idleTimeout = newDuration(time.Hour)

func boundaryTLSConfig(certPath, keyPath, clientCAPath string) (*tls.Config, error) {
	if certPath == "" && keyPath == "" && clientCAPath == "" {
		return nil, nil
	}
	if certPath == "" || keyPath == "" {
		return nil, errors.New("TLS requires both -tls-cert and -tls-key; -tls-client-ca cannot be used without them")
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load boundary certificate: %w", err)
	}
	config := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2", "http/1.1"},
	}
	if clientCAPath != "" {
		pem, err := os.ReadFile(clientCAPath)
		if err != nil {
			return nil, fmt.Errorf("load client CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no CA certificates in %s", clientCAPath)
		}
		config.ClientCAs = pool
		config.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return config, nil
}

// auditRecord is one JSON line per decision (spec/draft/audit.md).
// Guest-supplied fields are JSON-encoded, so they cannot inject line
// breaks or additional fields.
type auditRecord struct {
	Time        string `json:"ts"`
	Listener    string `json:"listener,omitempty"`
	Sandbox     string `json:"sandbox,omitempty"`
	Generation  string `json:"generation,omitempty"`
	Policy      string `json:"policy,omitempty"`
	Wire        string `json:"wire,omitempty"`
	Transport   string `json:"transport,omitempty"`
	Destination string `json:"destination,omitempty"`
	Address     string `json:"address,omitempty"`
	Peer        string `json:"peer,omitempty"`
	Connection  string `json:"connection,omitempty"`
	Rule        string `json:"rule,omitempty"`
	Decision    string `json:"decision"`
	Reason      string `json:"reason,omitempty"`
}

var (
	auditMu  sync.Mutex
	auditOut io.Writer = os.Stdout
	// listenerName labels records with the listener the controller bound
	// this process to; identity and policy version come from the policy.
	listenerName string
)

func audit(r auditRecord) {
	r.Time = time.Now().UTC().Format(time.RFC3339Nano)
	r.Listener = listenerName
	if p := current.Load(); p != nil {
		r.Sandbox, r.Policy, r.Generation = p.sandbox, p.version, p.generation
	}
	line, err := json.Marshal(r)
	if err != nil {
		return
	}
	auditMu.Lock()
	defer auditMu.Unlock()
	auditOut.Write(append(line, '\n'))
}

// responder writes a non-tunnel response on either wire.
type responder interface {
	deny(status int, reason string)
}

// proxyStatus is the Proxy-Status field value for a refusal by this boundary.
func proxyStatus(reason string) string {
	return tun2connect.ProxyStatus("boundary", reason)
}

type h1Responder struct{ conn net.Conn }

func (r h1Responder) deny(status int, reason string) {
	// The connection ends after a refusal; a peer that never reads must
	// not hold the handler.
	r.conn.SetWriteDeadline(time.Now().Add(headTimeout.Load()))
	fmt.Fprintf(r.conn, "HTTP/1.1 %d %s\r\nProxy-Status: %s\r\nContent-Length: 0\r\n\r\n", status, http.StatusText(status), proxyStatus(reason))
}

type h2Responder struct{ w http.ResponseWriter }

func (r h2Responder) deny(status int, reason string) {
	r.w.Header().Set("Proxy-Status", proxyStatus(reason))
	r.w.WriteHeader(status)
}

// session labels every record of one accepted connection or HTTP/2
// session: the channel-authenticated peer identity (audit-only) and a
// boundary-local connection id for correlating requests.
type session struct{ peer, id string }

var connections atomic.Uint64

func newSession(peer string) session {
	return session{peer: peer, id: strconv.FormatUint(connections.Add(1), 10)}
}

// connectUpstream authorizes host:port and dials a checked address. It
// writes the refusal itself and returns nil when no tunnel may be opened.
func connectUpstream(ctx context.Context, r responder, wire, network, host, port string, s session) net.Conn {
	rec := auditRecord{Wire: wire, Transport: network, Destination: net.JoinHostPort(host, port), Peer: s.peer, Connection: s.id}
	p := current.Load()
	if p == nil {
		rec.Decision, rec.Reason = "fail", "policy-unavailable"
		audit(rec)
		r.deny(http.StatusServiceUnavailable, "policy-unavailable")
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	// features.udp false refuses every connect-udp request before rules.
	if network == "udp" && !p.udp {
		rec.Decision, rec.Reason = "block", "udp-disabled"
		audit(rec)
		r.deny(http.StatusForbidden, "udp-disabled")
		return nil
	}
	v := p.authorize(ctx, host, port, network)
	rec.Destination = v.destination
	switch {
	case v.reason != "":
		rec.Decision, rec.Reason = "block", v.reason
		audit(rec)
		r.deny(v.status, v.reason)
		return nil
	case v.err != nil:
		rec.Decision, rec.Reason = "fail", "resolve-failed"
		audit(rec)
		r.deny(http.StatusBadGateway, "resolve-failed")
		return nil
	}
	upstream, err := dialAuthorized(network, v.addresses, port)
	if err != nil {
		rec.Decision, rec.Reason = "fail", "dial-failed"
		audit(rec)
		r.deny(http.StatusBadGateway, "dial-failed")
		return nil
	}
	rec.Decision, rec.Address, rec.Rule = "allow", upstream.RemoteAddr().String(), v.rule
	audit(rec)
	return upstream
}

// dialAuthorized connects to the first reachable checked address without
// resolving the hostname again.
func dialAuthorized(network string, addresses []netip.Addr, port string) (net.Conn, error) {
	var err error
	for _, address := range addresses {
		var upstream net.Conn
		upstream, err = net.DialTimeout(network, net.JoinHostPort(address.String(), port), dialTimeout)
		if err == nil {
			return upstream, nil
		}
	}
	return nil, err
}

// malformed records and refuses a request that never reached policy.
func malformed(r responder, wire, network, destination string, s session, reason string) {
	refuse(r, wire, network, destination, s, http.StatusBadRequest, reason)
}

// refuse records a block decision and writes the refusal.
func refuse(r responder, wire, network, destination string, s session, status int, reason string) {
	audit(auditRecord{Wire: wire, Transport: network, Destination: destination, Peer: s.peer, Connection: s.id, Decision: "block", Reason: reason})
	r.deny(status, reason)
}

type closeWriter interface{ CloseWrite() error }

type activityReader struct {
	io.Reader
	touch func()
}

func (a activityReader) Read(p []byte) (int, error) {
	n, err := a.Reader.Read(p)
	if n > 0 {
		a.touch()
	}
	return n, err
}

// idleWatch runs stop once no touch has occurred for idleTimeout, as
// configured when the tunnel starts. The returned cancel ends the watch
// and must be called exactly once.
func idleWatch(stop func()) (touch, cancel func()) {
	idle := idleTimeout.Load()
	if idle <= 0 {
		return func() {}, func() {}
	}
	var last atomic.Int64
	last.Store(time.Now().UnixNano())
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(max(idle/4, time.Millisecond))
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				if time.Since(time.Unix(0, last.Load())) >= idle {
					stop()
					return
				}
			}
		}
	}()
	return func() { last.Store(time.Now().UnixNano()) }, func() { close(done) }
}

// relay copies client<->upstream until upstream ends or the tunnel is
// idle. Client EOF is propagated to upstream as a half-close.
func relay(client io.ReadWriter, upstream net.Conn, closeClient func()) {
	touch, cancel := idleWatch(func() { upstream.Close(); closeClient() })
	defer cancel()
	go func() {
		io.Copy(upstream, activityReader{client, touch})
		if cw, ok := upstream.(closeWriter); ok {
			cw.CloseWrite()
		} else {
			upstream.Close()
		}
	}()
	io.Copy(client, activityReader{upstream, touch})
}

func handleConnect(conn net.Conn, br *bufio.Reader, h *head, s session) {
	host, port, reason := connectTarget(h)
	if reason != "" {
		malformed(h1Responder{conn}, "h1", "tcp", h.target, s, reason)
		return
	}
	upstream := connectUpstream(context.Background(), h1Responder{conn}, "h1", "tcp", host, port, s)
	if upstream == nil {
		return
	}
	defer upstream.Close()
	io.WriteString(conn, "HTTP/1.1 200 OK\r\n\r\n")
	// br first: it may hold bytes the client sent after the request head.
	relay(struct {
		io.Reader
		io.Writer
	}{br, conn}, upstream, func() { conn.Close() })
}

func handleConnectUDP(conn net.Conn, br *bufio.Reader, h *head, s session) {
	path, ok := upgradeTarget(h)
	if !ok {
		malformed(h1Responder{conn}, "h1", "udp", h.target, s, "malformed-upgrade")
		return
	}
	host, port, ok := masqueTarget(path)
	if !ok {
		malformed(h1Responder{conn}, "h1", "udp", h.target, s, "malformed-template")
		return
	}
	upstream := connectUpstream(context.Background(), h1Responder{conn}, "h1", "udp", host, port, s)
	if upstream == nil {
		return
	}
	defer upstream.Close()
	io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: connect-udp\r\nCapsule-Protocol: ?1\r\n\r\n")
	pumpUDP(tun2connect.NewCapsuleStream(struct {
		io.Reader
		io.Writer
	}{br, conn}), upstream, func() { conn.Close() })
}

// maxHeadBytes bounds an HTTP/1.x request head. The limit is lifted for
// tunnel data once the head has been parsed.
const maxHeadBytes = 64 << 10

// headError is a request head the boundary refuses with an HTTP status.
type headError struct {
	status int
	reason string
}

func (e *headError) Error() string { return e.reason }

// boundedReader caps the bytes read while remaining is non-negative.
type boundedReader struct {
	r         io.Reader
	remaining int64
}

func (b *boundedReader) Read(p []byte) (int, error) {
	if b.remaining < 0 {
		return b.r.Read(p)
	}
	if b.remaining == 0 {
		return 0, &headError{http.StatusRequestHeaderFieldsTooLarge, "head-too-large"}
	}
	if int64(len(p)) > b.remaining {
		p = p[:b.remaining]
	}
	n, err := b.r.Read(p)
	b.remaining -= int64(n)
	return n, err
}

// head is a parsed HTTP/1.x request head. It is parsed here rather than
// with http.ReadRequest because that reader discards the Host field,
// which Section 4.5 requires comparing against the CONNECT authority.
type head struct {
	method, target string
	major, minor   int
	header         textproto.MIMEHeader
}

// readHead parses the request line and header block. It rejects a
// request line without exactly three single-space-separated fields, a
// non-token method, an HTTP version other than 1.x, and more than one
// Host field. Content-Length and Transfer-Encoding are ignored on CONNECT
// (RFC 9110 Section 9.3.6): bytes after the head are tunnel data.
func readHead(br *bufio.Reader) (*head, error) {
	tp := textproto.NewReader(br)
	line, err := tp.ReadLine()
	if err != nil {
		return nil, err
	}
	method, rest, found := strings.Cut(line, " ")
	target, proto, foundProto := strings.Cut(rest, " ")
	if !found || !foundProto || target == "" || strings.Contains(proto, " ") || !httpguts.ValidHeaderFieldName(method) {
		return nil, &headError{http.StatusBadRequest, "malformed-request-line"}
	}
	major, minor, ok := http.ParseHTTPVersion(proto)
	if !ok || major != 1 {
		return nil, &headError{http.StatusHTTPVersionNotSupported, "unsupported-version"}
	}
	header, err := tp.ReadMIMEHeader()
	if err != nil {
		var he *headError
		if errors.As(err, &he) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, os.ErrDeadlineExceeded) {
			return nil, err
		}
		return nil, &headError{http.StatusBadRequest, "malformed-header"}
	}
	if len(header.Values("Host")) > 1 {
		return nil, &headError{http.StatusBadRequest, "duplicate-host"}
	}
	// textproto tolerates whitespace before the colon (go.dev/issue/34540);
	// RFC 9112 Section 5.1 requires rejecting it.
	for key := range header {
		if !httpguts.ValidHeaderFieldName(key) {
			return nil, &headError{http.StatusBadRequest, "malformed-header"}
		}
	}
	if minor >= 1 && len(header.Values("Host")) == 0 {
		return nil, &headError{http.StatusBadRequest, "missing-host"}
	}
	return &head{method: method, target: target, major: major, minor: minor, header: header}, nil
}

// connectTarget validates an authority-form CONNECT target: a host and an
// explicit numeric port, no userinfo, path, or query, and a Host field
// (when present) naming the same destination.
func connectTarget(h *head) (host, port, reason string) {
	if !httpguts.ValidHostHeader(h.target) {
		return "", "", "malformed-target"
	}
	host, port, err := net.SplitHostPort(h.target)
	if err != nil || host == "" {
		return "", "", "malformed-target"
	}
	if _, err := parsePort(port); err != nil {
		return "", "", "malformed-port"
	}
	if hostField := h.header.Get("Host"); hostField != "" && !sameAuthority(hostField, h.target) {
		return "", "", "authority-mismatch"
	}
	return host, port, ""
}

// sameAuthority compares two host:port authorities after normalizing
// case, a trailing DNS dot, and IP address text.
func sameAuthority(a, b string) bool {
	hostA, portA, errA := net.SplitHostPort(a)
	hostB, portB, errB := net.SplitHostPort(b)
	if errA != nil || errB != nil || portA != portB {
		return false
	}
	if addrA, err := netip.ParseAddr(hostA); err == nil {
		addrB, err := netip.ParseAddr(hostB)
		return err == nil && addrA == addrB
	}
	return strings.EqualFold(strings.TrimSuffix(hostA, "."), strings.TrimSuffix(hostB, "."))
}

// upgradeTarget accepts a connect-udp upgrade (RFC 9298 Section 3.1) in
// origin or absolute form and returns its path.
func upgradeTarget(h *head) (path string, ok bool) {
	if !httpguts.HeaderValuesContainsToken(h.header.Values("Connection"), "Upgrade") ||
		!httpguts.HeaderValuesContainsToken(h.header.Values("Upgrade"), "connect-udp") {
		return "", false
	}
	u, err := url.ParseRequestURI(h.target)
	if err != nil || u.User != nil {
		return "", false
	}
	return u.Path, true
}

func isUpgrade(h *head) bool {
	return httpguts.HeaderValuesContainsToken(h.header.Values("Upgrade"), "connect-udp")
}

// masqueTarget parses the default connect-udp URI template
// /.well-known/masque/udp/{host}/{port}/.
func masqueTarget(path string) (host, port string, ok bool) {
	seg := strings.Split(strings.Trim(path, "/"), "/")
	if len(seg) != 5 || seg[0] != ".well-known" || seg[1] != "masque" || seg[2] != "udp" {
		return "", "", false
	}
	host, err := url.PathUnescape(seg[3])
	if err != nil || host == "" {
		return "", "", false
	}
	return host, seg[4], true
}

func pumpUDP(cs *tun2connect.CapsuleStream, upstream net.Conn, closeClient func()) {
	touch, cancel := idleWatch(func() { upstream.Close(); closeClient() })
	defer cancel()
	go func() {
		defer upstream.Close()
		for {
			p, err := cs.ReadDatagram()
			if err != nil {
				return
			}
			touch()
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
		touch()
		if cs.WriteDatagram(buf[:n]) != nil {
			return
		}
	}
}

func serve(conn net.Conn) {
	defer conn.Close()
	peer, err := sessionPeer(conn)
	if err != nil {
		audit(auditRecord{Wire: "h1", Decision: "fail", Reason: "tls-failed"})
		return
	}
	s := newSession(peer)
	// Bound the request head in time and bytes so a stalled or oversized
	// head cannot hold the handler or its memory.
	conn.SetReadDeadline(time.Now().Add(headTimeout.Load()))
	limiter := &boundedReader{r: conn, remaining: maxHeadBytes}
	br := bufio.NewReader(limiter)
	h, err := readHead(br)
	if err != nil {
		var he *headError
		if errors.As(err, &he) {
			audit(auditRecord{Wire: "h1", Peer: s.peer, Connection: s.id, Decision: "block", Reason: he.reason})
			h1Responder{conn}.deny(he.status, he.reason)
		}
		return
	}
	conn.SetReadDeadline(time.Time{})
	limiter.remaining = -1
	switch {
	case h.method == http.MethodConnect:
		handleConnect(conn, br, h, s)
	case h.method == http.MethodGet && isUpgrade(h):
		handleConnectUDP(conn, br, h, s)
	default:
		refuse(h1Responder{conn}, "h1", "", "", s, http.StatusMethodNotAllowed, "connect-only")
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

// sessionPeer extracts the mTLS identity at session level: CONNECT
// streams carry no :scheme, so x/net never populates r.TLS for them.
func sessionPeer(conn net.Conn) (string, error) {
	tc, ok := conn.(*tls.Conn)
	if !ok {
		return "", nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()
	if err := tc.HandshakeContext(ctx); err != nil {
		return "", err
	}
	cs := tc.ConnectionState()
	return peerIdentity(&cs), nil
}

// serveH2 handles one stream of the multiplexed session: CONNECT is a
// TCP tunnel, extended CONNECT (:protocol connect-udp) a UDP session.
// s carries the session's mTLS identity (audit-only) and connection id.
func serveH2(s session) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			refuse(h2Responder{w}, "h2", "", "", s, http.StatusMethodNotAllowed, "connect-only")
			return
		}
		f, _ := w.(http.Flusher)
		if proto := r.Header.Get(":protocol"); proto != "" {
			if proto != "connect-udp" {
				malformed(h2Responder{w}, "h2", "", r.URL.Path, s, "unsupported-protocol")
				return
			}
			host, port, ok := masqueTarget(r.URL.Path)
			if !ok {
				malformed(h2Responder{w}, "h2", "udp", r.URL.Path, s, "malformed-template")
				return
			}
			upstream := connectUpstream(r.Context(), h2Responder{w}, "h2", "udp", host, port, s)
			if upstream == nil {
				return
			}
			defer upstream.Close()
			w.Header().Set("Capsule-Protocol", "?1")
			w.WriteHeader(http.StatusOK)
			f.Flush()
			// Closing upstream ends the handler, which closes the stream.
			pumpUDP(tun2connect.NewCapsuleStream(struct {
				io.Reader
				io.Writer
			}{r.Body, flushWriter{w, f}}), upstream, func() {})
			return
		}

		host, port, err := net.SplitHostPort(r.Host)
		if err != nil || host == "" {
			malformed(h2Responder{w}, "h2", "tcp", r.Host, s, "malformed-target")
			return
		}
		if _, err := parsePort(port); err != nil {
			malformed(h2Responder{w}, "h2", "tcp", r.Host, s, "malformed-port")
			return
		}
		upstream := connectUpstream(r.Context(), h2Responder{w}, "h2", "tcp", host, port, s)
		if upstream == nil {
			return
		}
		defer upstream.Close()
		w.WriteHeader(http.StatusOK)
		f.Flush()
		relay(struct {
			io.Reader
			io.Writer
		}{r.Body, flushWriter{w, f}}, upstream, func() {})
	}
}

// serveListener accepts connections within the connection budget. A
// connection over budget is refused with 503 before its request head is
// read, so a flood cannot hold handler goroutines.
func serveListener(ln net.Listener, useH2 bool, maxConnections, maxStreams int) error {
	slots := make(chan struct{}, maxConnections)
	h2s := &http2.Server{MaxConcurrentStreams: uint32(maxStreams), IdleTimeout: idleTimeout.Load()}
	wire := "h1"
	if useH2 {
		wire = "h2"
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		select {
		case slots <- struct{}{}:
		default:
			audit(auditRecord{Wire: wire, Decision: "fail", Reason: "busy"})
			if _, isTLS := conn.(*tls.Conn); !isTLS {
				h1Responder{conn}.deny(http.StatusServiceUnavailable, "busy")
			}
			conn.Close()
			continue
		}
		go func() {
			defer func() { <-slots }()
			if !useH2 {
				serve(conn)
				return
			}
			peer, err := sessionPeer(conn)
			if err != nil {
				audit(auditRecord{Wire: wire, Decision: "fail", Reason: "tls-failed"})
				conn.Close()
				return
			}
			h2s.ServeConn(conn, &http2.ServeConnOpts{Handler: serveH2(newSession(peer))})
		}()
	}
}

func main() {
	listen := flag.String("listen", "unix:///tmp/boundary.sock", "listen address (unix:///path or tcp://host:port)")
	policyPath := flag.String("policy", "", "policy descriptor file (spec/draft/policy.md) bound to this listener; required")
	generation := flag.String("generation", "", "controller-assigned sandbox generation recorded in every audit record")
	resolver := flag.String("resolver", "", "DNS server host:port the boundary resolves allowed hostnames with (default: the system resolver)")
	maxConnections := flag.Int("max-connections", 1024, "maximum concurrently accepted client connections or HTTP/2 sessions; further connections receive 503")
	maxStreams := flag.Int("max-streams", 256, "maximum concurrent streams per HTTP/2 session")
	idle := flag.Duration("idle-timeout", time.Hour, "close tunnels that carry no data in either direction for this long; 0 disables")
	h2 := flag.Bool("h2", false, "speak multiplexed cleartext HTTP/2 (prior knowledge) instead of HTTP/1.1")
	tlsCert := flag.String("tls-cert", "", "PEM server certificate; enables TLS (with -h2: the HBONE-style mTLS+h2 arrangement)")
	tlsKey := flag.String("tls-key", "", "PEM server key")
	clientCA := flag.String("tls-client-ca", "", "PEM CA bundle; when set, REQUIRE verified client certificates and audit their identity")
	flag.Parse()
	idleTimeout.Store(*idle)
	listenerName = *listen
	if *maxConnections <= 0 || *maxStreams <= 0 {
		log.Fatal("-max-connections and -max-streams must be positive")
	}
	if *policyPath == "" {
		log.Fatal("-policy is required: a boundary without a policy descriptor answers every request with policy-unavailable")
	}
	p, err := loadPolicyFile(*policyPath, *generation)
	if err != nil {
		log.Fatal(err)
	}
	current.Store(p)
	if *resolver != "" {
		lookupNetIP = pinnedResolver(*resolver).LookupNetIP
	}
	tlsConfig, err := boundaryTLSConfig(*tlsCert, *tlsKey, *clientCA)
	if err != nil {
		log.Fatal(err)
	}

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
	if tlsConfig != nil {
		ln = tls.NewListener(ln, tlsConfig)
	}
	log.Printf("boundary listening on %s (policy=%s sandbox=%q version=%q generation=%q udp=%v h2=%v tls=%v mtls=%v max-connections=%d max-streams=%d idle-timeout=%s)",
		*listen, *policyPath, p.sandbox, p.version, p.generation, p.udp, *h2, *tlsCert != "", *clientCA != "", *maxConnections, *maxStreams, *idle)
	log.Fatal(serveListener(ln, *h2, *maxConnections, *maxStreams))
}
