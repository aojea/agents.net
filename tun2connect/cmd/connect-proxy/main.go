// Command connect-proxy is a minimal reference boundary: CONNECT for
// TCP and connect-udp (RFC 9298) for UDP, applying deny-by-default
// policy on destination names, IP addresses, and ports, with one JSON
// audit record per decision.
// Hostnames are resolved by the boundary and only public or explicitly
// listed resolved addresses are dialed, so an allowed name cannot reach
// loopback, private, link-local, or metadata addresses.
// -h2 switches from HTTP/1.1 (one connection per flow) to a single
// multiplexed cleartext HTTP/2 session (prior knowledge, HBONE-shaped):
// TCP flows are CONNECT streams, UDP sessions extended CONNECT streams.
//
// It pairs with cmd/tun2connect for the full demo, and is curl-testable
// alone (curl uses CONNECT through an HTTP proxy):
//
//	connect-proxy -listen tcp://127.0.0.1:8080 -allow example.com:443
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
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/net/http2"

	"github.com/aojea/agents.net/tun2connect/pkg/tun2connect"
)

const dialTimeout = 15 * time.Second

// headTimeout bounds how long a client may take to send a request head.
var headTimeout = dialTimeout

// idleTimeout closes a tunnel that has carried no data in either
// direction for this long; zero disables the check.
var idleTimeout = time.Hour

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

// portSet is the set of ports a policy entry permits; any covers every port.
type portSet struct {
	any   bool
	ports map[uint16]bool
}

func (p *portSet) permits(port uint16) bool { return p.any || p.ports[port] }

func (p *portSet) add(port uint16, hasPort bool) {
	if !hasPort {
		p.any = true
		return
	}
	if p.ports == nil {
		p.ports = map[uint16]bool{}
	}
	p.ports[port] = true
}

type ipRule struct {
	prefix netip.Prefix
	ports  portSet
}

var (
	// allowed maps a lowercase hostname, or "*" for every name, to its ports.
	allowed    = map[string]*portSet{}
	allowedIPs []ipRule
	enableUDP  bool
	// static maps a hostname to fixed addresses used instead of DNS.
	static = map[string][]netip.Addr{}
	// lookupNetIP resolves permitted hostnames; tests substitute it.
	lookupNetIP = net.DefaultResolver.LookupNetIP
)

// nonPublic lists special-purpose ranges that netip's classifiers do not
// cover. Together with loopback, private, link-local, multicast, and
// unspecified addresses they are denied for resolved hostnames unless
// -allow-ip names them.
var nonPublic = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("3fff::/20"),
	netip.MustParsePrefix("5f00::/16"),
	netip.MustParsePrefix("fec0::/10"),
}

// auditRecord is one JSON line per decision. Guest-supplied fields are
// JSON-encoded, so they cannot inject line breaks or additional fields.
type auditRecord struct {
	Time        string `json:"ts"`
	Listener    string `json:"listener,omitempty"`
	Sandbox     string `json:"sandbox,omitempty"`
	Policy      string `json:"policy,omitempty"`
	Wire        string `json:"wire,omitempty"`
	Transport   string `json:"transport,omitempty"`
	Destination string `json:"destination,omitempty"`
	Address     string `json:"address,omitempty"`
	Peer        string `json:"peer,omitempty"`
	Decision    string `json:"decision"`
	Reason      string `json:"reason,omitempty"`
}

var (
	auditMu  sync.Mutex
	auditOut io.Writer = os.Stdout
	// Listener-bound identity: the controller assigns one sandbox and
	// policy to this listener, so every record carries them.
	listenerName  string
	sandboxID     string
	policyVersion string
)

func audit(r auditRecord) {
	r.Time = time.Now().UTC().Format(time.RFC3339Nano)
	r.Listener, r.Sandbox, r.Policy = listenerName, sandboxID, policyVersion
	line, err := json.Marshal(r)
	if err != nil {
		return
	}
	auditMu.Lock()
	defer auditMu.Unlock()
	auditOut.Write(append(line, '\n'))
}

// listedAddress reports whether -allow-ip permits address on port, and
// whether any -allow-ip prefix covers the address at all.
func listedAddress(address netip.Addr, port uint16) (permitted, known bool) {
	for _, rule := range allowedIPs {
		if !rule.prefix.Contains(address) {
			continue
		}
		known = true
		if rule.ports.permits(port) {
			return true, true
		}
	}
	return false, known
}

// namePermitted reports whether -allow permits host on port, and whether
// the host (or the wildcard) appears in -allow at all.
func namePermitted(host string, port uint16) (permitted, known bool) {
	for _, key := range []string{host, "*"} {
		if ports, ok := allowed[key]; ok {
			known = true
			if ports.permits(port) {
				return true, true
			}
		}
	}
	return false, known
}

func publicAddress(address netip.Addr) bool {
	if !address.IsGlobalUnicast() || address.IsPrivate() {
		return false
	}
	for _, prefix := range nonPublic {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

// authorize applies destination policy and returns the exact addresses the
// boundary may dial. Literals must be listed in -allow-ip. Hostnames must
// pass -allow and are resolved here; only public or explicitly listed
// resolved addresses are kept, so an allowed name cannot reach loopback,
// private, or metadata addresses by rebinding. Port restrictions on an
// entry apply to the port requested. A non-empty reason is a policy
// denial; a non-nil error is a resolution failure.
func authorize(ctx context.Context, host, port string) (addresses []netip.Addr, reason string, err error) {
	number, err := parsePort(port)
	if err != nil {
		return nil, "malformed-port", nil
	}
	host = strings.ToLower(host)
	if address, err := netip.ParseAddr(host); err == nil {
		if address.Zone() != "" {
			return nil, "scoped-ip", nil
		}
		address = address.Unmap()
		switch permitted, known := listedAddress(address, number); {
		case permitted:
			return []netip.Addr{address}, "", nil
		case known:
			return nil, "port-not-allowed", nil
		default:
			return nil, "ip-not-on-allowlist", nil
		}
	}
	host = strings.TrimSuffix(host, ".")
	switch permitted, known := namePermitted(host, number); {
	case permitted:
	case known:
		return nil, "port-not-allowed", nil
	default:
		return nil, "not-on-allowlist", nil
	}
	resolved, mapped := static[host]
	if !mapped {
		if resolved, err = lookupNetIP(ctx, "ip", host); err != nil {
			return nil, "", err
		}
	}
	for _, address := range resolved {
		address = address.Unmap()
		if address.Zone() != "" {
			continue
		}
		if permitted, _ := listedAddress(address, number); permitted || publicAddress(address) {
			addresses = append(addresses, address)
		}
	}
	if len(addresses) == 0 {
		return nil, "resolved-address-denied", nil
	}
	return addresses, "", nil
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

func parsePort(value string) (uint16, error) {
	number, err := strconv.ParseUint(value, 10, 16)
	if err != nil || number == 0 {
		return 0, fmt.Errorf("invalid port %q", value)
	}
	return uint16(number), nil
}

// splitPort separates an optional ":port" suffix from a policy entry.
// IPv6 addresses and prefixes carry a port only in bracket form,
// "[2001:db8::/64]:443"; a bare entry with several colons has no port.
func splitPort(entry string) (rest string, port uint16, hasPort bool, err error) {
	if strings.HasPrefix(entry, "[") {
		end := strings.IndexByte(entry, ']')
		if end < 0 {
			return "", 0, false, fmt.Errorf("unbalanced bracket in %q", entry)
		}
		rest, tail := entry[1:end], entry[end+1:]
		if tail == "" {
			return rest, 0, false, nil
		}
		if !strings.HasPrefix(tail, ":") {
			return "", 0, false, fmt.Errorf("unexpected %q after bracket in %q", tail, entry)
		}
		port, err := parsePort(tail[1:])
		return rest, port, err == nil, err
	}
	if strings.Count(entry, ":") != 1 {
		return entry, 0, false, nil
	}
	rest, rawPort, _ := strings.Cut(entry, ":")
	port, err = parsePort(rawPort)
	return rest, port, err == nil, err
}

// parseAllow reads "name[:port]" entries; "*" matches every name. An
// entry without a port permits every port on that name.
func parseAllow(value string) (map[string]*portSet, error) {
	names := map[string]*portSet{}
	for _, entry := range strings.Split(value, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		name, port, hasPort, err := splitPort(entry)
		if err != nil {
			return nil, fmt.Errorf("invalid -allow entry %q: %w", entry, err)
		}
		name = strings.TrimSuffix(strings.ToLower(name), ".")
		if name == "" {
			return nil, fmt.Errorf("invalid -allow entry %q: empty name", entry)
		}
		if _, err := netip.ParseAddr(name); err == nil {
			return nil, fmt.Errorf("invalid -allow entry %q: addresses belong in -allow-ip", entry)
		}
		set := names[name]
		if set == nil {
			set = &portSet{}
			names[name] = set
		}
		set.add(port, hasPort)
	}
	return names, nil
}

// parseIPAllowlist reads "ip[:port]", "cidr[:port]", "[ip6]:port", and
// "[cidr6]:port" entries.
func parseIPAllowlist(value string) ([]ipRule, error) {
	var rules []ipRule
	for _, entry := range strings.Split(value, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		rest, port, hasPort, err := splitPort(entry)
		if err != nil {
			return nil, fmt.Errorf("invalid -allow-ip entry %q: %w", entry, err)
		}
		var rule ipRule
		rule.ports.add(port, hasPort)
		if address, err := netip.ParseAddr(rest); err == nil && address.Zone() == "" {
			address = address.Unmap()
			rule.prefix = netip.PrefixFrom(address, address.BitLen())
			rules = append(rules, rule)
			continue
		}
		prefix, err := netip.ParsePrefix(rest)
		if err != nil {
			return nil, fmt.Errorf("invalid -allow-ip entry %q: %w", entry, err)
		}
		if prefix.Addr().Is4In6() {
			if prefix.Bits() < 96 {
				return nil, fmt.Errorf("invalid IPv4-mapped prefix %q", entry)
			}
			prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
		}
		rule.prefix = prefix.Masked()
		rules = append(rules, rule)
	}
	return rules, nil
}

// parseStatic reads "name=ip[+ip...]" entries. Mapped addresses are still
// subject to address policy: a non-public mapping needs -allow-ip.
func parseStatic(value string) (map[string][]netip.Addr, error) {
	mappings := map[string][]netip.Addr{}
	for _, entry := range strings.Split(value, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		name, rawAddresses, found := strings.Cut(entry, "=")
		name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
		if !found || name == "" {
			return nil, fmt.Errorf("invalid -resolve entry %q (want name=ip)", entry)
		}
		if _, err := netip.ParseAddr(name); err == nil {
			return nil, fmt.Errorf("invalid -resolve entry %q: name is an address", entry)
		}
		for _, raw := range strings.Split(rawAddresses, "+") {
			address, err := netip.ParseAddr(strings.TrimSpace(raw))
			if err != nil || address.Zone() != "" {
				return nil, fmt.Errorf("invalid -resolve address %q in %q", raw, entry)
			}
			mappings[name] = append(mappings[name], address.Unmap())
		}
	}
	return mappings, nil
}

// responder writes a non-tunnel response on either wire.
type responder interface {
	deny(status int, reason string)
}

type h1Responder struct{ conn net.Conn }

func (r h1Responder) deny(status int, reason string) {
	fmt.Fprintf(r.conn, "HTTP/1.1 %d %s\r\nBoundary-Reason: %s\r\nContent-Length: 0\r\n\r\n", status, http.StatusText(status), reason)
}

type h2Responder struct{ w http.ResponseWriter }

func (r h2Responder) deny(status int, reason string) {
	r.w.Header().Set("Boundary-Reason", reason)
	r.w.WriteHeader(status)
}

// connectUpstream authorizes host:port and dials a checked address. It
// writes the refusal itself and returns nil when no tunnel may be opened.
func connectUpstream(ctx context.Context, r responder, wire, network, host, port, peer string) net.Conn {
	rec := auditRecord{Wire: wire, Transport: network, Destination: net.JoinHostPort(host, port), Peer: peer}
	ctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	addresses, reason, err := authorize(ctx, host, port)
	if reason == "" && err == nil && network == "udp" && !enableUDP {
		reason = "udp-disabled"
	}
	switch {
	case reason != "":
		rec.Decision, rec.Reason = "block", reason
		audit(rec)
		r.deny(http.StatusForbidden, reason)
		return nil
	case err != nil:
		rec.Decision, rec.Reason = "fail", "resolve-failed"
		audit(rec)
		r.deny(http.StatusBadGateway, "resolve-failed")
		return nil
	}
	upstream, err := dialAuthorized(network, addresses, port)
	if err != nil {
		rec.Decision, rec.Reason = "fail", "dial-failed"
		audit(rec)
		r.deny(http.StatusBadGateway, "dial-failed")
		return nil
	}
	rec.Decision, rec.Address = "allow", upstream.RemoteAddr().String()
	audit(rec)
	return upstream
}

// malformed records and refuses a request that never reached policy.
func malformed(r responder, wire, network, destination, peer, reason string) {
	audit(auditRecord{Wire: wire, Transport: network, Destination: destination, Peer: peer, Decision: "block", Reason: reason})
	r.deny(http.StatusForbidden, reason)
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
	idle := idleTimeout
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

func handleConnect(conn net.Conn, br *bufio.Reader, req *http.Request, peer string) {
	host, port, err := net.SplitHostPort(req.Host)
	if err != nil {
		malformed(h1Responder{conn}, "h1", "tcp", req.Host, peer, "malformed-target")
		return
	}
	upstream := connectUpstream(context.Background(), h1Responder{conn}, "h1", "tcp", host, port, peer)
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

func handleConnectUDP(conn net.Conn, br *bufio.Reader, req *http.Request, peer string) {
	host, port, ok := masqueTarget(req.URL.Path)
	if !ok {
		malformed(h1Responder{conn}, "h1", "udp", req.URL.Path, peer, "malformed-template")
		return
	}
	upstream := connectUpstream(context.Background(), h1Responder{conn}, "h1", "udp", host, port, peer)
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
	// Bound the request head so a stalled client cannot hold the handler.
	conn.SetReadDeadline(time.Now().Add(headTimeout))
	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	conn.SetReadDeadline(time.Time{})
	switch {
	case req.Method == http.MethodConnect:
		handleConnect(conn, br, req, peer)
	case req.Method == http.MethodGet && strings.EqualFold(req.Header.Get("Upgrade"), "connect-udp"):
		handleConnectUDP(conn, br, req, peer)
	default:
		h1Responder{conn}.deny(http.StatusMethodNotAllowed, "connect-only")
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
// peer is the session's mTLS identity, audit-only.
func serveH2(peer string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			h2Responder{w}.deny(http.StatusMethodNotAllowed, "connect-only")
			return
		}
		f, _ := w.(http.Flusher)
		if proto := r.Header.Get(":protocol"); proto != "" {
			if proto != "connect-udp" {
				malformed(h2Responder{w}, "h2", "", r.URL.Path, peer, "unsupported-protocol")
				return
			}
			host, port, ok := masqueTarget(r.URL.Path)
			if !ok {
				malformed(h2Responder{w}, "h2", "udp", r.URL.Path, peer, "malformed-template")
				return
			}
			upstream := connectUpstream(r.Context(), h2Responder{w}, "h2", "udp", host, port, peer)
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
		if err != nil {
			malformed(h2Responder{w}, "h2", "tcp", r.Host, peer, "malformed-target")
			return
		}
		upstream := connectUpstream(r.Context(), h2Responder{w}, "h2", "tcp", host, port, peer)
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
	h2s := &http2.Server{MaxConcurrentStreams: uint32(maxStreams), IdleTimeout: idleTimeout}
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
			h2s.ServeConn(conn, &http2.ServeConnOpts{Handler: serveH2(peer)})
		}()
	}
}

func main() {
	listen := flag.String("listen", "unix:///tmp/boundary.sock", "listen address (unix:///path or tcp://host:port)")
	allow := flag.String("allow", "", "comma-separated destination names to allow, each optionally :port; '*' or '*:port' allows all names (default: deny everything). Resolved addresses must be public unless listed in -allow-ip")
	allowIP := flag.String("allow-ip", "", "comma-separated IP addresses or CIDRs, each optionally :port ([v6]:port), to allow for literal destinations and for non-public resolved addresses (default: deny)")
	resolve := flag.String("resolve", "", "comma-separated name=ip[+ip] static mappings used instead of DNS for those names; addresses still need -allow-ip unless public")
	sandbox := flag.String("sandbox", "", "controller-assigned identity of the sandbox this listener serves, recorded in every audit record")
	policy := flag.String("policy-version", "", "opaque policy version recorded in every audit record")
	maxConnections := flag.Int("max-connections", 1024, "maximum concurrently accepted client connections or HTTP/2 sessions; further connections receive 503")
	maxStreams := flag.Int("max-streams", 256, "maximum concurrent streams per HTTP/2 session")
	idle := flag.Duration("idle-timeout", time.Hour, "close tunnels that carry no data in either direction for this long; 0 disables")
	udp := flag.Bool("udp", false, "serve connect-udp tunnels")
	h2 := flag.Bool("h2", false, "speak multiplexed cleartext HTTP/2 (prior knowledge) instead of HTTP/1.1")
	tlsCert := flag.String("tls-cert", "", "PEM server certificate; enables TLS (with -h2: the HBONE-style mTLS+h2 arrangement)")
	tlsKey := flag.String("tls-key", "", "PEM server key")
	clientCA := flag.String("tls-client-ca", "", "PEM CA bundle; when set, REQUIRE verified client certificates and audit their identity")
	flag.Parse()
	enableUDP = *udp
	idleTimeout = *idle
	listenerName, sandboxID, policyVersion = *listen, *sandbox, *policy
	if *maxConnections <= 0 || *maxStreams <= 0 {
		log.Fatal("-max-connections and -max-streams must be positive")
	}
	var err error
	allowed, err = parseAllow(*allow)
	if err != nil {
		log.Fatal(err)
	}
	allowedIPs, err = parseIPAllowlist(*allowIP)
	if err != nil {
		log.Fatal(err)
	}
	static, err = parseStatic(*resolve)
	if err != nil {
		log.Fatal(err)
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
	log.Printf("boundary listening on %s (sandbox=%q policy=%q allow=%q allow-ip=%q resolve=%q udp=%v h2=%v tls=%v mtls=%v max-connections=%d max-streams=%d idle-timeout=%s)",
		*listen, *sandbox, *policy, *allow, *allowIP, *resolve, *udp, *h2, *tlsCert != "", *clientCA != "", *maxConnections, *maxStreams, *idle)
	log.Fatal(serveListener(ln, *h2, *maxConnections, *maxStreams))
}
