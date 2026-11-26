// Copyright 2026 The Kubernetes Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tunnel

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aojea/agents.net/pkg/apis"
	"github.com/aojea/agents.net/pkg/auth"
)

const (
	maxHeadBytes        = 64 * 1024
	maxInterimResponses = 8
	udpTargetPrefix     = "/.well-known/masque/udp/"
	dohPath             = "/dns-query"
	dohMediaType        = "application/dns-message"
	maxDoHBodyBytes     = 64 * 1024
)

type headError struct {
	status int
	reason string
}

func (e *headError) Error() string { return e.reason }

type requestHead struct {
	method        string
	target        string
	host          string
	port          string
	upgrade       string
	connection    string
	capsuleProt   string
	contentType   string
	contentLength int
	isUDP         bool
	isDoH         bool
	isHTTPProxy   bool
	originReqHead string
}

// boundedReader caps request head bytes to maxHeadBytes before clearing the cap for tunneling.
type boundedReader struct {
	r         io.Reader
	remaining int
}

func (b *boundedReader) Read(p []byte) (int, error) {
	if b.remaining < 0 {
		return b.r.Read(p)
	}
	if b.remaining == 0 {
		return 0, &headError{status: 431, reason: "head-too-large"}
	}
	if len(p) > b.remaining {
		p = p[:b.remaining]
	}
	n, err := b.r.Read(p)
	b.remaining -= n
	return n, err
}

func readHead(br *bufio.Reader) (*requestHead, error) {
	line, err := readCRLFLine(br)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(line, " ")
	if len(parts) != 3 {
		return nil, &headError{status: 400, reason: "malformed-request-line"}
	}
	method, target, version := parts[0], parts[1], parts[2]
	if version != "HTTP/1.1" && version != "HTTP/1.0" {
		if strings.HasPrefix(version, "HTTP/") {
			return nil, &headError{status: 505, reason: "unsupported-version"}
		}
		return nil, &headError{status: 400, reason: "malformed-request-line"}
	}

	type rawHeader struct {
		key   string
		lower string
		val   string
	}
	var hostHeader, upgrade, connection, capsuleProt, contentType, contentLengthStr string
	var parsedHeaders []rawHeader
	hostCount := 0
	for {
		hline, err := readCRLFLine(br)
		if err != nil {
			return nil, err
		}
		if hline == "" {
			break
		}
		if strings.HasPrefix(hline, " ") || strings.HasPrefix(hline, "\t") {
			return nil, &headError{status: 400, reason: "obs-fold-forbidden"}
		}
		k, v, ok := strings.Cut(hline, ":")
		if !ok || k == "" || !isValidHTTPToken(k) {
			return nil, &headError{status: 400, reason: "malformed-header"}
		}
		val := strings.TrimSpace(v)
		lowerK := strings.ToLower(k)
		switch lowerK {
		case "host":
			hostCount++
			hostHeader = val
		case "upgrade":
			upgrade = val
		case "connection":
			if connection == "" {
				connection = val
			} else {
				connection += "," + val
			}
		case "capsule-protocol":
			capsuleProt = val
		case "content-type":
			contentType = val
		case "content-length":
			contentLengthStr = val
		}
		parsedHeaders = append(parsedHeaders, rawHeader{key: k, lower: lowerK, val: val})
	}
	if hostCount > 1 {
		return nil, &headError{status: 400, reason: "duplicate-host"}
	}
	if version == "HTTP/1.1" && (hostCount == 0 || hostHeader == "") {
		return nil, &headError{status: 400, reason: "missing-host"}
	}

	// Collect hop-by-hop header names listed in Connection plus RFC 9110 fixed hop-by-hop headers.
	hopByHop := map[string]struct{}{
		"host":             {},
		"connection":       {},
		"proxy-connection": {},
		"keep-alive":       {},
		"upgrade":          {},
		"te":               {},
		"trailer":          {},
		"trailers":         {},
	}
	for tok := range strings.SplitSeq(connection, ",") {
		if t := strings.ToLower(strings.TrimSpace(tok)); t != "" {
			hopByHop[t] = struct{}{}
		}
	}
	var forwardHeaders strings.Builder
	for _, hdr := range parsedHeaders {
		if _, skip := hopByHop[hdr.lower]; skip || strings.HasPrefix(hdr.lower, "proxy-") {
			continue
		}
		fmt.Fprintf(&forwardHeaders, "%s: %s\r\n", hdr.key, hdr.val)
	}

	h := &requestHead{
		method:      method,
		target:      target,
		upgrade:     upgrade,
		connection:  connection,
		capsuleProt: capsuleProt,
	}

	switch method {
	case http.MethodConnect:
		host, port, err := splitStrictAuthority(target)
		if err != nil {
			return nil, &headError{status: 400, reason: "malformed-authority"}
		}
		if hostHeader != "" && !sameAuthority(hostHeader, target) {
			return nil, &headError{status: 400, reason: "authority-mismatch"}
		}
		h.host = host
		h.port = port
		return h, nil

	case http.MethodGet:
		if strings.EqualFold(upgrade, "connect-udp") && headerHasToken(connection, "upgrade") {
			if strings.TrimSpace(capsuleProt) != "?1" {
				return nil, &headError{status: 400, reason: "missing-capsule-protocol"}
			}
			host, port, err := parseConnectUDPTarget(target)
			if err != nil {
				return nil, &headError{status: 400, reason: "malformed-udp-target"}
			}
			h.host = host
			h.port = port
			h.isUDP = true
			return h, nil
		}
		if strings.HasPrefix(strings.ToLower(target), "http://") {
			return parseAbsoluteHTTPProxyHead(h, target, forwardHeaders.String())
		}
		return nil, &headError{status: 405, reason: "method-not-allowed"}

	case http.MethodPost:
		if target == dohPath && isDoHMediaType(contentType) {
			n, err := strconv.Atoi(contentLengthStr)
			if err != nil || n <= 0 || n > maxDoHBodyBytes {
				return nil, &headError{status: 400, reason: "malformed-doh-length"}
			}
			h.contentType = contentType
			h.contentLength = n
			h.isDoH = true
			return h, nil
		}
		if strings.HasPrefix(strings.ToLower(target), "http://") {
			return parseAbsoluteHTTPProxyHead(h, target, forwardHeaders.String())
		}
		return nil, &headError{status: 405, reason: "method-not-allowed"}

	case http.MethodHead, http.MethodPut, http.MethodDelete, http.MethodPatch, http.MethodOptions:
		if strings.HasPrefix(strings.ToLower(target), "http://") {
			return parseAbsoluteHTTPProxyHead(h, target, forwardHeaders.String())
		}
		return nil, &headError{status: 405, reason: "method-not-allowed"}

	default:
		return nil, &headError{status: 405, reason: "method-not-allowed"}
	}
}

func parseAbsoluteHTTPProxyHead(h *requestHead, target, forwardHeaders string) (*requestHead, error) {
	u, err := url.Parse(target)
	if err != nil || !strings.EqualFold(u.Scheme, "http") || u.Host == "" {
		return nil, &headError{status: 400, reason: "malformed-http-proxy-target"}
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "80"
	}
	if !isValidTargetHost(host) {
		return nil, &headError{status: 400, reason: "malformed-http-proxy-target"}
	}
	if err := validatePort(port); err != nil {
		return nil, &headError{status: 400, reason: "malformed-http-proxy-target"}
	}
	reqURI := u.RequestURI()
	if !isSafeHeaderValue(reqURI) || strings.ContainsAny(reqURI, " \t") {
		return nil, &headError{status: 400, reason: "malformed-http-proxy-target"}
	}
	h.host = host
	h.port = port
	h.isHTTPProxy = true
	h.originReqHead = fmt.Sprintf("%s %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n%s\r\n",
		h.method, reqURI, u.Host, forwardHeaders)
	return h, nil
}

func readCRLFLine(br *bufio.Reader) (string, error) {
	line, err := br.ReadString('\n')
	if err != nil {
		if he, ok := errors.AsType[*headError](err); ok {
			return "", he
		}
		return "", err
	}
	if !strings.HasSuffix(line, "\r\n") {
		return "", &headError{status: 400, reason: "bare-lf-forbidden"}
	}
	trimmed := strings.TrimSuffix(line, "\r\n")
	if strings.ContainsRune(trimmed, '\r') || !isSafeHeaderValue(trimmed) {
		return "", &headError{status: 400, reason: "malformed-control-char"}
	}
	return trimmed, nil
}

func isSafeHeaderValue(v string) bool {
	for i := range len(v) {
		c := v[i]
		if (c < 0x20 && c != '\t') || c == 0x7f {
			return false
		}
	}
	return true
}

func isValidHTTPToken(s string) bool {
	if len(s) == 0 {
		return false
	}
	for i := range len(s) {
		c := s[i]
		isAlphaNum := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
		if !isAlphaNum && !strings.ContainsRune("!#$%&'*+-.^_`|~", rune(c)) {
			return false
		}
	}
	return true
}

// isValidTargetHost accepts either a literal IPv4/IPv6 address (without zone) or
// a syntactically valid DNS hostname, preventing CRLF or HTTP framing injection via CONNECT authority.
func isValidTargetHost(host string) bool {
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr.Zone() == ""
	}
	trimmed := strings.TrimSuffix(host, ".")
	if len(trimmed) == 0 {
		return false
	}
	for label := range strings.SplitSeq(trimmed, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		for i := range len(label) {
			c := label[i]
			ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_'
			if !ok {
				return false
			}
			if (i == 0 || i == len(label)-1) && c == '-' {
				return false
			}
		}
	}
	return true
}

func splitStrictAuthority(authority string) (string, string, error) {
	host, port, err := net.SplitHostPort(authority)
	if err != nil || !isValidTargetHost(host) || port == "" {
		return "", "", errors.New("invalid authority")
	}
	if err := validatePort(port); err != nil {
		return "", "", err
	}
	return host, port, nil
}

// sameAuthority compares two host:port authorities after normalizing case, a
// single trailing DNS dot, and IPv4/IPv6 text representations.
func sameAuthority(a, b string) bool {
	hostA, portA, errA := splitStrictAuthority(a)
	hostB, portB, errB := splitStrictAuthority(b)
	if errA != nil || errB != nil || portA != portB {
		return false
	}
	if addrA, err := netip.ParseAddr(hostA); err == nil {
		addrB, err := netip.ParseAddr(hostB)
		return err == nil && addrA == addrB
	}
	return strings.EqualFold(strings.TrimSuffix(hostA, "."), strings.TrimSuffix(hostB, "."))
}

func encodeConnectUDPHost(host string) string {
	// RFC 9298 Section 3 requires ":" in IPv6 literals to be percent-encoded.
	return strings.ReplaceAll(url.PathEscape(host), ":", "%3A")
}

func validatePort(value string) error {
	n, err := strconv.ParseUint(value, 10, 16)
	if err != nil || n == 0 {
		return fmt.Errorf("invalid port %q", value)
	}
	return nil
}

func parseConnectUDPTarget(target string) (string, string, error) {
	if !strings.HasPrefix(target, udpTargetPrefix) || !strings.HasSuffix(target, "/") {
		return "", "", errors.New("bad udp target prefix")
	}
	rest := strings.TrimSuffix(strings.TrimPrefix(target, udpTargetPrefix), "/")
	rawHost, rawPort, ok := strings.Cut(rest, "/")
	if !ok || strings.Contains(rawPort, "/") || rawHost == "" || rawPort == "" {
		return "", "", errors.New("bad udp target segments")
	}
	host, err := url.PathUnescape(rawHost)
	if err != nil || !isValidTargetHost(host) {
		return "", "", errors.New("bad escaped host")
	}
	port, err := url.PathUnescape(rawPort)
	if err != nil {
		return "", "", errors.New("bad escaped port")
	}
	if err := validatePort(port); err != nil {
		return "", "", err
	}
	return host, port, nil
}

func headerHasToken(headerVal, token string) bool {
	for part := range strings.SplitSeq(headerVal, ",") {
		if strings.EqualFold(strings.TrimSpace(part), token) {
			return true
		}
	}
	return false
}

func isDoHMediaType(contentType string) bool {
	mediaType, _, _ := strings.Cut(contentType, ";")
	return strings.EqualFold(strings.TrimSpace(mediaType), dohMediaType)
}

func sanitizeHeaderOutput(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := range len(s) {
		c := s[i]
		if c >= 0x20 && c < 0x7f {
			b.WriteByte(c)
		}
	}
	return b.String()
}

// writeH1Deny emits an RFC 9110 error response carrying an RFC 9209 Proxy-Status header.
func writeH1Deny(conn net.Conn, timeout time.Duration, status int, reason string) {
	_ = conn.SetWriteDeadline(time.Now().Add(timeout))
	text := http.StatusText(status)
	if text == "" {
		text = "Error"
	}
	proxyStatus := apis.FormatProxyStatus("dra-agents-net", status, reason)
	resp := fmt.Sprintf(
		"HTTP/1.1 %d %s\r\nProxy-Status: %s\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
		status, text, proxyStatus,
	)
	_, _ = io.WriteString(conn, resp)
}

func writeH1RawDeny(conn net.Conn, timeout time.Duration, status int, proxyStatus string) {
	_ = conn.SetWriteDeadline(time.Now().Add(timeout))
	text := http.StatusText(status)
	if text == "" {
		text = "Error"
	}
	cleanStatus := sanitizeHeaderOutput(proxyStatus)
	if cleanStatus == "" {
		cleanStatus = apis.FormatProxyStatus("dra-agents-net", status, "upstream-denied")
	}
	resp := fmt.Sprintf(
		"HTTP/1.1 %d %s\r\nProxy-Status: %s\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
		status, text, cleanStatus,
	)
	_, _ = io.WriteString(conn, resp)
}

type upstreamDeniedError struct {
	status      int
	proxyStatus string
	reason      string
}

func (e *upstreamDeniedError) Error() string {
	return fmt.Sprintf("upstream returned HTTP %d (%s)", e.status, e.reason)
}

type parsedUpstream struct {
	scheme  string // "https" or "unix"
	address string // host:port or socket path
	host    string // Host header value
}

func parseUpstreamAddress(raw string) (parsedUpstream, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return parsedUpstream{}, fmt.Errorf("parse upstream address %q: %w", raw, err)
	}
	switch u.Scheme {
	case "https":
		hostname := u.Hostname()
		if hostname == "" {
			return parsedUpstream{}, fmt.Errorf("upstream address %q missing host", raw)
		}
		port := u.Port()
		if port == "" {
			port = "443"
		}
		addr := net.JoinHostPort(hostname, port)
		return parsedUpstream{scheme: "https", address: addr, host: u.Host}, nil
	case "unix":
		sockPath := u.Path
		if sockPath == "" {
			sockPath = u.Opaque
		}
		if sockPath == "" {
			return parsedUpstream{}, fmt.Errorf("unix upstream address %q missing socket path", raw)
		}
		return parsedUpstream{scheme: "unix", address: sockPath, host: "localhost"}, nil
	default:
		return parsedUpstream{}, fmt.Errorf("unsupported upstream scheme %q (want https or unix; plaintext http is forbidden)", u.Scheme)
	}
}

// upstreamTunnel is an established bidirectional tunnel to the upstream agents.net proxy.
type upstreamTunnel struct {
	r     io.Reader
	w     io.WriteCloser
	close func()
}

var errALPNFallbackHTTP1 = errors.New("PEP negotiated non-h2 ALPN; falling back to HTTP/1.1")

// upstreamDialer opens authenticated CONNECT and RFC 9298 connect-udp tunnels to one
// configured Policy Enforcement Point (PEP), negotiating HTTP/2 vs HTTP/1.1 via TLS ALPN
// on https:// URLs and using HTTP/1.1 on http:// or unix:// URLs.
type upstreamDialer struct {
	target    parsedUpstream
	clientCfg *auth.ClientConfig
	dialTime  time.Duration
	dialNet   func(ctx context.Context, network, addr string) (net.Conn, error)

	mu       sync.Mutex
	closed   bool
	h2Tr     *http.Transport
	useH1    atomic.Bool
	useH1UDP atomic.Bool
}

func newUpstreamDialer(
	pep *apis.PolicyEnforcementPointConfig,
	clientCfg *auth.ClientConfig,
	dialTimeout time.Duration,
	dialNet func(ctx context.Context, network, addr string) (net.Conn, error),
) (*upstreamDialer, error) {
	parsed, err := parseUpstreamAddress(pep.URL)
	if err != nil {
		return nil, err
	}
	if dialNet == nil {
		dialNet = (&net.Dialer{Timeout: dialTimeout}).DialContext
	}
	return &upstreamDialer{
		target:    parsed,
		clientCfg: clientCfg,
		dialTime:  dialTimeout,
		dialNet:   dialNet,
	}, nil
}

func (u *upstreamDialer) negotiatedProtocol(isUDP bool) string {
	if u.target.scheme != "https" || u.useH1.Load() {
		return "HTTP1"
	}
	if isUDP && u.useH1UDP.Load() {
		return "HTTP1"
	}
	return "HTTP2"
}

func (u *upstreamDialer) Close() error {
	u.mu.Lock()
	u.closed = true
	tr := u.h2Tr
	u.h2Tr = nil
	u.mu.Unlock()
	if tr != nil {
		tr.CloseIdleConnections()
	}
	return u.clientCfg.Close()
}

func (u *upstreamDialer) getH2Transport() (*http.Transport, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.closed {
		return nil, errors.New("upstream dialer closed")
	}
	if u.h2Tr != nil {
		return u.h2Tr, nil
	}

	var tlsCfg *tls.Config
	if u.clientCfg != nil && u.clientCfg.TLSConfig != nil {
		tlsCfg = u.clientCfg.TLSConfig.Clone()
	} else {
		tlsCfg = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	if tlsCfg.ServerName == "" {
		if host, _, err := net.SplitHostPort(u.target.address); err == nil {
			tlsCfg.ServerName = host
		}
	}
	dialTLSBase := tlsCfg.Clone()
	dialTLSBase.NextProtos = []string{"h2", "http/1.1"}

	protos := new(http.Protocols)
	protos.SetHTTP2(true)

	u.h2Tr = &http.Transport{
		TLSClientConfig: tlsCfg,
		Protocols:       protos,
		DialTLSContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			rawConn, err := u.dialNet(ctx, network, u.target.address)
			if err != nil {
				return nil, err
			}
			tlsConn := tls.Client(rawConn, dialTLSBase.Clone())
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				_ = rawConn.Close()
				return nil, err
			}
			if tlsConn.ConnectionState().NegotiatedProtocol != "h2" {
				_ = tlsConn.Close()
				u.useH1.Store(true)
				return nil, errALPNFallbackHTTP1
			}
			return tlsConn, nil
		},
	}
	return u.h2Tr, nil
}

func (u *upstreamDialer) buildAuthHeaders(id auth.WorkloadIdentity) http.Header {
	return id.AttestedHeaders()
}

func (u *upstreamDialer) dialTCP(ctx context.Context, host, port string, id auth.WorkloadIdentity) (*upstreamTunnel, error) {
	hdrs := u.buildAuthHeaders(id)
	authority := net.JoinHostPort(host, port)

	// Over https://, prefer multiplexed HTTP/2 via TLS ALPN and transparently fall back
	// to HTTP/1.1 CONNECT if the PEP negotiates http/1.1 (or no ALPN).
	if u.target.scheme == "https" && !u.useH1.Load() {
		tun, err := u.dialH2Connect(ctx, authority, hdrs)
		if err == nil || !errors.Is(err, errALPNFallbackHTTP1) {
			return tun, err
		}
	}
	return u.dialH1Connect(ctx, authority, hdrs)
}

func (u *upstreamDialer) dialH2Connect(ctx context.Context, authority string, hdrs http.Header) (*upstreamTunnel, error) {
	tr, err := u.getH2Transport()
	if err != nil {
		return nil, err
	}

	pr, pw := io.Pipe()
	reqCtx, cancel := context.WithCancel(context.Background())
	// Propagate dial-phase cancellation/timeout into reqCtx, then detach once
	// RoundTrip succeeds so the live tunnel outlives the dial timeout.
	stopCancel := context.AfterFunc(ctx, cancel)

	req := (&http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Scheme: "https", Host: u.target.address},
		Host:   authority,
		Header: hdrs,
		Body:   pr,
	}).WithContext(reqCtx)

	resp, err := tr.RoundTrip(req)
	if !stopCancel() {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		cancel()
		_ = pw.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	if err != nil {
		cancel()
		_ = pw.Close()
		return nil, err
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		proxyStatus := resp.Header.Get("Proxy-Status")
		_ = resp.Body.Close()
		cancel()
		_ = pw.Close()
		return nil, &upstreamDeniedError{
			status:      resp.StatusCode,
			proxyStatus: proxyStatus,
			reason:      "upstream-denied",
		}
	}

	return &upstreamTunnel{
		r: resp.Body,
		w: pw,
		close: func() {
			cancel()
			_ = pw.Close()
			_ = resp.Body.Close()
		},
	}, nil
}

func (u *upstreamDialer) dialRawUpstreamConn(ctx context.Context, alpn []string) (net.Conn, error) {
	if u.target.scheme == "unix" {
		return u.dialNet(ctx, "unix", u.target.address)
	}
	rawConn, err := u.dialNet(ctx, "tcp", u.target.address)
	if err != nil {
		return nil, err
	}
	if u.target.scheme != "https" {
		return rawConn, nil
	}
	var tlsCfg *tls.Config
	if u.clientCfg != nil && u.clientCfg.TLSConfig != nil {
		tlsCfg = u.clientCfg.TLSConfig.Clone()
	} else {
		tlsCfg = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	if tlsCfg.ServerName == "" {
		host, _, err := net.SplitHostPort(u.target.address)
		if err == nil {
			tlsCfg.ServerName = host
		}
	}
	if len(alpn) > 0 {
		tlsCfg.NextProtos = alpn
	}
	tlsConn := tls.Client(rawConn, tlsCfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = rawConn.Close()
		return nil, err
	}
	return tlsConn, nil
}

func (u *upstreamDialer) dialH1Connect(ctx context.Context, authority string, hdrs http.Header) (*upstreamTunnel, error) {
	conn, err := u.dialRawUpstreamConn(ctx, []string{"http/1.1"})
	if err != nil {
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	stopCancel := context.AfterFunc(ctx, func() {
		_ = conn.SetDeadline(time.Now())
	})

	var reqBuf strings.Builder
	fmt.Fprintf(&reqBuf, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n", authority, authority)
	writeHTTPHeaders(&reqBuf, hdrs)
	reqBuf.WriteString("\r\n")
	if _, err := io.WriteString(conn, reqBuf.String()); err != nil {
		stopCancel()
		_ = conn.Close()
		return nil, err
	}

	limiter := &boundedReader{r: conn, remaining: maxHeadBytes}
	br := bufio.NewReader(limiter)
	resp, err := readFinalH1Response(br, &http.Request{Method: http.MethodConnect})
	if !stopCancel() {
		_ = conn.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	limiter.remaining = -1

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		proxyStatus := resp.Header.Get("Proxy-Status")
		_ = conn.Close()
		return nil, &upstreamDeniedError{
			status:      resp.StatusCode,
			proxyStatus: proxyStatus,
			reason:      "upstream-denied",
		}
	}

	return &upstreamTunnel{
		r:     br,
		w:     conn,
		close: func() { _ = conn.Close() },
	}, nil
}

// doDoH forwards one RFC 8484 DNS-over-HTTPS POST /dns-query request to the
// configured upstream PEP (reusing the multiplexed HTTP/2 mTLS transport when
// talking to https://, falling back to HTTP/1.1 for unix:// or non-h2 PEPs).
func (u *upstreamDialer) doDoH(ctx context.Context, query []byte, id auth.WorkloadIdentity) ([]byte, error) {
	hdrs := u.buildAuthHeaders(id)
	hdrs.Set("Content-Type", dohMediaType)
	hdrs.Set("Accept", dohMediaType)

	if u.target.scheme == "https" && !u.useH1.Load() {
		body, err := u.doH2DoH(ctx, query, hdrs)
		if err == nil || !errors.Is(err, errALPNFallbackHTTP1) {
			return body, err
		}
	}
	return u.doH1DoH(ctx, query, hdrs)
}

func (u *upstreamDialer) doH2DoH(ctx context.Context, query []byte, hdrs http.Header) ([]byte, error) {
	tr, err := u.getH2Transport()
	if err != nil {
		return nil, err
	}
	req := (&http.Request{
		Method:        http.MethodPost,
		URL:           &url.URL{Scheme: "https", Host: u.target.address, Path: dohPath},
		Host:          u.target.host,
		Header:        hdrs,
		ContentLength: int64(len(query)),
		Body:          io.NopCloser(bytes.NewReader(query)),
	}).WithContext(ctx)

	resp, err := tr.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, &upstreamDeniedError{
			status:      resp.StatusCode,
			proxyStatus: resp.Header.Get("Proxy-Status"),
			reason:      "upstream-denied",
		}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDoHBodyBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxDoHBodyBytes {
		return nil, fmt.Errorf("upstream DoH response exceeded %d bytes", maxDoHBodyBytes)
	}
	return body, nil
}

func (u *upstreamDialer) doH1DoH(ctx context.Context, query []byte, hdrs http.Header) ([]byte, error) {
	conn, err := u.dialRawUpstreamConn(ctx, []string{"http/1.1"})
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	stopCancel := context.AfterFunc(ctx, func() {
		_ = conn.SetDeadline(time.Now())
	})
	defer stopCancel()

	var reqBuf bytes.Buffer
	fmt.Fprintf(&reqBuf, "POST %s HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\nConnection: close\r\n", dohPath, u.target.host, len(query))
	var hsb strings.Builder
	writeHTTPHeaders(&hsb, hdrs)
	reqBuf.WriteString(hsb.String())
	reqBuf.WriteString("\r\n")
	reqBuf.Write(query)

	if _, err := conn.Write(reqBuf.Bytes()); err != nil {
		return nil, err
	}
	br := bufio.NewReader(conn)
	resp, err := readFinalH1Response(br, &http.Request{Method: http.MethodPost})
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, &upstreamDeniedError{
			status:      resp.StatusCode,
			proxyStatus: resp.Header.Get("Proxy-Status"),
			reason:      "upstream-denied",
		}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDoHBodyBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxDoHBodyBytes {
		return nil, fmt.Errorf("upstream DoH response exceeded %d bytes", maxDoHBodyBytes)
	}
	return body, nil
}

// readFinalH1Response skips non-101 1xx interim responses (RFC 9110 Section 15.2).
// 101 Switching Protocols is the final response for an upgrade and is returned.
func readFinalH1Response(br *bufio.Reader, req *http.Request) (*http.Response, error) {
	for interim := range maxInterimResponses + 1 {
		resp, err := http.ReadResponse(br, req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode < 100 || resp.StatusCode >= 200 || resp.StatusCode == http.StatusSwitchingProtocols {
			return resp, nil
		}
		if interim == maxInterimResponses {
			return nil, fmt.Errorf("upstream sent more than %d interim responses", maxInterimResponses)
		}
	}
	return nil, errors.New("unexpected interim response loop termination")
}

// dialUDP forwards an RFC 9298 connect-udp tunnel over the mTLS upstream transport.
// Over https://, it opens an HTTP/2 extended CONNECT (:protocol: connect-udp, RFC 8441)
// stream and falls back to HTTP/1.1 Upgrade: connect-udp when the PEP negotiates
// http/1.1 or does not advertise SETTINGS_ENABLE_CONNECT_PROTOCOL.
func (u *upstreamDialer) dialUDP(ctx context.Context, host, port string, id auth.WorkloadIdentity) (*upstreamTunnel, error) {
	hdrs := u.buildAuthHeaders(id)
	if u.target.scheme == "https" && !u.useH1.Load() && !u.useH1UDP.Load() {
		tun, err := u.dialH2ConnectUDP(ctx, host, port, hdrs)
		if err == nil {
			return tun, nil
		}
		if errors.Is(err, errALPNFallbackHTTP1) || errors.Is(err, errExtendedConnectNotSupported) {
			return u.dialH1ConnectUDP(ctx, host, port, hdrs)
		}
		return nil, err
	}
	return u.dialH1ConnectUDP(ctx, host, port, hdrs)
}

func (u *upstreamDialer) dialH1ConnectUDP(ctx context.Context, host, port string, hdrs http.Header) (*upstreamTunnel, error) {
	conn, err := u.dialRawUpstreamConn(ctx, []string{"http/1.1"})
	if err != nil {
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	stopCancel := context.AfterFunc(ctx, func() {
		_ = conn.SetDeadline(time.Now())
	})

	targetPath := fmt.Sprintf("%s%s/%s/", udpTargetPrefix, encodeConnectUDPHost(host), url.PathEscape(port))
	var reqBuf strings.Builder
	fmt.Fprintf(&reqBuf, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: connect-udp\r\nCapsule-Protocol: ?1\r\n", targetPath, u.target.host)
	writeHTTPHeaders(&reqBuf, hdrs)
	reqBuf.WriteString("\r\n")
	if _, err := io.WriteString(conn, reqBuf.String()); err != nil {
		stopCancel()
		_ = conn.Close()
		return nil, err
	}

	limiter := &boundedReader{r: conn, remaining: maxHeadBytes}
	br := bufio.NewReader(limiter)
	resp, err := readFinalH1Response(br, &http.Request{Method: http.MethodGet})
	if !stopCancel() {
		_ = conn.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	limiter.remaining = -1

	if resp.StatusCode != http.StatusSwitchingProtocols {
		proxyStatus := resp.Header.Get("Proxy-Status")
		_ = conn.Close()
		return nil, &upstreamDeniedError{
			status:      resp.StatusCode,
			proxyStatus: proxyStatus,
			reason:      "upstream-denied",
		}
	}
	if !headerHasToken(resp.Header.Get("Upgrade"), "connect-udp") || strings.TrimSpace(resp.Header.Get("Capsule-Protocol")) != "?1" {
		_ = conn.Close()
		return nil, errors.New("upstream 101 response missing Upgrade: connect-udp or Capsule-Protocol: ?1")
	}

	return &upstreamTunnel{
		r:     br,
		w:     conn,
		close: func() { _ = conn.Close() },
	}, nil
}

func writeHTTPHeaders(b *strings.Builder, hdrs http.Header) {
	for k, vals := range hdrs {
		if !isValidHTTPToken(k) {
			continue
		}
		for _, v := range vals {
			if !isSafeHeaderValue(v) {
				continue
			}
			fmt.Fprintf(b, "%s: %s\r\n", k, v)
		}
	}
}

type closeWriter interface {
	CloseWrite() error
}

type activityReader struct {
	io.Reader
	touch func()
	bytes *atomic.Int64
}

func (a activityReader) Read(p []byte) (int, error) {
	n, err := a.Reader.Read(p)
	if n > 0 {
		if a.bytes != nil {
			a.bytes.Add(int64(n))
		}
		a.touch()
	}
	return n, err
}

func startIdleWatch(idle time.Duration, onTimeout func()) (touch func(), cancel func()) {
	if idle <= 0 {
		return func() {}, func() {}
	}
	// Track monotonic elapsed nanoseconds since startTime so wall-clock NTP steps
	// never prematurely expire or stall idle timers.
	startTime := time.Now()
	var lastOffset atomic.Int64
	stop := make(chan struct{})
	var once sync.Once

	go func() {
		timer := time.NewTimer(idle)
		defer timer.Stop()
		for {
			select {
			case <-stop:
				return
			case <-timer.C:
				elapsed := time.Since(startTime) - time.Duration(lastOffset.Load())
				if elapsed >= idle {
					onTimeout()
					return
				}
				timer.Reset(idle - elapsed)
			}
		}
	}()

	touch = func() { lastOffset.Store(int64(time.Since(startTime))) }
	cancel = func() { once.Do(func() { close(stop) }) }
	return touch, cancel
}

func relayStream(clientR io.Reader, clientW io.Writer, up *upstreamTunnel, idle time.Duration, closeClient func()) (bytesOut, bytesIn int64) {
	var outN, inN atomic.Int64
	touch, cancel := startIdleWatch(idle, func() {
		up.close()
		closeClient()
	})
	defer cancel()

	var wg sync.WaitGroup
	wg.Go(func() {
		_, _ = io.Copy(up.w, activityReader{Reader: clientR, touch: touch, bytes: &outN})
		if cw, ok := up.w.(closeWriter); ok {
			_ = cw.CloseWrite()
		} else {
			_ = up.w.Close()
		}
	})
	_, _ = io.Copy(clientW, activityReader{Reader: up.r, touch: touch, bytes: &inN})
	closeClient()
	wg.Wait()
	return outN.Load(), inN.Load()
}
