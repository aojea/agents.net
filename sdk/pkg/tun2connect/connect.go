package tun2connect

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// BoundaryClient dials tunnels over HTTP/1.1, one boundary connection
// per flow: authority-form CONNECT for TCP, and the connect-udp upgrade
// (RFC 9298) for UDP. The transport is whatever DialBoundary returns --
// a Unix socket, vsock, or TCP connection.
type BoundaryClient struct {
	// DialBoundary opens the stream to the boundary for one flow.
	DialBoundary func(ctx context.Context) (net.Conn, error)
	// Authority is the Host header naming the boundary; defaults to
	// "boundary" (over a Unix socket there is no real authority).
	Authority string
	// Header is copied into every tunnel request: sandbox identity,
	// tracing -- the wire's extension point.
	Header http.Header
}

func (c *BoundaryClient) authority() string {
	if c.Authority != "" {
		return c.Authority
	}
	return "boundary"
}

func (c *BoundaryClient) roundTrip(ctx context.Context, req *http.Request) (net.Conn, *bufio.Reader, *http.Response, error) {
	conn, err := c.DialBoundary(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	if d, ok := ctx.Deadline(); ok {
		conn.SetDeadline(d)
	}
	for k, vs := range c.Header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	if err := req.Write(conn); err != nil {
		conn.Close()
		return nil, nil, nil, err
	}
	br := bufio.NewReader(conn)
	resp, err := readFinalResponse(br, req)
	if err != nil {
		conn.Close()
		return nil, nil, nil, err
	}
	conn.SetDeadline(time0)
	return conn, br, resp, nil
}

// readFinalResponse skips 1xx interim responses (RFC 9110 15.2). 101 is
// the final response of an upgrade and is returned.
func readFinalResponse(br *bufio.Reader, req *http.Request) (*http.Response, error) {
	for interim := 0; ; interim++ {
		resp, err := http.ReadResponse(br, req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode < 100 || resp.StatusCode >= 200 || resp.StatusCode == http.StatusSwitchingProtocols {
			return resp, nil
		}
		if interim >= maxInterimResponses {
			return nil, fmt.Errorf("boundary sent more than %d interim responses", maxInterimResponses)
		}
	}
}

// maxInterimResponses bounds how many 1xx responses precede the final one.
const maxInterimResponses = 8

// DialTCP opens CONNECT to a hostname or IP address and returns the raw tunnel.
func (c *BoundaryClient) DialTCP(ctx context.Context, name string, port uint16) (net.Conn, error) {
	hostport := net.JoinHostPort(name, strconv.Itoa(int(port)))
	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Host: hostport},
		Host:   hostport,
		Header: make(http.Header),
	}
	conn, br, resp, err := c.roundTrip(ctx, req)
	if err != nil {
		return nil, err
	}
	// CONNECT success is any 2xx (RFC 9110 9.3.6).
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		conn.Close()
		return nil, refusal(resp)
	}
	return &bufConn{Conn: conn, br: br}, nil
}

// DialUDP opens a connect-udp tunnel (HTTP/1.1 upgrade form) and
// returns the capsule-framed session.
func (c *BoundaryClient) DialUDP(ctx context.Context, name string, port uint16) (DatagramConn, error) {
	req := &http.Request{
		Method: http.MethodGet,
		URL:    udpProxyURL(c.authority(), name, port),
		Host:   c.authority(),
		Header: make(http.Header),
	}
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "connect-udp")
	req.Header.Set("Capsule-Protocol", "?1")
	conn, br, resp, err := c.roundTrip(ctx, req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusSwitchingProtocols || resp.Header.Get("Upgrade") != "connect-udp" {
		conn.Close()
		return nil, refusal(resp)
	}
	return &capsuleConn{CapsuleStream: NewCapsuleStream(&bufConn{Conn: conn, br: br}), conn: conn}, nil
}

func udpProxyURL(authority, host string, port uint16) *url.URL {
	encodedHost := strings.ReplaceAll(url.PathEscape(host), ":", "%3A")
	return &url.URL{
		Scheme:  "http",
		Host:    authority,
		Path:    fmt.Sprintf("/.well-known/masque/udp/%s/%d/", host, port),
		RawPath: fmt.Sprintf("/.well-known/masque/udp/%s/%d/", encodedHost, port),
	}
}

func refusal(resp *http.Response) error {
	return &DialError{
		StatusCode: resp.StatusCode,
		Status:     resp.Status,
		Reason:     ProxyStatusReason(resp.Header),
	}
}

// ProxyStatusReason returns the reason parameter of the first Proxy-Status
// member (RFC 9209), or "" when the boundary sent none.
func ProxyStatusReason(h http.Header) string {
	member := strings.Split(h.Get("Proxy-Status"), ",")[0]
	for _, param := range strings.Split(member, ";")[1:] {
		if key, value, ok := strings.Cut(strings.TrimSpace(param), "="); ok && key == "reason" {
			return strings.Trim(value, `"`)
		}
	}
	return ""
}

// ProxyStatus builds the Proxy-Status field value for a refusal: one
// member naming the responder, the RFC 9209 error type for the reason
// token, and the token itself (spec/draft/wire.md Section 4).
func ProxyStatus(member, reason string) string {
	return member + "; error=" + ProxyErrorType(reason) + "; reason=" + reason
}

// ProxyErrorType maps a registered reason token to its RFC 9209 proxy error
// type (spec/draft/registries.md Section 2).
func ProxyErrorType(reason string) string {
	switch reason {
	case "not-on-allowlist", "port-not-allowed", "transport-not-allowed", "udp-disabled", "identity-unknown", "port-not-permitted":
		return "http_request_denied"
	case "ip-not-on-allowlist", "resolved-address-denied", "scoped-ip":
		return "destination_ip_prohibited"
	case "resolve-failed":
		return "dns_error"
	case "dial-failed":
		return "destination_unavailable"
	case "busy":
		return "connection_limit_reached"
	case "policy-unavailable":
		return "proxy_configuration_error"
	case "unsupported-version":
		return "http_protocol_error"
	}
	return "http_request_error"
}

// bufConn keeps bytes the response reader buffered past the header.
type bufConn struct {
	net.Conn
	br *bufio.Reader
}

func (c *bufConn) Read(p []byte) (int, error) { return c.br.Read(p) }

func (c *bufConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Conn.Close()
}

type capsuleConn struct {
	*CapsuleStream
	conn net.Conn
}

func (c *capsuleConn) Close() error { return c.conn.Close() }
