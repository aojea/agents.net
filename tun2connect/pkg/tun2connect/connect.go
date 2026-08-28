package tun2connect

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
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
	// tracing -- the extension point SOCKS5 never had.
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
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		conn.Close()
		return nil, nil, nil, err
	}
	conn.SetDeadline(time0)
	return conn, br, resp, nil
}

// DialTCP opens `CONNECT name:port` and returns the raw tunnel.
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
	if resp.StatusCode != http.StatusOK {
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
		URL: &url.URL{
			Scheme: "http",
			Host:   c.authority(),
			// The default connect-udp URI template (RFC 9298 section 2).
			Path: fmt.Sprintf("/.well-known/masque/udp/%s/%d/", url.PathEscape(name), port),
		},
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

func refusal(resp *http.Response) error {
	return &DialError{
		StatusCode: resp.StatusCode,
		Status:     resp.Status,
		Reason:     resp.Header.Get("Boundary-Reason"),
	}
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
