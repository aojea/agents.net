package tun2connect

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"golang.org/x/net/http2"
)

// BoundaryClientH2 multiplexes every flow over ONE HTTP/2 session to the
// boundary: each TCP flow is a CONNECT stream, each UDP session an
// extended CONNECT stream (:protocol connect-udp, RFC 9298 section 3.4)
// carrying capsules. This is the HBONE-shaped wire: over a Unix socket
// or vsock the whole sandbox costs one boundary connection, and adding
// mTLS to the same session is a transport concern, not a protocol one.
//
// The session is cleartext h2 with prior knowledge -- no TLS, no ALPN,
// no h1 upgrade -- which both x/net and Envoy-family dataplanes accept.
type BoundaryClientH2 struct {
	// DialBoundary opens the transport carrying the shared session.
	DialBoundary func(ctx context.Context) (net.Conn, error)
	// Authority is the :authority for extended CONNECT requests;
	// defaults to "boundary".
	Authority string
	// Header is copied into every tunnel request.
	Header http.Header

	mu sync.Mutex
	t  *http2.Transport
	cc *http2.ClientConn
}

func (c *BoundaryClientH2) authority() string {
	if c.Authority != "" {
		return c.Authority
	}
	return "boundary"
}

// session returns the shared ClientConn, dialing a fresh one if the
// previous session died or cannot take another stream.
func (c *BoundaryClientH2) session(ctx context.Context) (*http2.ClientConn, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cc != nil && c.cc.CanTakeNewRequest() {
		return c.cc, nil
	}
	if c.t == nil {
		c.t = &http2.Transport{
			AllowHTTP:       true,
			ReadIdleTimeout: 30 * time.Second, // h2 PING keepalive on an idle boundary
		}
	}
	nc, err := c.DialBoundary(ctx)
	if err != nil {
		return nil, err
	}
	cc, err := c.t.NewClientConn(nc)
	if err != nil {
		nc.Close()
		return nil, err
	}
	c.cc = cc
	return cc, nil
}

func (c *BoundaryClientH2) roundTrip(ctx context.Context, req *http.Request) (*http.Response, *io.PipeWriter, context.CancelFunc, error) {
	cc, err := c.session(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	pr, pw := io.Pipe()
	req.Body = pr
	for k, vs := range c.Header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	// The stream must outlive the caller's dial context (it lives as
	// long as the flow), so bind it to its own context and only abort
	// it via ctx while the handshake is still in flight.
	streamCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	stop := context.AfterFunc(ctx, cancel)
	resp, err := cc.RoundTrip(req.WithContext(streamCtx))
	stop()
	if err != nil {
		cancel()
		pw.Close()
		return nil, nil, nil, err
	}
	// h2 CONNECT success is any 2xx (RFC 9110 9.3.6, RFC 8441).
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		err := refusal(resp)
		cancel()
		pw.Close()
		resp.Body.Close()
		return nil, nil, nil, err
	}
	return resp, pw, cancel, nil
}

// DialTCP opens one CONNECT stream on the shared session.
func (c *BoundaryClientH2) DialTCP(ctx context.Context, name string, port uint16) (net.Conn, error) {
	hostport := net.JoinHostPort(name, strconv.Itoa(int(port)))
	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Scheme: "http", Host: hostport},
		Host:   hostport,
		Header: make(http.Header),
	}
	resp, pw, cancel, err := c.roundTrip(ctx, req)
	if err != nil {
		return nil, err
	}
	return &h2Stream{r: resp.Body, w: pw, cancel: cancel}, nil
}

// DialUDP opens one extended CONNECT stream (:protocol connect-udp).
func (c *BoundaryClientH2) DialUDP(ctx context.Context, name string, port uint16) (DatagramConn, error) {
	req := &http.Request{
		Method: http.MethodConnect,
		URL: &url.URL{
			Scheme: "http",
			Host:   c.authority(),
			Path:   fmt.Sprintf("/.well-known/masque/udp/%s/%d/", url.PathEscape(name), port),
		},
		Host:   c.authority(),
		Header: make(http.Header),
	}
	req.Header.Set(":protocol", "connect-udp")
	req.Header.Set("Capsule-Protocol", "?1")
	resp, pw, cancel, err := c.roundTrip(ctx, req)
	if err != nil {
		return nil, err
	}
	stream := &h2Stream{r: resp.Body, w: pw, cancel: cancel}
	return &capsuleConn{CapsuleStream: NewCapsuleStream(stream), conn: stream}, nil
}

// h2Stream adapts one CONNECT stream to net.Conn: reads come from the
// response body, writes go out as DATA frames via the request body pipe.
type h2Stream struct {
	r      io.ReadCloser
	w      *io.PipeWriter
	cancel context.CancelFunc
}

func (s *h2Stream) Read(p []byte) (int, error)  { return s.r.Read(p) }
func (s *h2Stream) Write(p []byte) (int, error) { return s.w.Write(p) }

// CloseWrite half-closes the stream (END_STREAM) but keeps reading.
func (s *h2Stream) CloseWrite() error { return s.w.Close() }

func (s *h2Stream) Close() error {
	s.w.Close()
	err := s.r.Close()
	s.cancel()
	return err
}

func (s *h2Stream) LocalAddr() net.Addr              { return h2Addr{} }
func (s *h2Stream) RemoteAddr() net.Addr             { return h2Addr{} }
func (s *h2Stream) SetDeadline(time.Time) error      { return nil }
func (s *h2Stream) SetReadDeadline(time.Time) error  { return nil }
func (s *h2Stream) SetWriteDeadline(time.Time) error { return nil }

type h2Addr struct{}

func (h2Addr) Network() string { return "h2" }
func (h2Addr) String() string  { return "h2-stream" }
