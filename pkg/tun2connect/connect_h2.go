package tun2connect

import (
	"bytes"
	"context"
	"crypto/tls"
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
// carrying capsules.
//
// Without TLS the session is cleartext h2 with prior knowledge. With TLS
// set it is h2 CONNECT inside (m)TLS -- the arrangement mesh dataplanes
// terminate (Istio's HBONE being one deployment of it).
type BoundaryClientH2 struct {
	// DialBoundary opens the transport carrying the shared session.
	DialBoundary func(ctx context.Context) (net.Conn, error)
	// TLS, when set, wraps the boundary transport in (m)TLS with ALPN
	// h2 before the session starts. What the certificates assert --
	// SPIFFE IDs, plain hostnames, anything else -- is between the
	// deployment's PKI and the boundary; this library never inspects it.
	TLS *tls.Config
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
	if c.TLS != nil {
		cfg := c.TLS.Clone()
		if len(cfg.NextProtos) == 0 {
			cfg.NextProtos = []string{"h2"}
		}
		if cfg.ServerName == "" && !cfg.InsecureSkipVerify {
			cfg.ServerName = c.authority()
		}
		tc := tls.Client(nc, cfg)
		if err := tc.HandshakeContext(ctx); err != nil {
			nc.Close()
			return nil, fmt.Errorf("tun2connect: boundary TLS handshake: %w", err)
		}
		if proto := tc.ConnectionState().NegotiatedProtocol; proto != "h2" {
			tc.Close()
			return nil, fmt.Errorf("tun2connect: boundary negotiated %q, want h2", proto)
		}
		nc = tc
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
		URL:    udpProxyURL(c.authority(), name, port),
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

// QueryDoH sends one RFC 8484 DNS-over-HTTPS POST /dns-query request over the
// shared HTTP/2 boundary session and returns the raw DNS wire response.
func (c *BoundaryClientH2) QueryDoH(ctx context.Context, query []byte) ([]byte, error) {
	if len(query) == 0 || len(query) > maxDoHBytes {
		return nil, fmt.Errorf("tun2connect: invalid DoH query size %d", len(query))
	}
	cc, err := c.session(ctx)
	if err != nil {
		return nil, err
	}
	scheme := "http"
	if c.TLS != nil {
		scheme = "https"
	}
	req := (&http.Request{
		Method:        http.MethodPost,
		URL:           &url.URL{Scheme: scheme, Host: c.authority(), Path: "/dns-query"},
		Host:          c.authority(),
		Header:        make(http.Header),
		ContentLength: int64(len(query)),
		Body:          io.NopCloser(bytes.NewReader(query)),
	}).WithContext(ctx)
	for k, vs := range c.Header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	req.Header.Set("Content-Type", dohMediaType)
	req.Header.Set("Accept", dohMediaType)

	resp, err := cc.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, refusal(resp)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDoHBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxDoHBytes {
		return nil, fmt.Errorf("tun2connect: DoH response exceeds %d bytes", maxDoHBytes)
	}
	return body, nil
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
