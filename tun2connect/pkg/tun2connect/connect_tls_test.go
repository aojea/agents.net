package tun2connect

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

// mintPKI builds a throwaway CA, a server cert for "boundary", and a
// client cert asserting a deliberately non-SPIFFE URI: the identity
// scheme is the deployment's business, never this library's.
func mintPKI(t *testing.T) (pool *x509.CertPool, server, client tls.Certificate) {
	t.Helper()
	return mintPKIWithTemplates(t, nil, nil)
}

func mintPKIWithTemplates(t *testing.T, changeServer, changeClient func(*x509.Certificate)) (pool *x509.CertPool, server, client tls.Certificate) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	mint := func(tmpl *x509.Certificate) tls.Certificate {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	}
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		DNSNames:     []string{"boundary"},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	if changeServer != nil {
		changeServer(serverTemplate)
	}
	server = mint(serverTemplate)
	sandboxID, err := url.Parse("sandbox://tenant-a/agent-123")
	if err != nil {
		t.Fatal(err)
	}
	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		URIs:         []*url.URL{sandboxID},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	if changeClient != nil {
		changeClient(clientTemplate)
	}
	client = mint(clientTemplate)
	pool = x509.NewCertPool()
	pool.AddCert(caCert)
	return pool, server, client
}

// mtlsBoundary is an in-process mTLS+h2 boundary recording the peer's
// certificate URI, echoing every CONNECT stream.
type mtlsBoundary struct {
	addr    string
	mu      sync.Mutex
	peer    string
	tunnels int
}

func startMTLSBoundary(t *testing.T, pool *x509.CertPool, server tls.Certificate) *mtlsBoundary {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{server},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		NextProtos:   []string{"h2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	b := &mtlsBoundary{addr: ln.Addr().String()}
	h2s := &http2.Server{}
	handler := func(w http.ResponseWriter, r *http.Request) {
		b.mu.Lock()
		b.tunnels++
		b.mu.Unlock()
		f := w.(http.Flusher)
		w.WriteHeader(http.StatusOK)
		f.Flush()
		io.Copy(h2FlushWriter{w, f}, r.Body)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				tc := c.(*tls.Conn)
				if err := tc.HandshakeContext(context.Background()); err != nil {
					tc.Close()
					return
				}
				// CONNECT streams carry no :scheme, so x/net never sets
				// r.TLS for them -- identity is a session property, read
				// it from the handshake, not the request.
				if certs := tc.ConnectionState().PeerCertificates; len(certs) > 0 && len(certs[0].URIs) > 0 {
					b.mu.Lock()
					b.peer = certs[0].URIs[0].String()
					b.mu.Unlock()
				}
				h2s.ServeConn(tc, &http2.ServeConnOpts{Handler: http.HandlerFunc(handler)})
			}()
		}
	}()
	return b
}

func tcpDialer(addr string) func(ctx context.Context) (net.Conn, error) {
	return func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", addr)
	}
}

func TestH2MutualTLSCarriesDeploymentIdentity(t *testing.T) {
	pool, server, client := mintPKI(t)
	b := startMTLSBoundary(t, pool, server)

	c := &BoundaryClientH2{
		DialBoundary: tcpDialer(b.addr),
		Header: http.Header{
			"Sandbox-Id":    {"forged-admin"},
			"X-Dome-Tenant": {"forged-admin"},
		},
		TLS: &tls.Config{
			RootCAs:      pool,
			Certificates: []tls.Certificate{client},
			ServerName:   "boundary",
		},
	}
	conn, err := c.DialTCP(context.Background(), "api.example", 443)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "ping" {
		t.Fatalf("echo = %q", buf)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.peer != "sandbox://tenant-a/agent-123" {
		t.Fatalf("boundary saw peer %q, want the deployment's own URI scheme", b.peer)
	}
}

func TestH2MutualTLSRejectsAnonymousClient(t *testing.T) {
	pool, server, _ := mintPKI(t)
	b := startMTLSBoundary(t, pool, server)

	c := &BoundaryClientH2{
		DialBoundary: tcpDialer(b.addr),
		TLS:          &tls.Config{RootCAs: pool, ServerName: "boundary"}, // no client cert
	}
	if _, err := c.DialTCP(context.Background(), "api.example", 443); err == nil {
		t.Fatal("a client without a certificate must not reach the boundary")
	}
}

func TestH2MutualTLSRejectsInvalidPeers(t *testing.T) {
	expired := func(cert *x509.Certificate) {
		cert.NotBefore = time.Now().Add(-2 * time.Hour)
		cert.NotAfter = time.Now().Add(-time.Hour)
	}
	future := func(cert *x509.Certificate) {
		cert.NotBefore = time.Now().Add(time.Hour)
		cert.NotAfter = time.Now().Add(2 * time.Hour)
	}
	for _, test := range []struct {
		name           string
		serverTemplate func(*x509.Certificate)
		clientTemplate func(*x509.Certificate)
		clientConfig   func(*tls.Config)
	}{
		{name: "wrong-server-name", clientConfig: func(config *tls.Config) { config.ServerName = "other-boundary" }},
		{name: "untrusted-server", clientConfig: func(config *tls.Config) { config.RootCAs = x509.NewCertPool() }},
		{name: "expired-server", serverTemplate: expired},
		{name: "future-server", serverTemplate: future},
		{name: "wrong-server-usage", serverTemplate: func(cert *x509.Certificate) { cert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth} }},
		{name: "expired-client", clientTemplate: expired},
		{name: "future-client", clientTemplate: future},
		{name: "wrong-client-usage", clientTemplate: func(cert *x509.Certificate) { cert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth} }},
		{name: "untrusted-client", clientConfig: func(config *tls.Config) {
			_, _, rogue := mintPKI(t)
			config.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &rogue, nil }
		}},
		{name: "wrong-client-key", clientConfig: func(config *tls.Config) {
			_, _, other := mintPKI(t)
			config.Certificates[0].PrivateKey = other.PrivateKey
		}},
		{name: "wrong-alpn", clientConfig: func(config *tls.Config) { config.NextProtos = []string{"http/1.1"} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			pool, server, client := mintPKIWithTemplates(t, test.serverTemplate, test.clientTemplate)
			boundary := startMTLSBoundary(t, pool, server)
			config := &tls.Config{RootCAs: pool, Certificates: []tls.Certificate{client}, ServerName: "boundary"}
			if test.clientConfig != nil {
				test.clientConfig(config)
			}
			adapter := &BoundaryClientH2{DialBoundary: tcpDialer(boundary.addr), TLS: config}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			conn, err := adapter.DialTCP(ctx, "api.example", 443)
			if err == nil {
				conn.Close()
				t.Fatal("invalid TLS peer established a tunnel")
			}
			if ctx.Err() != nil {
				t.Fatalf("authentication timed out instead of rejecting: %v", err)
			}
			boundary.mu.Lock()
			defer boundary.mu.Unlock()
			if boundary.tunnels != 0 {
				t.Fatalf("invalid TLS peer reached %d tunnel handlers", boundary.tunnels)
			}
		})
	}
}

type corruptingConn struct {
	net.Conn
	armed     atomic.Bool
	corrupted atomic.Bool
}

func (conn *corruptingConn) Write(packet []byte) (int, error) {
	if len(packet) > 5 && conn.armed.CompareAndSwap(true, false) {
		packet = append([]byte(nil), packet...)
		packet[len(packet)-1] ^= 1
		conn.corrupted.Store(true)
	}
	return conn.Conn.Write(packet)
}

func TestH2MutualTLSRejectsModifiedRecords(t *testing.T) {
	pool, server, client := mintPKI(t)
	boundary := startMTLSBoundary(t, pool, server)
	var transport *corruptingConn
	adapter := &BoundaryClientH2{
		DialBoundary: func(ctx context.Context) (net.Conn, error) {
			conn, err := tcpDialer(boundary.addr)(ctx)
			if err != nil {
				return nil, err
			}
			transport = &corruptingConn{Conn: conn}
			return transport, nil
		},
		TLS: &tls.Config{RootCAs: pool, Certificates: []tls.Certificate{client}, ServerName: "boundary"},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	stream, err := adapter.DialTCP(ctx, "api.example", 443)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	defer transport.Close()
	transport.armed.Store(true)
	result := make(chan error, 1)
	go func() {
		if _, err := stream.Write([]byte("must-not-be-delivered")); err != nil {
			result <- err
			return
		}
		buffer := make([]byte, 64)
		count, err := stream.Read(buffer)
		if count != 0 {
			result <- nil
			return
		}
		result <- err
	}()
	select {
	case err := <-result:
		if err == nil || !transport.corrupted.Load() {
			t.Fatalf("modified TLS record was not rejected: corrupted=%v err=%v", transport.corrupted.Load(), err)
		}
	case <-ctx.Done():
		t.Fatal("modified TLS record did not terminate the tunnel promptly")
	}
}
