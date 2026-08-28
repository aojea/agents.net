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
	"testing"
	"time"

	"golang.org/x/net/http2"
)

// mintPKI builds a throwaway CA, a server cert for "boundary", and a
// client cert asserting a deliberately non-SPIFFE URI: the identity
// scheme is the deployment's business, never this library's.
func mintPKI(t *testing.T) (pool *x509.CertPool, server, client tls.Certificate) {
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
	server = mint(&x509.Certificate{
		SerialNumber: big.NewInt(2),
		DNSNames:     []string{"boundary"},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	})
	sandboxID, err := url.Parse("sandbox://tenant-a/agent-123")
	if err != nil {
		t.Fatal(err)
	}
	client = mint(&x509.Certificate{
		SerialNumber: big.NewInt(3),
		URIs:         []*url.URL{sandboxID},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	})
	pool = x509.NewCertPool()
	pool.AddCert(caCert)
	return pool, server, client
}

// mtlsBoundary is an in-process mTLS+h2 boundary recording the peer's
// certificate URI, echoing every CONNECT stream.
type mtlsBoundary struct {
	addr string
	mu   sync.Mutex
	peer string
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
