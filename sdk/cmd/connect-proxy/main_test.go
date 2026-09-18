package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/aojea/agents.net/sdk/pkg/tun2connect"
)

func TestMain(tests *testing.M) {
	godebug := os.Getenv("GODEBUG")
	if !strings.Contains(godebug, "http2xconnect=1") {
		executable, err := os.Executable()
		if err == nil {
			syscall.Exec(executable, os.Args, append(os.Environ(), "GODEBUG="+godebug+",http2xconnect=1"))
		}
	}
	os.Exit(tests.Run())
}

func boundaryClient(t *testing.T, protocol string) tun2connect.Dialer {
	t.Helper()
	dial := func(ctx context.Context) (net.Conn, error) {
		client, server := net.Pipe()
		if protocol == "h1" {
			go serve(server)
		} else {
			go new(http2.Server).ServeConn(server, &http2.ServeConnOpts{Handler: serveH2(newSession(""))})
		}
		t.Cleanup(func() { client.Close(); server.Close() })
		return client, nil
	}
	if protocol == "h2" {
		return &tun2connect.BoundaryClientH2{DialBoundary: dial}
	}
	return &tun2connect.BoundaryClient{DialBoundary: dial}
}

func setResolver(t *testing.T, lookup func(ctx context.Context, network, host string) ([]netip.Addr, error)) {
	t.Helper()
	previous := lookupNetIP
	t.Cleanup(func() { lookupNetIP = previous })
	lookupNetIP = lookup
}

// captureAudit redirects audit records to a buffer for the test.
func captureAudit(t *testing.T) *bytes.Buffer {
	t.Helper()
	auditMu.Lock()
	previous := auditOut
	buffer := &bytes.Buffer{}
	auditOut = buffer
	auditMu.Unlock()
	t.Cleanup(func() { auditMu.Lock(); auditOut = previous; auditMu.Unlock() })
	return buffer
}

func TestBoundaryTLSConfig(t *testing.T) {
	for _, test := range []struct{ name, cert, key, ca string }{
		{"CA-without-TLS", "", "", "ca.pem"},
		{"certificate-only", "cert.pem", "", ""},
		{"key-only", "", "key.pem", ""},
		{"CA-and-key-only", "", "key.pem", "ca.pem"},
		{"missing-files", "missing.pem", "missing.key", ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			if config, err := boundaryTLSConfig(test.cert, test.key, test.ca); err == nil || config != nil {
				t.Fatalf("invalid TLS config accepted: %v, %v", config, err)
			}
		})
	}
	if config, err := boundaryTLSConfig("", "", ""); err != nil || config != nil {
		t.Fatalf("explicit local plaintext config: %v, %v", config, err)
	}
	certPath, keyPath := testTLSFiles(t)
	for _, clientCA := range []string{"", certPath} {
		config, err := boundaryTLSConfig(certPath, keyPath, clientCA)
		if err != nil {
			t.Fatal(err)
		}
		if config.MinVersion < tls.VersionTLS12 || len(config.Certificates) != 1 {
			t.Fatal("missing TLS minimum or certificate")
		}
		if clientCA != "" && (config.ClientAuth != tls.RequireAndVerifyClientCert || config.ClientCAs == nil) {
			t.Fatal("client CA must require verified client certificates")
		}
	}
	if _, err := boundaryTLSConfig(certPath, keyPath, keyPath); err == nil {
		t.Fatal("non-certificate client CA accepted")
	}
	if _, err := boundaryTLSConfig(certPath, certPath, ""); err == nil {
		t.Fatal("invalid private key accepted")
	}
}

func testTLSFiles(t *testing.T) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "boundary-test"},
		DNSNames: []string{"boundary"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage:    x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certificate, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	privateKey, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	certPath, keyPath := filepath.Join(directory, "cert.pem"), filepath.Join(directory, "key.pem")
	for path, block := range map[string]*pem.Block{
		certPath: {Type: "CERTIFICATE", Bytes: certificate},
		keyPath:  {Type: "PRIVATE KEY", Bytes: privateKey},
	} {
		if err := os.WriteFile(path, pem.EncodeToMemory(block), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return certPath, keyPath
}

func TestTunnelPayloadDoesNotGrantAuthority(t *testing.T) {
	setPolicy(t, policyJSON(`{"cidr":"127.0.0.1/32"}`, ""))
	for _, protocol := range []string{"h1", "h2"} {
		t.Run(protocol, func(t *testing.T) {
			upstream, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer upstream.Close()
			var connections atomic.Int32
			go func() {
				for {
					conn, err := upstream.Accept()
					if err != nil {
						return
					}
					connections.Add(1)
					go func() { defer conn.Close(); io.Copy(conn, conn) }()
				}
			}()
			client := boundaryClient(t, protocol)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			conn, err := client.DialTCP(ctx, "127.0.0.1", uint16(upstream.Addr().(*net.TCPAddr).Port))
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			stop := context.AfterFunc(ctx, func() { conn.Close() })
			defer stop()
			payload := "CONNECT 192.0.2.1:443 HTTP/1.1\r\nHost: 192.0.2.1:443\r\nSandbox-Id: forged-admin\r\nAuthorization: Bearer guest-value\r\n\r\n\x00opaque-data"
			if _, err := io.WriteString(conn, payload); err != nil {
				t.Fatal(err)
			}
			response := make([]byte, len(payload))
			if _, err := io.ReadFull(conn, response); err != nil || string(response) != payload {
				t.Fatalf("tunnel content was not passed unchanged: %q, %v", response, err)
			}
			_, err = client.DialTCP(ctx, "192.0.2.1", 443)
			var denial *tun2connect.DialError
			if !errors.As(err, &denial) || denial.StatusCode != http.StatusForbidden {
				t.Fatalf("payload changed boundary authorization: %v", err)
			}
			if connections.Load() != 1 {
				t.Fatalf("unexpected upstream connections: %d", connections.Load())
			}
		})
	}
}

// TestHostnameDialsCheckedAddress sends a hostname CONNECT and checks the
// boundary dials the resolved address it checked rather than the name.
func TestHostnameDialsCheckedAddress(t *testing.T) {
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	var connections atomic.Int32
	go func() {
		for {
			conn, err := upstream.Accept()
			if err != nil {
				return
			}
			connections.Add(1)
			go func() { defer conn.Close(); io.Copy(conn, conn) }()
		}
	}()
	port := uint16(upstream.Addr().(*net.TCPAddr).Port)
	setResolver(t, func(ctx context.Context, network, host string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	})
	for _, protocol := range []string{"h1", "h2"} {
		t.Run(protocol, func(t *testing.T) {
			client := boundaryClient(t, protocol)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			// Loopback is not public: without an exception the resolved address is denied.
			setPolicy(t, policyJSON(`{"name":"echo.example"},{"name":"rebound.example"}`, ""))
			_, err := client.DialTCP(ctx, "rebound.example", port)
			var refusal *tun2connect.DialError
			if !errors.As(err, &refusal) || refusal.StatusCode != http.StatusForbidden || refusal.Reason != "resolved-address-denied" {
				t.Fatalf("allowed name resolving to loopback must be denied: %v", err)
			}
			if connections.Load() != 0 {
				t.Fatal("denied name produced an upstream connection")
			}
			setPolicy(t, policyJSON(`{"name":"echo.example"},{"name":"rebound.example"}`, `,"resolved_addresses":[{"cidr":"127.0.0.1/32"}]`))
			conn, err := client.DialTCP(ctx, "echo.example", port)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			stop := context.AfterFunc(ctx, func() { conn.Close() })
			defer stop()
			if _, err := conn.Write([]byte("named")); err != nil {
				t.Fatal(err)
			}
			response := make([]byte, 5)
			if _, err := io.ReadFull(conn, response); err != nil || string(response) != "named" {
				t.Fatalf("echo = %q, err = %v", response, err)
			}
			connections.Store(0)
		})
	}
}

func TestRequestHeadDeadline(t *testing.T) {
	previous := headTimeout.Load()
	t.Cleanup(func() { headTimeout.Store(previous) })
	headTimeout.Store(50 * time.Millisecond)
	client, server := net.Pipe()
	defer client.Close()
	done := make(chan struct{})
	go func() { defer close(done); serve(server) }()
	// A client that never completes the request head must not hold the
	// handler indefinitely; net.Pipe honors deadlines.
	client.SetDeadline(time.Now().Add(time.Second))
	io.WriteString(client, "CONNECT ")
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("stalled request head kept the handler alive")
	}
}

func TestLiteralTCPThroughBoundary(t *testing.T) {
	setPolicy(t, policyJSON(`{"cidr":"127.0.0.1/32"},{"cidr":"::1/128"}`, ""))
	for _, host := range []string{"127.0.0.1", "::1"} {
		t.Run(host, func(t *testing.T) {
			upstream, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
			if err != nil {
				t.Fatal(err)
			}
			defer upstream.Close()
			go func() {
				for {
					conn, err := upstream.Accept()
					if err != nil {
						return
					}
					go func() { defer conn.Close(); io.Copy(conn, conn) }()
				}
			}()
			for _, protocol := range []string{"h1", "h2"} {
				t.Run(protocol, func(t *testing.T) {
					client := boundaryClient(t, protocol)
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					conn, err := client.DialTCP(ctx, host, uint16(upstream.Addr().(*net.TCPAddr).Port))
					if err != nil {
						t.Fatal(err)
					}
					defer conn.Close()
					stop := context.AfterFunc(ctx, func() { conn.Close() })
					defer stop()
					if _, err := conn.Write([]byte("literal")); err != nil {
						t.Fatal(err)
					}
					response := make([]byte, 7)
					if _, err := io.ReadFull(conn, response); err != nil || string(response) != "literal" {
						t.Fatalf("echo = %q, err = %v", response, err)
					}
					_, err = client.DialTCP(ctx, "192.0.2.1", 443)
					var refusal *tun2connect.DialError
					if !errors.As(err, &refusal) || refusal.StatusCode != http.StatusForbidden {
						t.Fatalf("unlisted IP should be denied: %v", err)
					}
				})
			}
		})
	}
}

func TestLiteralUDPThroughBoundary(t *testing.T) {
	setPolicy(t, policyJSON(`{"cidr":"127.0.0.1/32","transports":["tcp","udp"]},{"cidr":"::1/128","transports":["tcp","udp"]}`, `,"features":{"udp":true}`))
	for _, host := range []string{"127.0.0.1", "::1"} {
		t.Run(host, func(t *testing.T) {
			upstream, err := net.ListenPacket("udp", net.JoinHostPort(host, "0"))
			if err != nil {
				t.Fatal(err)
			}
			defer upstream.Close()
			go func() {
				buffer := make([]byte, 128)
				for {
					count, peer, err := upstream.ReadFrom(buffer)
					if err != nil {
						return
					}
					upstream.WriteTo(buffer[:count], peer)
				}
			}()
			for _, protocol := range []string{"h1", "h2"} {
				t.Run(protocol, func(t *testing.T) {
					client := boundaryClient(t, protocol)
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					session, err := client.DialUDP(ctx, host, uint16(upstream.LocalAddr().(*net.UDPAddr).Port))
					if err != nil {
						t.Fatal(err)
					}
					defer session.Close()
					stop := context.AfterFunc(ctx, func() { session.Close() })
					defer stop()
					if err := session.WriteDatagram([]byte("literal")); err != nil {
						t.Fatal(err)
					}
					response, err := session.ReadDatagram()
					if err != nil || string(response) != "literal" {
						t.Fatalf("UDP echo = %q, err = %v", response, err)
					}
					_, err = client.DialUDP(ctx, "192.0.2.1", 3478)
					var refusal *tun2connect.DialError
					if !errors.As(err, &refusal) || refusal.StatusCode != http.StatusForbidden {
						t.Fatalf("unlisted UDP IP should be denied: %v", err)
					}
				})
			}
		})
	}
}

// echoListener returns a TCP echo server and a counter of accepted connections.
func echoListener(t *testing.T) (net.Listener, *atomic.Int32) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var connections atomic.Int32
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			connections.Add(1)
			go func() { defer conn.Close(); io.Copy(conn, conn) }()
		}
	}()
	return ln, &connections
}

// TestAuditRecordsAreStructured checks that each decision is one JSON
// object carrying the listener-bound identity and that guest-controlled
// text cannot break the record apart.
func TestAuditRecordsAreStructured(t *testing.T) {
	previousListener, previousPolicy := listenerName, current.Load()
	t.Cleanup(func() { listenerName = previousListener; current.Store(previousPolicy) })
	listenerName = "unix:///run/a.sock"
	p, err := loadDescriptor([]byte(`{"agents_net_policy":1,"version":"v7","sandbox":"sandbox-a","default":"deny","rules":[{"id":"loop","cidr":"127.0.0.1/32"}]}`), "gen-3")
	if err != nil {
		t.Fatal(err)
	}
	current.Store(p)
	output := captureAudit(t)
	upstream, _ := echoListener(t)
	port := uint16(upstream.Addr().(*net.TCPAddr).Port)
	client := boundaryClient(t, "h1")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := client.DialTCP(ctx, "127.0.0.1", port)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	// Commas, semicolons, and equals signs are legal in an HTTP authority
	// and would split or spoof fields in a space- or comma-delimited log;
	// they are not hostname characters, so the request is malformed.
	// Quotes and control characters are rejected by the HTTP parser and
	// never reach the record.
	hostile := "evil,decision=allow;address=203.0.113.1.example"
	if _, err := client.DialTCP(ctx, hostile, 443); err == nil {
		t.Fatal("hostile name was allowed")
	}
	// Records are written when the decision is made; the allow record may
	// still be in flight when DialTCP returns, so wait briefly.
	var lines []string
	for range 50 {
		lines = strings.Split(strings.TrimSpace(output.String()), "\n")
		if len(lines) >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(lines) != 2 {
		t.Fatalf("want 2 records, got %d: %q", len(lines), output.String())
	}
	var records []auditRecord
	for _, line := range lines {
		var record auditRecord
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatalf("record is not one JSON object: %q: %v", line, err)
		}
		if record.Sandbox != "sandbox-a" || record.Policy != "v7" || record.Generation != "gen-3" || record.Listener != "unix:///run/a.sock" || record.Wire != "h1" || record.Transport != "tcp" || record.Time == "" {
			t.Fatalf("missing listener-bound fields: %+v", record)
		}
		records = append(records, record)
	}
	if records[0].Decision != "allow" || records[0].Rule != "loop" || records[0].Address != upstream.Addr().String() || records[0].Destination != net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))) {
		t.Fatalf("allow record: %+v", records[0])
	}
	if records[1].Decision != "block" || records[1].Reason != "malformed-target" || records[1].Destination != hostile+":443" {
		t.Fatalf("block record did not preserve the hostile destination as data: %+v", records[1])
	}
}

// TestConnectionBudget checks that connections over -max-connections are
// refused with 503 before their request head is read and that a slot is
// released when its connection ends.
func TestConnectionBudget(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "b.sock")
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go serveListener(ln, false, 1, 1)
	captureAudit(t)

	first, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	second.SetReadDeadline(time.Now().Add(5 * time.Second))
	response, err := http.ReadResponse(bufio.NewReader(second), nil)
	if err != nil || response.StatusCode != http.StatusServiceUnavailable || tun2connect.ProxyStatusReason(response.Header) != "busy" {
		t.Fatalf("second connection: %v, %v", response, err)
	}
	first.Close()
	// The slot is released asynchronously; retry until a third connection
	// is served (405 for a non-CONNECT request proves it reached serve).
	deadline := time.Now().Add(5 * time.Second)
	for {
		third, err := net.Dial("unix", socket)
		if err != nil {
			t.Fatal(err)
		}
		third.SetDeadline(time.Now().Add(5 * time.Second))
		io.WriteString(third, "GET / HTTP/1.1\r\nHost: boundary\r\n\r\n")
		response, err := http.ReadResponse(bufio.NewReader(third), nil)
		third.Close()
		if err == nil && response.StatusCode == http.StatusMethodNotAllowed {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("slot never released: %v, %v", response, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestIdleTunnelIsClosed checks that a tunnel with no traffic in either
// direction is closed after -idle-timeout on both wires, while an active
// tunnel survives.
func TestIdleTunnelIsClosed(t *testing.T) {
	previous := idleTimeout.Load()
	t.Cleanup(func() { idleTimeout.Store(previous) })
	idleTimeout.Store(100 * time.Millisecond)
	setPolicy(t, policyJSON(`{"cidr":"127.0.0.1/32"}`, ""))
	upstream, _ := echoListener(t)
	port := uint16(upstream.Addr().(*net.TCPAddr).Port)
	for _, protocol := range []string{"h1", "h2"} {
		t.Run(protocol, func(t *testing.T) {
			client := boundaryClient(t, protocol)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			conn, err := client.DialTCP(ctx, "127.0.0.1", port)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			buffer := make([]byte, 1)
			// Traffic every 40ms keeps a 100ms idle tunnel open.
			for range 5 {
				if _, err := conn.Write([]byte("k")); err != nil {
					t.Fatal(err)
				}
				conn.SetReadDeadline(time.Now().Add(time.Second))
				if _, err := io.ReadFull(conn, buffer); err != nil {
					t.Fatalf("active tunnel was closed: %v", err)
				}
				time.Sleep(40 * time.Millisecond)
			}
			conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			start := time.Now()
			if _, err := conn.Read(buffer); err == nil {
				t.Fatal("idle tunnel delivered data")
			} else if errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("idle tunnel still open after %s", time.Since(start))
			}
		})
	}
}
