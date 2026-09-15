package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/aojea/agents.net/tun2connect/pkg/tun2connect"
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
			go new(http2.Server).ServeConn(server, &http2.ServeConnOpts{Handler: serveH2("")})
		}
		t.Cleanup(func() { client.Close(); server.Close() })
		return client, nil
	}
	if protocol == "h2" {
		return &tun2connect.BoundaryClientH2{DialBoundary: dial}
	}
	return &tun2connect.BoundaryClient{DialBoundary: dial}
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
	previousIPs := allowedIPs
	t.Cleanup(func() { allowedIPs = previousIPs })
	allowedIPs = []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}
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

func TestIPAllowlist(t *testing.T) {
	previousIPs, previousAll, previousNames := allowedIPs, allowAll, allowed
	t.Cleanup(func() { allowedIPs, allowAll, allowed = previousIPs, previousAll, previousNames })
	allowed = map[string]bool{"api.example": true}
	allowAll = true
	allowedIPs = nil
	if _, ok := authorize("127.0.0.1"); ok {
		t.Fatal("hostname wildcard must not authorize literal addresses")
	}
	allowAll = false
	var err error
	allowedIPs, err = parseIPAllowlist("192.0.2.1, 198.51.100.19/24, 2001:db8::/64, ::ffff:203.0.113.0/120")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		host string
		want bool
	}{
		{"API.EXAMPLE", true}, {"denied.example", false},
		{"192.0.2.1", true}, {"192.0.2.2", false},
		{"198.51.100.254", true}, {"198.51.101.1", false},
		{"2001:db8::1", true}, {"2001:db8:0:1::1", false},
		{"::ffff:192.0.2.1", true}, {"203.0.113.1", true},
		{"127.0.0.1", false}, {"169.254.169.254", false}, {"fe80::1%eth0", false},
	} {
		t.Run(test.host, func(t *testing.T) {
			if reason, ok := authorize(test.host); ok != test.want {
				t.Fatalf("authorize = %v (%s), want %v", ok, reason, test.want)
			}
		})
	}
	for _, entry := range []string{"example.com", "*", "192.0.2.1/33", "2001:db8::/129", "::ffff:192.0.2.0/80", "fe80::1%eth0"} {
		if _, err := parseIPAllowlist(entry); err == nil {
			t.Errorf("invalid IP policy accepted: %s", entry)
		}
	}
}

func TestLiteralTCPThroughBoundary(t *testing.T) {
	previousIPs := allowedIPs
	t.Cleanup(func() { allowedIPs = previousIPs })
	allowedIPs = []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32"), netip.MustParsePrefix("::1/128")}
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
	previousIPs, previousUDP := allowedIPs, enableUDP
	t.Cleanup(func() { allowedIPs, enableUDP = previousIPs, previousUDP })
	allowedIPs = []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32"), netip.MustParsePrefix("::1/128")}
	enableUDP = true
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
