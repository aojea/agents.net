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

// setPolicy installs -allow, -allow-ip, and -resolve values for one test
// through the same parsers main uses, restoring the previous policy after.
func setPolicy(t *testing.T, allow, allowIP, resolve string) {
	t.Helper()
	previousNames, previousIPs, previousStatic := allowed, allowedIPs, static
	t.Cleanup(func() { allowed, allowedIPs, static = previousNames, previousIPs, previousStatic })
	var err error
	if allowed, err = parseAllow(allow); err != nil {
		t.Fatal(err)
	}
	if allowedIPs, err = parseIPAllowlist(allowIP); err != nil {
		t.Fatal(err)
	}
	if static, err = parseStatic(resolve); err != nil {
		t.Fatal(err)
	}
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
	setPolicy(t, "", "127.0.0.1/32", "")
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
	setResolver(t, func(ctx context.Context, network, host string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
	})
	ctx := context.Background()
	setPolicy(t, "api.example,*", "", "")
	if _, reason, _ := authorize(ctx, "127.0.0.1", "443"); reason == "" {
		t.Fatal("hostname wildcard must not authorize literal addresses")
	}
	setPolicy(t, "api.example", "192.0.2.1, 198.51.100.19/24, 2001:db8::/64, ::ffff:203.0.113.0/120", "")
	for _, test := range []struct {
		host string
		port string
		want bool
	}{
		{"API.EXAMPLE", "443", true}, {"api.example.", "443", true}, {"denied.example", "443", false},
		{"192.0.2.1", "443", true}, {"192.0.2.2", "443", false},
		{"198.51.100.254", "443", true}, {"198.51.101.1", "443", false},
		{"2001:db8::1", "443", true}, {"2001:db8:0:1::1", "443", false},
		{"::ffff:192.0.2.1", "443", true}, {"203.0.113.1", "443", true},
		{"127.0.0.1", "443", false}, {"169.254.169.254", "80", false}, {"fe80::1%eth0", "443", false},
		{"192.0.2.1", "0", false}, {"192.0.2.1", "65536", false}, {"192.0.2.1", "https", false}, {"192.0.2.1", "", false},
	} {
		t.Run(test.host+":"+test.port, func(t *testing.T) {
			addresses, reason, err := authorize(ctx, test.host, test.port)
			if err != nil {
				t.Fatal(err)
			}
			if ok := reason == ""; ok != test.want {
				t.Fatalf("authorize = %v (%s), want %v", ok, reason, test.want)
			}
			if test.want && len(addresses) != 1 {
				t.Fatalf("addresses = %v, want exactly one", addresses)
			}
		})
	}
	for _, entry := range []string{"example.com", "*", "192.0.2.1/33", "2001:db8::/129", "::ffff:192.0.2.0/80", "fe80::1%eth0", "192.0.2.1:0", "192.0.2.1:https", "[2001:db8::1", "[2001:db8::1]x"} {
		if _, err := parseIPAllowlist(entry); err == nil {
			t.Errorf("invalid IP policy accepted: %s", entry)
		}
	}
}

// TestPortPolicy checks that a :port suffix on -allow and -allow-ip
// entries restricts the destination port, on names, literals, and the
// wildcard, and that an entry without a port keeps every port open.
func TestPortPolicy(t *testing.T) {
	setResolver(t, func(ctx context.Context, network, host string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
	})
	setPolicy(t, "api.example:443, api.example:8443, any.example, *:80",
		"192.0.2.1:443, 198.51.100.0/24:22, [2001:db8::1]:443, [2001:db8:1::/64]:53, 203.0.113.7", "")
	ctx := context.Background()
	for _, test := range []struct {
		host, port, reason string
	}{
		{"api.example", "443", ""}, {"api.example", "8443", ""}, {"api.example", "80", ""},
		{"api.example", "22", "port-not-allowed"},
		{"any.example", "22", ""}, {"any.example", "1", ""},
		{"other.example", "80", ""}, {"other.example", "443", "port-not-allowed"},
		{"192.0.2.1", "443", ""}, {"192.0.2.1", "80", "port-not-allowed"},
		{"198.51.100.9", "22", ""}, {"198.51.100.9", "23", "port-not-allowed"},
		{"2001:db8::1", "443", ""}, {"2001:db8::1", "444", "port-not-allowed"},
		{"2001:db8:1::5", "53", ""}, {"2001:db8:1::5", "443", "port-not-allowed"},
		{"203.0.113.7", "1", ""}, {"203.0.113.7", "65535", ""},
		{"203.0.113.8", "443", "ip-not-on-allowlist"},
	} {
		t.Run(test.host+":"+test.port, func(t *testing.T) {
			_, reason, err := authorize(ctx, test.host, test.port)
			if err != nil || reason != test.reason {
				t.Fatalf("authorize = %q, %v; want %q", reason, err, test.reason)
			}
		})
	}
	// A listed non-public address used as a resolved-address exception is
	// also port-scoped.
	setResolver(t, func(ctx context.Context, network, host string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("10.1.2.3")}, nil
	})
	setPolicy(t, "internal.example", "10.1.2.0/24:9443", "")
	if _, reason, _ := authorize(ctx, "internal.example", "9443"); reason != "" {
		t.Fatalf("listed port: %q", reason)
	}
	if _, reason, _ := authorize(ctx, "internal.example", "443"); reason != "resolved-address-denied" {
		t.Fatalf("unlisted port on a private address: %q", reason)
	}
	for _, entry := range []string{"api.example:0", "api.example:65536", "api.example:https", ":443", "192.0.2.1", "[api.example]:443x", "..", "a..b", "a b.example", "ex*ample.com", "-" + strings.Repeat("a", 63) + ".example"} {
		if _, err := parseAllow(entry); err == nil {
			t.Errorf("invalid -allow entry accepted: %q", entry)
		}
	}
	if _, err := parseAllow("xn--bcher-kva.example, my_service.internal:8080, a-b.c"); err != nil {
		t.Fatalf("valid names rejected: %v", err)
	}
}

// TestResolvedAddressPolicy checks that an allowed hostname only yields
// public or explicitly listed addresses, whatever its DNS answers say.
func TestResolvedAddressPolicy(t *testing.T) {
	setPolicy(t, "*", "10.1.2.0/24", "")
	ctx := context.Background()
	answers := map[string][]string{
		"public.example":    {"93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"},
		"metadata.example":  {"169.254.169.254"},
		"loopback.example":  {"127.0.0.1", "::1"},
		"private.example":   {"10.0.0.5", "172.16.0.1", "192.168.1.1", "fd00::1"},
		"mapped.example":    {"::ffff:127.0.0.1", "::ffff:10.0.0.1"},
		"nat64.example":     {"64:ff9b::7f00:1"},
		"shared.example":    {"100.64.0.1", "100::1"},
		"reserved.example":  {"0.0.0.1", "240.0.0.1", "255.255.255.255", "2001:db8::1", "2002:7f00:1::1", "fec0::1"},
		"multicast.example": {"224.0.0.1", "ff02::1", "0.0.0.0", "::"},
		"mixed.example":     {"127.0.0.1", "93.184.216.34", "169.254.169.254"},
		"listed.example":    {"10.1.2.3"},
		"empty.example":     {},
	}
	lookupNetIP = func(ctx context.Context, network, host string) ([]netip.Addr, error) {
		records, ok := answers[host]
		if !ok {
			return nil, errors.New("no such host")
		}
		var addresses []netip.Addr
		for _, record := range records {
			addresses = append(addresses, netip.MustParseAddr(record))
		}
		return addresses, nil
	}
	t.Cleanup(func() { lookupNetIP = net.DefaultResolver.LookupNetIP })
	for host, want := range map[string][]string{
		"public.example":    {"93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"},
		"metadata.example":  nil,
		"loopback.example":  nil,
		"private.example":   nil,
		"mapped.example":    nil,
		"nat64.example":     nil,
		"shared.example":    nil,
		"reserved.example":  nil,
		"multicast.example": nil,
		"mixed.example":     {"93.184.216.34"},
		"listed.example":    {"10.1.2.3"},
		"empty.example":     nil,
	} {
		t.Run(host, func(t *testing.T) {
			addresses, reason, err := authorize(ctx, host, "443")
			if err != nil {
				t.Fatal(err)
			}
			if want == nil {
				if reason != "resolved-address-denied" || len(addresses) != 0 {
					t.Fatalf("expected denial, got %v (%q)", addresses, reason)
				}
				return
			}
			if reason != "" || len(addresses) != len(want) {
				t.Fatalf("addresses = %v (%q), want %v", addresses, reason, want)
			}
			for i, address := range addresses {
				if address.String() != want[i] {
					t.Fatalf("addresses = %v, want %v", addresses, want)
				}
			}
		})
	}
	if _, reason, err := authorize(ctx, "missing.example", "443"); err == nil || reason != "" {
		t.Fatalf("resolution failure must be an error, not a policy decision: %v %q", err, reason)
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
			// Loopback is not public: without -allow-ip the resolved address is denied.
			setPolicy(t, "echo.example,rebound.example", "", "")
			_, err := client.DialTCP(ctx, "rebound.example", port)
			var refusal *tun2connect.DialError
			if !errors.As(err, &refusal) || refusal.StatusCode != http.StatusForbidden || refusal.Reason != "resolved-address-denied" {
				t.Fatalf("allowed name resolving to loopback must be denied: %v", err)
			}
			if connections.Load() != 0 {
				t.Fatal("denied name produced an upstream connection")
			}
			setPolicy(t, "echo.example,rebound.example", "127.0.0.1/32", "")
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

// TestStaticMappingIsStillAddressChecked checks that -resolve replaces DNS
// for a name but does not bypass address policy.
func TestStaticMappingIsStillAddressChecked(t *testing.T) {
	var lookups atomic.Int32
	setResolver(t, func(ctx context.Context, network, host string) ([]netip.Addr, error) {
		lookups.Add(1)
		return nil, errors.New("DNS must not be consulted for a mapped name")
	})
	const mappings = " target.internal=127.0.0.1+::1 , Public.Example.=93.184.216.34"
	ctx := context.Background()
	setPolicy(t, "target.internal,public.example", "", mappings)
	if _, reason, err := authorize(ctx, "target.internal", "9099"); err != nil || reason != "resolved-address-denied" {
		t.Fatalf("loopback mapping without -allow-ip: %q, %v", reason, err)
	}
	setPolicy(t, "target.internal,public.example", "127.0.0.1/32", mappings)
	addresses, reason, err := authorize(ctx, "target.internal.", "9099")
	if err != nil || reason != "" || len(addresses) != 1 || addresses[0] != netip.MustParseAddr("127.0.0.1") {
		t.Fatalf("mapped and listed: %v %q %v", addresses, reason, err)
	}
	addresses, reason, err = authorize(ctx, "public.example", "443")
	if err != nil || reason != "" || len(addresses) != 1 || addresses[0] != netip.MustParseAddr("93.184.216.34") {
		t.Fatalf("public mapping: %v %q %v", addresses, reason, err)
	}
	if lookups.Load() != 0 {
		t.Fatalf("DNS consulted %d times for mapped names", lookups.Load())
	}
	for _, entry := range []string{"nohost", "=1.2.3.4", "a.example=", "a.example=not-an-ip", "1.2.3.4=5.6.7.8", "a.example=fe80::1%eth0"} {
		if _, err := parseStatic(entry); err == nil {
			t.Errorf("invalid mapping accepted: %q", entry)
		}
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
	setPolicy(t, "", "127.0.0.1/32, ::1/128", "")
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
	previousUDP := enableUDP
	t.Cleanup(func() { enableUDP = previousUDP })
	setPolicy(t, "", "127.0.0.1/32, ::1/128", "")
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
	previousSandbox, previousPolicy, previousListener := sandboxID, policyVersion, listenerName
	t.Cleanup(func() { sandboxID, policyVersion, listenerName = previousSandbox, previousPolicy, previousListener })
	sandboxID, policyVersion, listenerName = "sandbox-a", "v7", "unix:///run/a.sock"
	setPolicy(t, "", "127.0.0.1/32", "")
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
	// and would split or spoof fields in a space- or comma-delimited log.
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
		if record.Sandbox != "sandbox-a" || record.Policy != "v7" || record.Listener != "unix:///run/a.sock" || record.Wire != "h1" || record.Transport != "tcp" || record.Time == "" {
			t.Fatalf("missing listener-bound fields: %+v", record)
		}
		records = append(records, record)
	}
	if records[0].Decision != "allow" || records[0].Address != upstream.Addr().String() || records[0].Destination != net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))) {
		t.Fatalf("allow record: %+v", records[0])
	}
	if records[1].Decision != "block" || records[1].Reason != "not-on-allowlist" || records[1].Destination != hostile+":443" {
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
	if err != nil || response.StatusCode != http.StatusServiceUnavailable || response.Header.Get("Boundary-Reason") != "busy" {
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
	setPolicy(t, "", "127.0.0.1/32", "")
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
