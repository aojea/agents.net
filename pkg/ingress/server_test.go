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

package ingress

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/types"

	"github.com/aojea/agents.net/pkg/apis"
	"github.com/aojea/agents.net/pkg/params"
	"github.com/aojea/agents.net/pkg/store"
)

func TestIngressAllowlistSocketAtAndRevoke(t *testing.T) {
	// Simulated Pod HTTP server bound on loopback.
	backendSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "pod-ok:"+r.URL.Path)
	}))
	defer backendSrv.Close()

	st, err := store.New(nil)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	podUID := types.UID("pod-ingress-1")
	if err := st.Upsert(store.PodConfig{
		PodUID: podUID,
		NetNS:  "/var/run/netns/fake-pod",
		Parameters: params.NetworkParameters{
			IngressPorts: []apis.IngressPort{
				{Port: 8080, Protocol: apis.IngressProtocolTCP},
				{Port: 9000, EndPort: 9005, Protocol: apis.IngressProtocolTCP},
			},
		},
	}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	var dialedNetNS, dialedAddr string
	srv, err := NewServer(Config{
		ListenAddr: "127.0.0.1:0",
		Store:      st,
		DialNetNS: func(netnsPath, network, address string, timeout time.Duration) (net.Conn, error) {
			dialedNetNS = netnsPath
			dialedAddr = address
			return net.DialTimeout(network, backendSrv.Listener.Addr().String(), timeout)
		},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	addr, err := srv.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = srv.Close() }()

	// 1. Undeclared port must fail closed with 403 and RFC 9209 Proxy-Status.
	if resp := rawConnect(t, addr.String(), fmt.Sprintf("CONNECT %s:9999 HTTP/1.1\r\nHost: %s:9999\r\n\r\n", podUID, podUID)); !strings.HasPrefix(resp, "HTTP/1.1 403 ") ||
		!strings.Contains(resp, "Proxy-Status: dra-agents-net-ingress; error=http_request_denied; reason=port-not-permitted") {
		t.Fatalf("undeclared port response = %q, want 403 with RFC 9209 Proxy-Status", resp)
	}

	// 2. Unknown Pod UID must fail closed with 404 and RFC 9209 Proxy-Status.
	if resp := rawConnect(t, addr.String(), "CONNECT unknown-uid:8080 HTTP/1.1\r\nHost: unknown-uid:8080\r\n\r\n"); !strings.HasPrefix(resp, "HTTP/1.1 404 ") ||
		!strings.Contains(resp, "Proxy-Status: dra-agents-net-ingress; error=destination_not_found; reason=unknown-sandbox") {
		t.Fatalf("unknown pod response = %q, want 404 unknown-sandbox", resp)
	}

	// 3. Non-CONNECT method and Host mismatch are rejected cleanly with Proxy-Status.
	if resp := rawConnect(t, addr.String(), "GET / HTTP/1.1\r\nHost: x:80\r\n\r\n"); !strings.HasPrefix(resp, "HTTP/1.1 405 ") || !strings.Contains(resp, "Proxy-Status:") {
		t.Fatalf("non-CONNECT response = %q, want 405 with Proxy-Status", resp)
	}
	if resp := rawConnect(t, addr.String(), fmt.Sprintf("CONNECT %s:8080 HTTP/1.1\r\nHost: wrong:8080\r\n\r\n", podUID)); !strings.HasPrefix(resp, "HTTP/1.1 400 ") || !strings.Contains(resp, "reason=authority-mismatch") {
		t.Fatalf("host mismatch response = %q, want 400 authority-mismatch", resp)
	}

	// 4. Allowed port and inclusive range port (via HTTP/1.0 without Host) tunnel cleanly.
	for _, tc := range []struct {
		req      string
		wantAddr string
	}{
		{
			req:      fmt.Sprintf("CONNECT %s:8080 HTTP/1.1\r\nHost: %s:8080\r\n\r\n", podUID, podUID),
			wantAddr: "127.0.0.1:8080",
		},
		{
			req:      fmt.Sprintf("CONNECT %s:9003 HTTP/1.0\r\n\r\n", podUID),
			wantAddr: "127.0.0.1:9003",
		},
	} {
		conn, err := net.DialTimeout("tcp", addr.String(), 2*time.Second)
		if err != nil {
			t.Fatalf("dial ingress: %v", err)
		}
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		_, _ = io.WriteString(conn, tc.req)
		br := bufio.NewReader(conn)
		status, err := br.ReadString('\n')
		if err != nil || !strings.HasPrefix(status, "HTTP/1.1 200 ") {
			_ = conn.Close()
			t.Fatalf("CONNECT status = %q err=%v, want 200", status, err)
		}
		_, _ = br.ReadString('\n') // blank line

		_, _ = io.WriteString(conn, "GET /hello HTTP/1.1\r\nHost: sandbox\r\nConnection: close\r\n\r\n")
		httpResp, err := http.ReadResponse(br, nil)
		if err != nil {
			_ = conn.Close()
			t.Fatalf("ReadResponse: %v", err)
		}
		body, _ := io.ReadAll(httpResp.Body)
		_ = httpResp.Body.Close()
		_ = conn.Close()
		if string(body) != "pod-ok:/hello" {
			t.Fatalf("body = %q, want pod-ok:/hello", string(body))
		}
		if dialedNetNS != "/var/run/netns/fake-pod" || dialedAddr != tc.wantAddr {
			t.Fatalf("dialed (%q, %q), want (/var/run/netns/fake-pod, %s)", dialedNetNS, dialedAddr, tc.wantAddr)
		}
	}
}

func TestIngressSocketUDSPathAndRevoke(t *testing.T) {
	// Use a short temp dir so Unix socket path stays below Linux 108-byte sun_path limit.
	tmpDir, err := os.MkdirTemp("", "anet-ing-")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	ingressSock := filepath.Join(tmpDir, "ingress.sock")
	udsLn, err := net.Listen("unix", ingressSock)
	if err != nil {
		t.Fatalf("listen ingress.sock: %v", err)
	}
	defer func() { _ = udsLn.Close() }()

	// Simulated tun2connect ingress.sock listener echoing bytes after CONNECT 127.0.0.1:8080.
	go func() {
		for {
			c, err := udsLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer func() { _ = conn.Close() }()
				br := bufio.NewReader(conn)
				req, err := http.ReadRequest(br)
				if err != nil || req.Method != http.MethodConnect || req.Host != "127.0.0.1:8080" {
					_, _ = io.WriteString(conn, "HTTP/1.1 400 Bad Request\r\n\r\n")
					return
				}
				// Send a 1xx interim response followed by a non-200 2xx to verify RFC 9110 handling.
				_, _ = io.WriteString(conn, "HTTP/1.1 102 Processing\r\n\r\nHTTP/1.1 204 No Content\r\n\r\n")
				_, _ = io.Copy(conn, br)
			}(c)
		}
	}()

	st, _ := store.New(nil)
	podUID := types.UID("pod-uds-ingress")
	_ = st.Upsert(store.PodConfig{
		PodUID: podUID,
		SocketPaths: store.SocketPaths{
			IngressSocketPath: ingressSock,
		},
		Parameters: params.NetworkParameters{
			AdapterMode:  apis.AdapterModeTunSidecar,
			IngressPorts: []apis.IngressPort{{Port: 8080}},
		},
	})

	srv, err := NewServer(Config{
		ListenAddr: "127.0.0.1:0",
		Store:      st,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	addr, err := srv.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = srv.Close() }()

	conn, err := net.DialTimeout("tcp", addr.String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial ingress: %v", err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = fmt.Fprintf(conn, "CONNECT %s:8080 HTTP/1.1\r\nHost: %s:8080\r\n\r\n", podUID, podUID)
	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "HTTP/1.1 200 ") {
		t.Fatalf("UDS ingress status = %q err=%v", line, err)
	}
	_, _ = br.ReadString('\n')

	_, _ = io.WriteString(conn, "ping-ingress\n")
	if got, err := br.ReadString('\n'); err != nil || got != "ping-ingress\n" {
		t.Fatalf("echo = %q err=%v, want ping-ingress", got, err)
	}

	// Revoke immediately terminates the active ingress stream and blocks new connections until Allow.
	srv.Revoke(podUID)
	buf := make([]byte, 8)
	if _, err := br.Read(buf); err == nil {
		t.Fatalf("expected active ingress connection to close after Revoke")
	}
	if resp := rawConnect(t, addr.String(), fmt.Sprintf("CONNECT %s:8080 HTTP/1.1\r\nHost: %s:8080\r\n\r\n", podUID, podUID)); !strings.HasPrefix(resp, "HTTP/1.1 404 ") ||
		!strings.Contains(resp, "Proxy-Status: dra-agents-net-ingress; error=destination_not_found; reason=sandbox-revoked") {
		t.Fatalf("post-Revoke new connection response = %q, want 404 with Proxy-Status sandbox-revoked", resp)
	}
	srv.Allow(podUID)

	// Container-planted symlink at ingress.sock must be rejected (fail closed).
	symlinkPod := types.UID("pod-symlink-attack")
	linkPath := filepath.Join(tmpDir, "symlink.sock")
	if err := os.Symlink(ingressSock, linkPath); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	_ = st.Upsert(store.PodConfig{
		PodUID: symlinkPod,
		SocketPaths: store.SocketPaths{
			IngressSocketPath: linkPath,
		},
		Parameters: params.NetworkParameters{
			AdapterMode:  apis.AdapterModeTunSidecar,
			IngressPorts: []apis.IngressPort{{Port: 8080}},
		},
	})
	if resp := rawConnect(t, addr.String(), fmt.Sprintf("CONNECT %s:8080 HTTP/1.1\r\nHost: %s:8080\r\n\r\n", symlinkPod, symlinkPod)); !strings.HasPrefix(resp, "HTTP/1.1 502 ") || !strings.Contains(resp, "Proxy-Status:") {
		t.Fatalf("symlink ingress.sock response = %q, want 502 with Proxy-Status", resp)
	}
}

func TestIngressIPv6LoopbackFallback(t *testing.T) {
	backendSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "v6-fallback-ok")
	}))
	defer backendSrv.Close()

	st, _ := store.New(nil)
	podUID := types.UID("pod-v6-loopback")
	_ = st.Upsert(store.PodConfig{
		PodUID: podUID,
		NetNS:  "/var/run/netns/fake-v6",
		Parameters: params.NetworkParameters{
			IngressPorts: []apis.IngressPort{{Port: 8080}},
		},
	})

	var dialed []string
	srv, err := NewServer(Config{
		ListenAddr: "127.0.0.1:0",
		Store:      st,
		DialNetNS: func(_, network, address string, timeout time.Duration) (net.Conn, error) {
			dialed = append(dialed, address)
			if strings.HasPrefix(address, "127.0.0.1:") {
				return nil, net.ErrClosed
			}
			return net.DialTimeout(network, backendSrv.Listener.Addr().String(), timeout)
		},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	addr, err := srv.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = srv.Close() }()

	conn, err := net.DialTimeout("tcp", addr.String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial ingress: %v", err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = fmt.Fprintf(conn, "CONNECT %s:8080 HTTP/1.1\r\nHost: %s:8080\r\n\r\n", podUID, podUID)
	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil || !strings.HasPrefix(status, "HTTP/1.1 200 ") {
		t.Fatalf("CONNECT status = %q err=%v, want 200", status, err)
	}
	_, _ = br.ReadString('\n')
	_, _ = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
	httpResp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	body, _ := io.ReadAll(httpResp.Body)
	_ = httpResp.Body.Close()
	if string(body) != "v6-fallback-ok" {
		t.Fatalf("body = %q, want v6-fallback-ok", string(body))
	}
	if len(dialed) != 2 || dialed[0] != "127.0.0.1:8080" || dialed[1] != "[::1]:8080" {
		t.Fatalf("dialed addresses = %v, want [127.0.0.1:8080 [::1]:8080]", dialed)
	}
}

func TestIngressMTLSAuthentication(t *testing.T) {
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ingress-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)
	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)

	issue := func(cn string, server bool) tls.Certificate {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		eku := x509.ExtKeyUsageClientAuth
		var ips []net.IP
		if server {
			eku = x509.ExtKeyUsageServerAuth
			ips = []net.IP{net.ParseIP("127.0.0.1")}
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(time.Now().UnixNano()),
			Subject:      pkix.Name{CommonName: cn},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{eku},
			IPAddresses:  ips,
		}
		der, _ := x509.CreateCertificate(rand.Reader, tmpl, caCert, &k.PublicKey, caKey)
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
	}

	st, _ := store.New(nil)
	srv, err := NewServer(Config{
		ListenAddr: "127.0.0.1:0",
		Store:      st,
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{issue("dra-agents-net-ingress", true)},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    caPool,
		},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	addr, err := srv.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = srv.Close() }()

	// Client without certificate must fail TLS handshake.
	if c, err := tls.Dial("tcp", addr.String(), &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: caPool}); err == nil {
		_, rerr := io.ReadAll(c)
		_ = c.Close()
		if rerr == nil {
			t.Fatalf("expected TLS rejection without client certificate")
		}
	}

	// Client with valid cert passes TLS handshake and receives HTTP 404 for unknown Pod.
	c, err := tls.Dial("tcp", addr.String(), &tls.Config{
		MinVersion:   tls.VersionTLS12,
		RootCAs:      caPool,
		Certificates: []tls.Certificate{issue("sandbox-router", false)},
	})
	if err != nil {
		t.Fatalf("mTLS dial failed: %v", err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	_, _ = io.WriteString(c, "CONNECT no-such-pod:8080 HTTP/1.1\r\nHost: no-such-pod:8080\r\n\r\n")
	resp, err := io.ReadAll(c)
	if err != nil || !strings.HasPrefix(string(resp), "HTTP/1.1 404 ") {
		t.Fatalf("mTLS response = %q err=%v, want 404", string(resp), err)
	}
}

func TestNilServerAllowAndRevokeNoPanic(t *testing.T) {
	var srv *Server
	srv.Revoke("pod-uid-nil")
	srv.Allow("pod-uid-nil")
}

func rawConnect(t *testing.T, addr, req string) string {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	_, _ = io.WriteString(conn, req)
	data, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	head, _, _ := strings.Cut(string(data), "\r\n\r\n")
	return head
}
