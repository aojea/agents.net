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

	"github.com/aojea/agents.net/kubernetes/pkg/apis"
	"github.com/aojea/agents.net/kubernetes/pkg/params"
	"github.com/aojea/agents.net/kubernetes/pkg/store"
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

	// 1. Undeclared port must fail closed with 403 Boundary-Reason: ingress-port-denied.
	if resp := rawConnect(t, addr.String(), fmt.Sprintf("CONNECT %s:9999 HTTP/1.1\r\nHost: %s:9999\r\n\r\n", podUID, podUID)); !strings.HasPrefix(resp, "HTTP/1.1 403 ") || !strings.Contains(resp, "Boundary-Reason: ingress-port-denied") {
		t.Fatalf("undeclared port response = %q, want 403 ingress-port-denied", resp)
	}

	// 2. Unknown Pod UID must fail closed with 404 Boundary-Reason: unknown-sandbox.
	if resp := rawConnect(t, addr.String(), "CONNECT unknown-uid:8080 HTTP/1.1\r\nHost: unknown-uid:8080\r\n\r\n"); !strings.HasPrefix(resp, "HTTP/1.1 404 ") || !strings.Contains(resp, "Boundary-Reason: unknown-sandbox") {
		t.Fatalf("unknown pod response = %q, want 404 unknown-sandbox", resp)
	}

	// 3. Non-CONNECT method and Host mismatch are rejected cleanly.
	if resp := rawConnect(t, addr.String(), "GET / HTTP/1.1\r\nHost: x:80\r\n\r\n"); !strings.HasPrefix(resp, "HTTP/1.1 405 ") {
		t.Fatalf("non-CONNECT response = %q, want 405", resp)
	}
	if resp := rawConnect(t, addr.String(), fmt.Sprintf("CONNECT %s:8080 HTTP/1.1\r\nHost: wrong:8080\r\n\r\n", podUID)); !strings.HasPrefix(resp, "HTTP/1.1 400 ") {
		t.Fatalf("host mismatch response = %q, want 400", resp)
	}

	// 4. Allowed port tunnels HTTP traffic cleanly into the Pod netns via DialNetNS.
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
	_, _ = br.ReadString('\n') // blank line

	_, _ = io.WriteString(conn, "GET /hello HTTP/1.1\r\nHost: sandbox\r\nConnection: close\r\n\r\n")
	httpResp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	body, _ := io.ReadAll(httpResp.Body)
	_ = httpResp.Body.Close()
	if string(body) != "pod-ok:/hello" {
		t.Fatalf("body = %q, want pod-ok:/hello", string(body))
	}
	if dialedNetNS != "/var/run/netns/fake-pod" || dialedAddr != "127.0.0.1:8080" {
		t.Fatalf("dialed (%q, %q), want (/var/run/netns/fake-pod, 127.0.0.1:8080)", dialedNetNS, dialedAddr)
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
				_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
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
	if resp := rawConnect(t, addr.String(), fmt.Sprintf("CONNECT %s:8080 HTTP/1.1\r\nHost: %s:8080\r\n\r\n", podUID, podUID)); !strings.HasPrefix(resp, "HTTP/1.1 503 ") || !strings.Contains(resp, "sandbox-revoked") {
		t.Fatalf("post-Revoke new connection response = %q, want 503 sandbox-revoked", resp)
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
	if resp := rawConnect(t, addr.String(), fmt.Sprintf("CONNECT %s:8080 HTTP/1.1\r\nHost: %s:8080\r\n\r\n", symlinkPod, symlinkPod)); !strings.HasPrefix(resp, "HTTP/1.1 502 ") {
		t.Fatalf("symlink ingress.sock response = %q, want 502", resp)
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
