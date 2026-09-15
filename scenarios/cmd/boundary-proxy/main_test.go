package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestVsockAddr(t *testing.T) {
	addr := vsockAddr{cid: 1, port: 10088}
	if addr.Network() != "vsock" {
		t.Errorf("expected network 'vsock', got %q", addr.Network())
	}
	if addr.String() != "1:10088" {
		t.Errorf("expected '1:10088', got %q", addr.String())
	}
}

func TestBoundaryProxyIgnoresForgedIdentity(t *testing.T) {
	originalHosts, originalAll, originalRewrites, originalLogger := allowedHosts, allowAll, rewrites, auditLogger
	t.Cleanup(func() {
		allowedHosts, allowAll, rewrites, auditLogger = originalHosts, originalAll, originalRewrites, originalLogger
	})
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	allowedHosts = map[string]bool{"allowed.test": true}
	allowAll = false
	rewrites = map[string]string{"allowed.test": upstream.Listener.Addr().String()}
	var auditBuffer bytes.Buffer
	auditLogger = log.New(&auditBuffer, "", 0)
	listener, err := net.Listen("unix", filepath.Join(t.TempDir(), "boundary.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	for _, test := range []struct {
		target string
		status int
		action string
	}{
		{"allowed.test:80", http.StatusOK, "ALLOW tcp"},
		{"denied.test:80", http.StatusForbidden, "BLOCK not-on-allowlist"},
	} {
		t.Run(test.target, func(t *testing.T) {
			auditBuffer.Reset()
			client, err := net.Dial("unix", listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			client.SetDeadline(time.Now().Add(3 * time.Second))
			server, err := listener.Accept()
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan struct{})
			go func() {
				handleConnection(server)
				close(done)
			}()
			fmt.Fprintf(client, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nX-Capsule-ID: forged-admin\r\nSandbox-Id: forged-admin\r\nX-Dome-Tenant: forged-admin\r\n\r\n", test.target, test.target)
			response, err := http.ReadResponse(bufio.NewReader(client), &http.Request{Method: http.MethodConnect})
			client.Close()
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			if response.StatusCode != test.status {
				t.Fatalf("status = %d, want %d", response.StatusCode, test.status)
			}
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Fatal("boundary did not close after client disconnect")
			}
			identity := fmt.Sprintf("capsule-pid-%d-uid-%d", os.Getpid(), os.Getuid())
			expected := fmt.Sprintf("%s target=%s capsule=%s", test.action, test.target, identity)
			if record := auditBuffer.String(); !strings.Contains(record, expected) || strings.Contains(record, "forged-admin") {
				t.Fatalf("audit = %q, want kernel-derived identity in %q", record, expected)
			}
		})
	}
}

func TestBoundaryProxyCONNECTAndAuthorization(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "boundary.sock")

	// Upstream echo server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ECHO_OK"))
	}))
	defer ts.Close()

	upstreamAddr := ts.Listener.Addr().String()

	// Initialize allowlist and rewrites
	allowedHosts["target.test"] = true
	rewrites["target.test"] = upstreamAddr

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleConnection(conn)
		}
	}()

	// 1. Test Non-CONNECT Method -> 405
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: target.test\r\n\r\n")
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	conn.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", resp.StatusCode)
	}

	// 2. Test Disallowed Host -> 403 Forbidden
	conn, err = net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	fmt.Fprintf(conn, "CONNECT forbidden.test:80 HTTP/1.1\r\nHost: forbidden.test:80\r\n\r\n")
	br = bufio.NewReader(conn)
	resp, err = http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	conn.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403, got %d", resp.StatusCode)
	}
	if resp.Header.Get("Boundary-Reason") != "not-on-allowlist" {
		t.Errorf("expected Boundary-Reason: not-on-allowlist, got %q", resp.Header.Get("Boundary-Reason"))
	}

	// 3. Test Allowed Host with Handshake -> 200 OK Tunnel
	conn, err = net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	fmt.Fprintf(conn, "CONNECT target.test:80 HTTP/1.1\r\nHost: target.test:80\r\n\r\n")
	br = bufio.NewReader(conn)
	statusLine, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read status line: %v", err)
	}
	if !strings.Contains(statusLine, "200 OK") {
		t.Fatalf("expected 200 OK, got %q", statusLine)
	}
	// Discard trailing CRLF
	br.ReadString('\n')

	// Now send HTTP GET to upstream through tunnel
	fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: target.test\r\nConnection: close\r\n\r\n")
	echoResp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read echo response: %v", err)
	}
	defer echoResp.Body.Close()
	body, _ := io.ReadAll(echoResp.Body)
	if string(body) != "ECHO_OK" {
		t.Errorf("expected 'ECHO_OK', got %q", string(body))
	}
}
