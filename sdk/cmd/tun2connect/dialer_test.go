package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/aojea/agents.net/sdk/pkg/tun2connect"
)

func TestBoundaryDialerSchemes(t *testing.T) {
	tests := []struct {
		proxy   string
		wantErr bool
	}{
		{"unix:///tmp/test.sock", false},
		{"tcp://127.0.0.1:8080", false},
		{"vsock://2:10050", false},
		{"http://127.0.0.1:8080", true},
		{"vsock://invalid", true},
		{"://invalid-url", true},
	}

	for _, tt := range tests {
		dial, err := boundaryDialer(tt.proxy)
		if (err != nil) != tt.wantErr {
			t.Errorf("boundaryDialer(%q) error = %v, wantErr %v", tt.proxy, err, tt.wantErr)
			continue
		}
		if !tt.wantErr && dial == nil {
			t.Errorf("boundaryDialer(%q) returned nil dialer without error", tt.proxy)
		}
	}
}

func TestDialVSOCKInvalidAddresses(t *testing.T) {
	badAddrs := []string{
		"only-port",
		"not-a-number:1000",
		"2:not-a-number",
		"1:2:3",
	}

	for _, addr := range badAddrs {
		_, err := dialVSOCK(addr)
		if err == nil {
			t.Errorf("dialVSOCK(%q) expected error, got nil", addr)
		}
	}
}

// TestIngressOnlyReachesPinnedPort runs the ingress handshake against two
// loopback listeners and checks that only the pinned one is reachable,
// whatever port the caller names, and that refusals carry Proxy-Status.
func TestIngressOnlyReachesPinnedPort(t *testing.T) {
	listen := func(banner string) uint16 {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ln.Close() })
		go func() {
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				io.WriteString(conn, banner)
				conn.Close()
			}
		}()
		return uint16(ln.Addr().(*net.TCPAddr).Port)
	}
	pinned, other := listen("pinned\n"), listen("other\n")
	socket := filepath.Join(t.TempDir(), "ingress.sock")
	ln, err := listenIngress(socket)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go serveIngress(ln, pinned)

	handshake := func(head string) (status int, reason, rest string) {
		conn, err := net.Dial("unix", socket)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		io.WriteString(conn, head)
		br := bufio.NewReader(conn)
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatalf("%q: %v", head, err)
		}
		remaining, _ := io.ReadAll(br)
		return resp.StatusCode, tun2connect.ProxyStatusReason(resp.Header), string(remaining)
	}
	connect := func(port uint16) string {
		return fmt.Sprintf("CONNECT 127.0.0.1:%d HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n\r\n", port, port)
	}
	if status, reason, rest := handshake(connect(pinned)); status != 200 || reason != "" || rest != "pinned\n" {
		t.Fatalf("pinned port: %d %q %q", status, reason, rest)
	}
	for _, test := range []struct {
		name, head string
		status     int
		reason     string
	}{
		{"other listening port", connect(other), 403, "port-not-permitted"},
		{"unlistened port", connect(22), 403, "port-not-permitted"},
		{"non-loopback target", fmt.Sprintf("CONNECT 10.0.0.1:%d HTTP/1.1\r\nHost: 10.0.0.1:%d\r\n\r\n", pinned, pinned), 400, "malformed-target"},
		{"Host names another port", fmt.Sprintf("CONNECT 127.0.0.1:%d HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n\r\n", pinned, other), 400, "authority-mismatch"},
		{"missing Host", fmt.Sprintf("CONNECT 127.0.0.1:%d HTTP/1.1\r\n\r\n", pinned), 400, "missing-host"},
		{"GET", "GET / HTTP/1.1\r\nHost: x\r\n\r\n", 405, "connect-only"},
		{"textual handshake", fmt.Sprintf("CONNECT %d\n", pinned), 400, "malformed-request-line"},
		{"HTTP/2.0", fmt.Sprintf("CONNECT 127.0.0.1:%d HTTP/2.0\r\nHost: 127.0.0.1:%d\r\n\r\n", pinned, pinned), 505, "unsupported-version"},
	} {
		if status, reason, rest := handshake(test.head); status != test.status || reason != test.reason || rest != "" {
			t.Errorf("%s: got %d %q %q, want %d %q", test.name, status, reason, rest, test.status, test.reason)
		}
	}
}
