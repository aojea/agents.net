package main

import (
	"fmt"
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"
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
// whatever port the caller names.
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

	handshake := func(line string) string {
		conn, err := net.Dial("unix", socket)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		io.WriteString(conn, line)
		reply, _ := io.ReadAll(conn)
		return string(reply)
	}
	if got := handshake(fmt.Sprintf("CONNECT %d\n", pinned)); got != "OK\npinned\n" {
		t.Fatalf("pinned port: %q", got)
	}
	if got := handshake(fmt.Sprintf("CONNECT %d\n", other)); got != "ERR port not permitted\n" {
		t.Fatalf("other listening port must be unreachable: %q", got)
	}
	if got := handshake("CONNECT 22\n"); got != "ERR port not permitted\n" {
		t.Fatalf("unlistened port: %q", got)
	}
	if got := handshake("GET / HTTP/1.1\n"); got != "ERR malformed handshake\n" {
		t.Fatalf("malformed handshake: %q", got)
	}
}
