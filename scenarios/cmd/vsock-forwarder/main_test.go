package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"
)

func TestParseVsockAddr(t *testing.T) {
	tests := []struct {
		input        string
		expectedCID  uint32
		expectedPort uint32
		expectErr    bool
	}{
		{"1:10088", 1, 10088, false},
		{"vsock://2:9000", 2, 9000, false},
		{"vsock://3:80", 3, 80, false},
		{"4294967295:12345", 4294967295, 12345, false},
		{"invalid", 0, 0, true},
		{"1:notaport", 0, 0, true},
		{"notacid:1000", 0, 0, true},
		{"1:2:3", 0, 0, true},
	}

	for _, tc := range tests {
		cid, port, err := parseVsockAddr(tc.input)
		if tc.expectErr && err == nil {
			t.Errorf("parseVsockAddr(%q): expected error, got nil", tc.input)
		}
		if !tc.expectErr && err != nil {
			t.Errorf("parseVsockAddr(%q): unexpected error: %v", tc.input, err)
		}
		if !tc.expectErr {
			if cid != tc.expectedCID {
				t.Errorf("parseVsockAddr(%q): expected CID %d, got %d", tc.input, tc.expectedCID, cid)
			}
			if port != tc.expectedPort {
				t.Errorf("parseVsockAddr(%q): expected port %d, got %d", tc.input, tc.expectedPort, port)
			}
		}
	}
}

func TestForwarderBidirectionalStreaming(t *testing.T) {
	tmpDir := t.TempDir()
	targetSock := filepath.Join(tmpDir, "target.sock")
	clientSock := filepath.Join(tmpDir, "client.sock")

	// 1. Setup mock upstream target server
	targetLn, err := net.Listen("unix", targetSock)
	if err != nil {
		t.Fatalf("target listen: %v", err)
	}
	defer targetLn.Close()

	targetReceived := make(chan []byte, 1)
	go func() {
		conn, err := targetLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		buf := make([]byte, 1024)
		n, _ := conn.Read(buf)
		targetReceived <- buf[:n]

		// Send reply back
		conn.Write([]byte("TARGET_REPLY_PONG"))
	}()

	// 2. Setup forwarder
	fwdLn, err := net.Listen("unix", clientSock)
	if err != nil {
		t.Fatalf("fwd listen: %v", err)
	}
	defer fwdLn.Close()

	dialer := func() (net.Conn, error) {
		return net.Dial("unix", targetSock)
	}

	fwd := NewForwarder(fwdLn, dialer)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go fwd.Run(ctx)

	// 3. Client connects to forwarder
	clientConn, err := net.Dial("unix", clientSock)
	if err != nil {
		t.Fatalf("client dial: %v", err)
	}
	defer clientConn.Close()

	msg := "CLIENT_PING_DATA"
	if _, err := clientConn.Write([]byte(msg)); err != nil {
		t.Fatalf("client write: %v", err)
	}

	// 4. Verify upstream received data
	select {
	case received := <-targetReceived:
		if string(received) != msg {
			t.Errorf("upstream received %q, expected %q", string(received), msg)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for upstream target to receive data")
	}

	// 5. Verify client received reply
	replyBuf := make([]byte, 1024)
	n, err := clientConn.Read(replyBuf)
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	if string(replyBuf[:n]) != "TARGET_REPLY_PONG" {
		t.Errorf("client received %q, expected %q", string(replyBuf[:n]), "TARGET_REPLY_PONG")
	}
}

func TestForwarderDialErrorHandling(t *testing.T) {
	tmpDir := t.TempDir()
	clientSock := filepath.Join(tmpDir, "client_fail.sock")

	fwdLn, err := net.Listen("unix", clientSock)
	if err != nil {
		t.Fatalf("fwd listen: %v", err)
	}
	defer fwdLn.Close()

	// Dialer that always fails
	dialer := func() (net.Conn, error) {
		return nil, fmt.Errorf("simulated network failure")
	}

	fwd := NewForwarder(fwdLn, dialer)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go fwd.Run(ctx)

	clientConn, err := net.Dial("unix", clientSock)
	if err != nil {
		t.Fatalf("client dial: %v", err)
	}
	defer clientConn.Close()

	// Client read should immediately return EOF or error because target dial failed
	buf := make([]byte, 10)
	_, readErr := clientConn.Read(buf)
	if readErr == nil {
		t.Errorf("expected error or EOF when dialer fails, got nil")
	}
}

func TestForwarderHighThroughput(t *testing.T) {
	tmpDir := t.TempDir()
	targetSock := filepath.Join(tmpDir, "target_perf.sock")
	clientSock := filepath.Join(tmpDir, "client_perf.sock")

	targetLn, err := net.Listen("unix", targetSock)
	if err != nil {
		t.Fatalf("target listen: %v", err)
	}
	defer targetLn.Close()

	dataSize := 1024 * 1024 // 1 MB
	payload := bytes.Repeat([]byte("X"), dataSize)

	go func() {
		conn, err := targetLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		io.Copy(io.Discard, conn)
	}()

	fwdLn, err := net.Listen("unix", clientSock)
	if err != nil {
		t.Fatalf("fwd listen: %v", err)
	}
	defer fwdLn.Close()

	fwd := NewForwarder(fwdLn, func() (net.Conn, error) {
		return net.Dial("unix", targetSock)
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go fwd.Run(ctx)

	clientConn, err := net.Dial("unix", clientSock)
	if err != nil {
		t.Fatalf("client dial: %v", err)
	}
	defer clientConn.Close()

	n, err := clientConn.Write(payload)
	if err != nil {
		t.Fatalf("write error: %v", err)
	}
	if n != dataSize {
		t.Errorf("expected to write %d bytes, wrote %d", dataSize, n)
	}
}
