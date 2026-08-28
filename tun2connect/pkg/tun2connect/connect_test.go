package tun2connect

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"testing"
)

// fakeBoundary runs handler as the boundary side of a fresh pipe per dial.
func fakeBoundary(handler func(req *http.Request, br *bufio.Reader, conn net.Conn)) *BoundaryClient {
	return &BoundaryClient{
		DialBoundary: func(ctx context.Context) (net.Conn, error) {
			client, server := net.Pipe()
			go func() {
				defer server.Close()
				br := bufio.NewReader(server)
				req, err := http.ReadRequest(br)
				if err != nil {
					return
				}
				handler(req, br, server)
			}()
			return client, nil
		},
	}
}

func TestDialTCPConnectAndRelay(t *testing.T) {
	var gotTarget, gotID string
	c := fakeBoundary(func(req *http.Request, br *bufio.Reader, conn net.Conn) {
		gotTarget = req.Host
		gotID = req.Header.Get("Sandbox-Id")
		io.WriteString(conn, "HTTP/1.1 200 OK\r\n\r\n")
		io.Copy(conn, br) // echo
	})
	c.Header = http.Header{"Sandbox-Id": []string{"agent-123"}}

	conn, err := c.DialTCP(context.Background(), "api.example", 443)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if gotTarget != "api.example:443" {
		t.Fatalf("CONNECT target = %q, want api.example:443", gotTarget)
	}
	if gotID != "agent-123" {
		t.Fatalf("Sandbox-Id header = %q, not forwarded", gotID)
	}
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
}

func TestDialTCPRefusalIsDialError(t *testing.T) {
	c := fakeBoundary(func(req *http.Request, br *bufio.Reader, conn net.Conn) {
		io.WriteString(conn, "HTTP/1.1 403 Forbidden\r\nBoundary-Reason: not-on-allowlist\r\nContent-Length: 0\r\n\r\n")
	})
	_, err := c.DialTCP(context.Background(), "evil.example", 443)
	var de *DialError
	if !errors.As(err, &de) {
		t.Fatalf("want *DialError, got %v", err)
	}
	if de.StatusCode != http.StatusForbidden || de.Reason != "not-on-allowlist" {
		t.Fatalf("refusal not preserved: %+v", de)
	}
}

func TestDialUDPUpgradeAndEcho(t *testing.T) {
	var gotPath, gotUpgrade string
	c := fakeBoundary(func(req *http.Request, br *bufio.Reader, conn net.Conn) {
		gotPath = req.URL.Path
		gotUpgrade = req.Header.Get("Upgrade")
		io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: connect-udp\r\n\r\n")
		cs := NewCapsuleStream(struct {
			io.Reader
			io.Writer
		}{br, conn})
		for {
			p, err := cs.ReadDatagram()
			if err != nil {
				return
			}
			if cs.WriteDatagram(p) != nil {
				return
			}
		}
	})

	sess, err := c.DialUDP(context.Background(), "stun.example", 3478)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	if gotPath != "/.well-known/masque/udp/stun.example/3478/" {
		t.Fatalf("connect-udp path = %q", gotPath)
	}
	if gotUpgrade != "connect-udp" {
		t.Fatalf("Upgrade header = %q", gotUpgrade)
	}
	if err := sess.WriteDatagram([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	p, err := sess.ReadDatagram()
	if err != nil {
		t.Fatal(err)
	}
	if string(p) != "hello" {
		t.Fatalf("echo = %q", p)
	}
}

func TestDialUDPRefusalIsDialError(t *testing.T) {
	c := fakeBoundary(func(req *http.Request, br *bufio.Reader, conn net.Conn) {
		io.WriteString(conn, "HTTP/1.1 403 Forbidden\r\nBoundary-Reason: udp-not-allowed\r\nContent-Length: 0\r\n\r\n")
	})
	_, err := c.DialUDP(context.Background(), "evil.example", 443)
	var de *DialError
	if !errors.As(err, &de) {
		t.Fatalf("want *DialError, got %v", err)
	}
	if de.Reason != "udp-not-allowed" {
		t.Fatalf("refusal not preserved: %+v", de)
	}
}
