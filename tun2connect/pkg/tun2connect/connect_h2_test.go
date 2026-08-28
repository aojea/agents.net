package tun2connect

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
)

// x/net's h2 SERVER only advertises ENABLE_CONNECT_PROTOCOL under
// GODEBUG=http2xconnect=1 (golang/go#71128), read once at init -- so
// re-exec the test binary with it set. Only Go servers need this; the
// client side keys off peer settings and works against any dataplane
// that advertises extended CONNECT.
func TestMain(m *testing.M) {
	godebug := os.Getenv("GODEBUG")
	if !strings.Contains(godebug, "http2xconnect=1") {
		if godebug != "" {
			godebug += ","
		}
		env := append(os.Environ(), "GODEBUG="+godebug+"http2xconnect=1")
		exe, err := os.Executable()
		if err == nil {
			syscall.Exec(exe, os.Args, env)
		}
		// Exec only returns on failure; fall through and let the
		// extended CONNECT tests fail loudly.
	}
	os.Exit(m.Run())
}

// h2TestBoundary is an in-process multiplexed boundary: CONNECT streams
// echo, extended CONNECT streams echo capsules, evil.example is refused.
type h2TestBoundary struct {
	mu        sync.Mutex
	dialCount int
	targets   []string
	sandboxID string
	udpPaths  []string
}

type h2FlushWriter struct {
	w http.ResponseWriter
	f http.Flusher
}

func (fw h2FlushWriter) Write(p []byte) (int, error) {
	n, err := fw.w.Write(p)
	if err == nil {
		fw.f.Flush()
	}
	return n, err
}

func (b *h2TestBoundary) handler(w http.ResponseWriter, r *http.Request) {
	f := w.(http.Flusher)
	b.mu.Lock()
	b.sandboxID = r.Header.Get("Sandbox-Id")
	b.mu.Unlock()
	if proto := r.Header.Get(":protocol"); proto == "connect-udp" {
		b.mu.Lock()
		b.udpPaths = append(b.udpPaths, r.URL.Path)
		b.mu.Unlock()
		w.Header().Set("Capsule-Protocol", "?1")
		w.WriteHeader(http.StatusOK)
		f.Flush()
		cs := NewCapsuleStream(struct {
			io.Reader
			io.Writer
		}{r.Body, h2FlushWriter{w, f}})
		for {
			p, err := cs.ReadDatagram()
			if err != nil {
				return
			}
			if cs.WriteDatagram(p) != nil {
				return
			}
		}
	}
	if r.Host == "evil.example:443" {
		w.Header().Set("Boundary-Reason", "not-on-allowlist")
		w.WriteHeader(http.StatusForbidden)
		return
	}
	b.mu.Lock()
	b.targets = append(b.targets, r.Host)
	b.mu.Unlock()
	w.WriteHeader(http.StatusOK)
	f.Flush()
	io.Copy(h2FlushWriter{w, f}, r.Body) // echo
}

func (b *h2TestBoundary) dial(ctx context.Context) (net.Conn, error) {
	b.mu.Lock()
	b.dialCount++
	b.mu.Unlock()
	client, server := net.Pipe()
	h2s := &http2.Server{}
	go h2s.ServeConn(server, &http2.ServeConnOpts{Handler: http.HandlerFunc(b.handler)})
	return client, nil
}

func TestH2DialTCPEchoAndMultiplexing(t *testing.T) {
	b := &h2TestBoundary{}
	c := &BoundaryClientH2{DialBoundary: b.dial, Header: http.Header{"Sandbox-Id": []string{"agent-h2"}}}

	// Two concurrent flows must share ONE boundary connection.
	var conns []net.Conn
	for i := 0; i < 2; i++ {
		conn, err := c.DialTCP(context.Background(), "api.example", 443)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		conns = append(conns, conn)
	}
	for i, conn := range conns {
		msg := []byte{byte('a' + i), 'i', 'n', 'g'}
		if _, err := conn.Write(msg); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, len(msg))
		if _, err := io.ReadFull(conn, buf); err != nil {
			t.Fatal(err)
		}
		if string(buf) != string(msg) {
			t.Fatalf("echo = %q, want %q", buf, msg)
		}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.dialCount != 1 {
		t.Fatalf("boundary dialed %d times, want 1 multiplexed session", b.dialCount)
	}
	if b.sandboxID != "agent-h2" {
		t.Fatalf("Sandbox-Id = %q, not forwarded", b.sandboxID)
	}
}

func TestH2DialTCPRefusalIsDialError(t *testing.T) {
	b := &h2TestBoundary{}
	c := &BoundaryClientH2{DialBoundary: b.dial}
	_, err := c.DialTCP(context.Background(), "evil.example", 443)
	var de *DialError
	if !errors.As(err, &de) {
		t.Fatalf("want *DialError, got %v", err)
	}
	if de.StatusCode != http.StatusForbidden || de.Reason != "not-on-allowlist" {
		t.Fatalf("refusal not preserved: %+v", de)
	}
}

func TestH2DialUDPExtendedConnectEcho(t *testing.T) {
	b := &h2TestBoundary{}
	c := &BoundaryClientH2{DialBoundary: b.dial}
	sess, err := c.DialUDP(context.Background(), "stun.example", 3478)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	if err := sess.WriteDatagram([]byte("probe")); err != nil {
		t.Fatal(err)
	}
	p, err := sess.ReadDatagram()
	if err != nil {
		t.Fatal(err)
	}
	if string(p) != "probe" {
		t.Fatalf("echo = %q", p)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.udpPaths) != 1 || b.udpPaths[0] != "/.well-known/masque/udp/stun.example/3478/" {
		t.Fatalf("connect-udp path = %v", b.udpPaths)
	}
}

// TestEngineOverH2Boundary is the full stack on the v2 wire: guest gVisor
// stack -> engine -> one h2 session -> boundary, name preserved.
func TestEngineOverH2Boundary(t *testing.T) {
	b := &h2TestBoundary{}
	n := newTestNetWithDialer(t, &BoundaryClientH2{DialBoundary: b.dial})
	addr, err := n.dns.Resolve4("api.example.test")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for range 2 {
		conn, err := gonet.DialContextTCP(ctx, n.guest, fullAddr(addr, 443), ipv4.ProtocolNumber)
		if err != nil {
			t.Fatal(err)
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
		conn.Close()
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.targets) != 2 || b.targets[0] != "api.example.test:443" {
		t.Fatalf("boundary saw %v, want the NAME api.example.test", b.targets)
	}
	if b.dialCount != 1 {
		t.Fatalf("boundary dialed %d times, want 1 multiplexed session", b.dialCount)
	}
}
