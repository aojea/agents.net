package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

var (
	listenAddr = flag.String("listen", "127.0.0.1:18080", "Address to listen on (e.g. 127.0.0.1:18080, tcp://127.0.0.1:18080, or unix:///path)")
	vsockDest  = flag.String("vsock", "", "VSOCK destination CID:port (e.g. 1:10088 or 2:10088)")
	targetAddr = flag.String("target", "", "Generic target address (e.g. tcp://127.0.0.1:9080 or unix:///path, used for testing)")
)

type vsockConn struct {
	*os.File
	laddr vsockAddr
	raddr vsockAddr
}

func (c *vsockConn) LocalAddr() net.Addr                { return c.laddr }
func (c *vsockConn) RemoteAddr() net.Addr               { return c.raddr }
func (c *vsockConn) SetDeadline(t time.Time) error      { return c.File.SetDeadline(t) }
func (c *vsockConn) SetReadDeadline(t time.Time) error  { return c.File.SetReadDeadline(t) }
func (c *vsockConn) SetWriteDeadline(t time.Time) error { return c.File.SetWriteDeadline(t) }

type vsockAddr struct {
	cid  uint32
	port uint32
}

func (a vsockAddr) Network() string { return "vsock" }
func (a vsockAddr) String() string  { return fmt.Sprintf("%d:%d", a.cid, a.port) }

func parseVsockAddr(addr string) (uint32, uint32, error) {
	clean := strings.TrimPrefix(addr, "vsock://")
	parts := strings.Split(clean, ":")
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("expected <cid>:<port>, got %q", addr)
	}
	cid, err := strconv.ParseUint(parts[0], 10, 32)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid CID %q: %w", parts[0], err)
	}
	port, err := strconv.ParseUint(parts[1], 10, 32)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid port %q: %w", parts[1], err)
	}
	return uint32(cid), uint32(port), nil
}

func dialVsock(cid, port uint32) (net.Conn, error) {
	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM, 0)
	if err != nil {
		return nil, fmt.Errorf("socket(AF_VSOCK): %w", err)
	}

	sa := &unix.SockaddrVM{
		CID:  cid,
		Port: port,
	}
	if err := unix.Connect(fd, sa); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("connect(AF_VSOCK %d:%d): %w", cid, port, err)
	}

	f := os.NewFile(uintptr(fd), "vsock-client")
	return &vsockConn{
		File:  f,
		laddr: vsockAddr{cid: unix.VMADDR_CID_ANY, port: 0},
		raddr: vsockAddr{cid: cid, port: port},
	}, nil
}

type DialerFunc func() (net.Conn, error)

type Forwarder struct {
	listener net.Listener
	dialer   DialerFunc
	active   atomic.Int64
	total    atomic.Uint64
	bytes    atomic.Uint64
}

func NewForwarder(ln net.Listener, dialer DialerFunc) *Forwarder {
	return &Forwarder{
		listener: ln,
		dialer:   dialer,
	}
}

func (f *Forwarder) Run(ctx context.Context) error {
	for {
		conn, err := f.listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				return err
			}
		}

		f.active.Add(1)
		f.total.Add(1)
		go func(c net.Conn) {
			defer func() {
				c.Close()
				f.active.Add(-1)
			}()

			target, err := f.dialer()
			if err != nil {
				log.Printf("[Forwarder] failed to dial target: %v", err)
				return
			}
			defer target.Close()

			f.bridge(c, target)
		}(conn)
	}
}

func (f *Forwarder) bridge(c1, c2 net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		n, _ := io.Copy(c2, c1)
		f.bytes.Add(uint64(n))
		if tc, ok := c2.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	go func() {
		defer wg.Done()
		n, _ := io.Copy(c1, c2)
		f.bytes.Add(uint64(n))
		if tc, ok := c1.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	wg.Wait()
}

func listen(addr string) (net.Listener, error) {
	if strings.HasPrefix(addr, "unix://") {
		path := strings.TrimPrefix(addr, "unix://")
		os.Remove(path)
		ln, err := net.Listen("unix", path)
		if err == nil {
			os.Chmod(path, 0666)
		}
		return ln, err
	}
	clean := strings.TrimPrefix(addr, "tcp://")
	return net.Listen("tcp", clean)
}

func main() {
	flag.Parse()

	if *vsockDest == "" && *targetAddr == "" {
		log.Fatalf("either -vsock or -target must be specified")
	}

	var dialer DialerFunc
	if *vsockDest != "" {
		cid, port, err := parseVsockAddr(*vsockDest)
		if err != nil {
			log.Fatalf("invalid vsock destination: %v", err)
		}
		dialer = func() (net.Conn, error) {
			return dialVsock(cid, port)
		}
	} else {
		u, err := url.Parse(*targetAddr)
		if err != nil || u.Scheme == "" {
			// Assume tcp
			dialer = func() (net.Conn, error) {
				return net.DialTimeout("tcp", *targetAddr, 5*time.Second)
			}
		} else if u.Scheme == "unix" {
			dialer = func() (net.Conn, error) {
				return net.DialTimeout("unix", u.Path, 5*time.Second)
			}
		} else {
			dialer = func() (net.Conn, error) {
				return net.DialTimeout(u.Scheme, u.Host, 5*time.Second)
			}
		}
	}

	ln, err := listen(*listenAddr)
	if err != nil {
		log.Fatalf("failed to listen on %s: %v", *listenAddr, err)
	}
	defer ln.Close()

	destDesc := *vsockDest
	if destDesc == "" {
		destDesc = *targetAddr
	}
	log.Printf("[Forwarder] Listening on %s -> %s", ln.Addr().String(), destDesc)

	fwd := NewForwarder(ln, dialer)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		log.Printf("[Forwarder] Shutting down...")
		cancel()
		ln.Close()
	}()

	if err := fwd.Run(ctx); err != nil && ctx.Err() == nil {
		log.Fatalf("[Forwarder] fatal error: %v", err)
	}
}
