package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

var (
	listenAddr  = flag.String("listen", "unix:///tmp/boundary.sock", "Listen address (unix:///path or tcp://host:port)")
	allowList   = flag.String("allow", "*", "Allowed destination hostnames, comma-separated (default '*')")
	upstreamMap = flag.String("upstream-map", "", "Host rewrites (e.g. target.internal=127.0.0.1:9999)")
	auditLog    = flag.String("audit-log", "", "Path to audit log file")
)

var (
	allowedHosts = make(map[string]bool)
	allowAll     = false
	rewrites     = make(map[string]string)
	totalFlows   atomic.Uint64
	totalBytes   atomic.Uint64
	auditLogger  *log.Logger
)

type vsockAddr struct {
	cid  uint32
	port uint32
}

func (a vsockAddr) Network() string { return "vsock" }
func (a vsockAddr) String() string  { return fmt.Sprintf("%d:%d", a.cid, a.port) }

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

type vsockListener struct {
	fd   int
	addr vsockAddr
}

func (l *vsockListener) Accept() (net.Conn, error) {
	nfd, rsa, err := unix.Accept(l.fd)
	if err != nil {
		return nil, err
	}
	raddr := vsockAddr{}
	if vsa, ok := rsa.(*unix.SockaddrVM); ok {
		raddr.cid = vsa.CID
		raddr.port = vsa.Port
	}
	f := os.NewFile(uintptr(nfd), "vsock-conn")
	return &vsockConn{File: f, laddr: l.addr, raddr: raddr}, nil
}

func (l *vsockListener) Close() error   { return unix.Close(l.fd) }
func (l *vsockListener) Addr() net.Addr { return l.addr }

func main() {
	flag.Parse()

	for _, h := range strings.Split(*allowList, ",") {
		clean := strings.ToLower(strings.TrimSpace(h))
		if clean == "*" {
			allowAll = true
		} else if clean != "" {
			allowedHosts[clean] = true
		}
	}

	for _, entry := range strings.Split(*upstreamMap, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		parts := strings.SplitN(entry, "=", 2)
		if len(parts) == 2 {
			rewrites[strings.ToLower(strings.TrimSpace(parts[0]))] = strings.TrimSpace(parts[1])
		}
	}

	if *auditLog != "" {
		f, err := os.OpenFile(*auditLog, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			log.Fatalf("failed to open audit log: %v", err)
		}
		defer f.Close()
		auditLogger = log.New(f, "", log.LstdFlags)
	}

	u, err := url.Parse(*listenAddr)
	if err != nil {
		log.Fatalf("invalid listen URL: %v", err)
	}

	var ln net.Listener
	switch u.Scheme {
	case "unix":
		os.Remove(u.Path)
		ln, err = net.Listen("unix", u.Path)
		if err == nil {
			os.Chmod(u.Path, 0666) // Allow unprivileged containers to connect
		}
	case "tcp":
		ln, err = net.Listen("tcp", u.Host)
	case "vsock":
		parts := strings.Split(u.Host, ":")
		portStr := parts[len(parts)-1]
		port, parseErr := strconv.ParseUint(portStr, 10, 32)
		if parseErr != nil {
			log.Fatalf("invalid vsock port %q: %v", portStr, parseErr)
		}
		fd, sErr := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM, 0)
		if sErr != nil {
			log.Fatalf("socket(AF_VSOCK): %v", sErr)
		}
		sa := &unix.SockaddrVM{
			CID:  unix.VMADDR_CID_ANY,
			Port: uint32(port),
		}
		if err = unix.Bind(fd, sa); err != nil {
			log.Fatalf("bind(AF_VSOCK): %v", err)
		}
		if err = unix.Listen(fd, 128); err != nil {
			log.Fatalf("listen(AF_VSOCK): %v", err)
		}
		ln = &vsockListener{fd: fd, addr: vsockAddr{cid: unix.VMADDR_CID_ANY, port: uint32(port)}}
	default:
		log.Fatalf("unsupported scheme: %s", u.Scheme)
	}
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	log.Printf("[Boundary] Listening on %s (allow=%s, rewrites=%d)", *listenAddr, *allowList, len(rewrites))

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept error: %v", err)
			continue
		}
		go handleConnection(conn)
	}
}

func recordAudit(action, target, capsuleID string) {
	msg := fmt.Sprintf("%s target=%s capsule=%s", action, target, capsuleID)
	log.Printf("[AUDIT] %s", msg)
	if auditLogger != nil {
		auditLogger.Println(msg)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	capsuleID := "unknown"
	peerUID := uint32(0)

	// Extract Linux SO_PEERCRED or AF_VSOCK peer CID via SyscallConn
	if sc, ok := conn.(syscall.Conn); ok {
		raw, err := sc.SyscallConn()
		if err == nil {
			raw.Control(func(fd uintptr) {
				// Try SO_PEERCRED (for AF_UNIX)
				ucred, err := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
				if err == nil && ucred != nil && ucred.Pid > 0 {
					peerUID = ucred.Uid
					capsuleID = fmt.Sprintf("capsule-pid-%d-uid-%d", ucred.Pid, ucred.Uid)
					return
				}
				// Try Getpeername (for AF_VSOCK)
				sa, err := unix.Getpeername(int(fd))
				if err == nil {
					if vsa, ok := sa.(*unix.SockaddrVM); ok {
						capsuleID = fmt.Sprintf("capsule-microvm-cid-%d", vsa.CID)
					}
				}
			})
		}
	}

	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}

	if req.Method != http.MethodConnect {
		fmt.Fprintf(conn, "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n")
		return
	}

	target := req.Host
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		host = target
		port = "80"
		target = net.JoinHostPort(host, port)
	}

	// Sanitize untrusted guest headers
	for k := range req.Header {
		if strings.HasPrefix(strings.ToLower(k), "x-capsule-") || strings.EqualFold(k, "sandbox-id") {
			req.Header.Del(k)
		}
	}
	req.Header.Set("X-Capsule-ID", capsuleID)
	req.Header.Set("X-Capsule-Peer-UID", fmt.Sprintf("%d", peerUID))

	// Authorize destination (allowAll or explicit allowList)
	hostLower := strings.ToLower(host)
	if !allowAll && !allowedHosts[hostLower] {
		// Also allow if target matches (e.g. host:port)
		if !allowedHosts[strings.ToLower(target)] {
			recordAudit("BLOCK not-on-allowlist", target, capsuleID)
			fmt.Fprintf(conn, "HTTP/1.1 403 Forbidden\r\nBoundary-Reason: not-on-allowlist\r\nContent-Length: 0\r\n\r\n")
			return
		}
	}

	// Dial upstream (applying any rewrites for local test targets)
	dialTarget := target
	if rewrite, exists := rewrites[hostLower]; exists {
		dialTarget = rewrite
	}

	upstream, err := net.DialTimeout("tcp", dialTarget, 5*time.Second)
	if err != nil {
		recordAudit("DIAL-FAIL", target, capsuleID)
		fmt.Fprintf(conn, "HTTP/1.1 502 Bad Gateway\r\nBoundary-Reason: dial-failed\r\nContent-Length: 0\r\n\r\n")
		return
	}
	defer upstream.Close()

	recordAudit("ALLOW tcp", target, capsuleID)
	totalFlows.Add(1)

	// Handshake complete: HTTP 200 OK tunnel established
	io.WriteString(conn, "HTTP/1.1 200 OK\r\n\r\n")

	// Bidirectional data transfer
	errc := make(chan error, 2)
	go func() {
		n, err := io.Copy(upstream, br)
		totalBytes.Add(uint64(n))
		errc <- err
	}()
	go func() {
		n, err := io.Copy(conn, upstream)
		totalBytes.Add(uint64(n))
		errc <- err
	}()
	<-errc
}
