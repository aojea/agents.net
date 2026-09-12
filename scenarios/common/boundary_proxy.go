package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
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

	// Extract Linux SO_PEERCRED if this is a Unix Domain Socket
	if unixConn, ok := conn.(*net.UnixConn); ok {
		raw, err := unixConn.SyscallConn()
		if err == nil {
			raw.Control(func(fd uintptr) {
				ucred, err := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
				if err == nil && ucred != nil {
					peerUID = ucred.Uid
					capsuleID = fmt.Sprintf("capsule-pid-%d-uid-%d", ucred.Pid, ucred.Uid)
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

	// Authorize destination: Reject IP literals outright (agents.net core rule)
	if _, err := netip.ParseAddr(host); err == nil {
		recordAudit("BLOCK ip-literal", target, capsuleID)
		fmt.Fprintf(conn, "HTTP/1.1 403 Forbidden\r\nBoundary-Reason: ip-literal\r\nContent-Length: 0\r\n\r\n")
		return
	}

	hostLower := strings.ToLower(host)
	if !allowAll && !allowedHosts[hostLower] {
		recordAudit("BLOCK not-on-allowlist", target, capsuleID)
		fmt.Fprintf(conn, "HTTP/1.1 403 Forbidden\r\nBoundary-Reason: not-on-allowlist\r\nContent-Length: 0\r\n\r\n")
		return
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
