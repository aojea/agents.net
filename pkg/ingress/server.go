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

// Package ingress implements the node-local HTTP CONNECT ingress bridge for
// kube-net-driver. Authorized callers (such as kube-inbound or Envoy) connect
// to this host listener, issue "CONNECT <podUID>:<port> HTTP/1.1", and the
// server checks the Pod's ingressPorts allowlist before dialing either the
// sandbox guest over kube-netstack (for L2 sandboxes such as gVisor or microVMs)
// or the Pod's loopback 127.0.0.1:<port> via socketat (for runc containers).
package ingress

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"k8s.io/apimachinery/pkg/types"
	"k8s.io/klog/v2"

	"github.com/aojea/agents.net/pkg/apis"
	"github.com/aojea/agents.net/pkg/auth"
	"github.com/aojea/agents.net/pkg/metrics"
	"github.com/aojea/agents.net/pkg/socketat"
	"github.com/aojea/agents.net/pkg/store"
)

const (
	defaultDialTimeout = 5 * time.Second
	defaultHeadTimeout = 5 * time.Second
	maxHeadBytes       = 8 * 1024
	maxIngressConns    = 4096
)

// DialNetNSFunc dials a literal IP:port inside a Linux network namespace.
type DialNetNSFunc func(netnsPath, network, address string, timeout time.Duration) (net.Conn, error)

// DialGuestFunc opens an inbound TCP connection into an L2 sandbox guest
// (such as gVisor or a microVM) through kube-netstack.
type DialGuestFunc func(ctx context.Context, podUID types.UID, guestIP netip.Addr, port uint16) (net.Conn, error)

// Config configures the node-local ingress bridge.
type Config struct {
	ListenAddr  string
	Store       *store.PodConfigStore
	TLSConfig   *tls.Config
	DialNetNS   DialNetNSFunc
	DialGuest   DialGuestFunc
	DialTimeout time.Duration
	HeadTimeout time.Duration
}

// Server accepts HTTP/1.1 CONNECT <podUID>:<port> requests on the node host
// network and tunnels allowed connections into the target sandbox Pod.
type Server struct {
	listenAddr  string
	store       *store.PodConfigStore
	tlsConfig   *tls.Config
	dialNetNS   DialNetNSFunc
	dialGuest   DialGuestFunc
	dialTimeout time.Duration
	headTimeout time.Duration

	mu          sync.Mutex
	ln          net.Listener
	closed      bool
	revoked     map[types.UID]struct{}
	active      map[types.UID]map[net.Conn]func()
	activeConns atomic.Int64
	wg          sync.WaitGroup
}

// NewServer constructs an ingress Server without starting its listener.
func NewServer(cfg Config) (*Server, error) {
	if cfg.ListenAddr == "" {
		return nil, errors.New("ingress listen address is required")
	}
	if cfg.Store == nil {
		return nil, errors.New("pod config store is required")
	}
	dialNetNS := cfg.DialNetNS
	if dialNetNS == nil {
		dialNetNS = socketat.DialAtPath
	}
	dialTimeout := cfg.DialTimeout
	if dialTimeout <= 0 {
		dialTimeout = defaultDialTimeout
	}
	headTimeout := cfg.HeadTimeout
	if headTimeout <= 0 {
		headTimeout = defaultHeadTimeout
	}
	return &Server{
		listenAddr:  cfg.ListenAddr,
		store:       cfg.Store,
		tlsConfig:   cfg.TLSConfig,
		dialNetNS:   dialNetNS,
		dialGuest:   cfg.DialGuest,
		dialTimeout: dialTimeout,
		headTimeout: headTimeout,
		revoked:     make(map[types.UID]struct{}),
		active:      make(map[types.UID]map[net.Conn]func()),
	}, nil
}

// Start binds the TCP (or TLS/mTLS) listener and begins serving in the background.
func (s *Server) Start() (net.Addr, error) {
	rawLn, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return nil, fmt.Errorf("listen ingress %q: %w", s.listenAddr, err)
	}
	ln := rawLn
	if s.tlsConfig != nil {
		ln = tls.NewListener(rawLn, s.tlsConfig.Clone())
	}

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		_ = ln.Close()
		return nil, errors.New("ingress server already closed")
	}
	s.ln = ln
	s.wg.Go(func() { s.acceptLoop(ln) })
	s.mu.Unlock()

	klog.InfoS("dra-agents-net ingress bridge listening", "addr", ln.Addr().String(), "tls", s.tlsConfig != nil)
	return ln.Addr(), nil
}

// Close stops accepting new connections, closes active ingress tunnels, and waits
// for all connection goroutines to finish.
func (s *Server) Close() error {
	s.mu.Lock()
	s.closed = true
	ln := s.ln
	s.ln = nil
	var closers []func()
	for uid, conns := range s.active {
		for c, cancel := range conns {
			closers = append(closers, func() {
				cancel()
				_ = c.Close()
			})
		}
		delete(s.active, uid)
	}
	s.mu.Unlock()

	var err error
	if ln != nil {
		err = ln.Close()
	}
	for _, fn := range closers {
		fn()
	}
	s.wg.Wait()
	return err
}

// Revoke immediately closes all active and in-flight ingress connections for podUID
// and rejects new ingress attempts until Allow is called.
func (s *Server) Revoke(podUID types.UID) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.revoked[podUID] = struct{}{}
	conns := s.active[podUID]
	delete(s.active, podUID)
	s.mu.Unlock()

	for c, cancel := range conns {
		cancel()
		_ = c.Close()
	}
}

// Allow clears a prior Revoke marker for podUID (called when a PodSandbox starts
// or after podUID has been removed from the store so the revoked set stays bounded).
func (s *Server) Allow(podUID types.UID) {
	if s == nil {
		return
	}
	s.mu.Lock()
	delete(s.revoked, podUID)
	s.mu.Unlock()
}

func (s *Server) acceptLoop(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		if s.activeConns.Add(1) > maxIngressConns {
			s.activeConns.Add(-1)
			metrics.IngressConnectionsTotal.WithLabelValues("deny", "max_connections").Inc()
			s.writeError(conn, http.StatusServiceUnavailable, "busy")
			_ = conn.Close()
			continue
		}
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			s.activeConns.Add(-1)
			_ = conn.Close()
			return
		}
		s.wg.Go(func() {
			defer func() {
				s.activeConns.Add(-1)
				_ = conn.Close()
			}()
			s.serveConn(conn)
		})
		s.mu.Unlock()
	}
}

func (s *Server) registerConn(podUID types.UID, client net.Conn, cancel func()) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	if _, isRevoked := s.revoked[podUID]; isRevoked {
		return false
	}
	if s.active[podUID] == nil {
		s.active[podUID] = make(map[net.Conn]func())
	}
	s.active[podUID][client] = cancel
	return true
}

func (s *Server) updateConnCancel(podUID types.UID, client net.Conn, cancel func()) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	if _, isRevoked := s.revoked[podUID]; isRevoked {
		return false
	}
	conns := s.active[podUID]
	if conns == nil {
		return false
	}
	if _, ok := conns[client]; !ok {
		return false
	}
	conns[client] = cancel
	return true
}

func (s *Server) untrackConn(podUID types.UID, client net.Conn) {
	s.mu.Lock()
	if conns := s.active[podUID]; conns != nil {
		delete(conns, client)
		if len(conns) == 0 {
			delete(s.active, podUID)
		}
	}
	s.mu.Unlock()
}

func (s *Server) serveConn(conn net.Conn) {
	_ = conn.SetReadDeadline(time.Now().Add(s.headTimeout))
	br := bufio.NewReader(io.LimitReader(conn, maxHeadBytes))
	podUID, port, status, reason := readConnectHead(br)
	if status != 0 {
		metrics.IngressConnectionsTotal.WithLabelValues("deny", "malformed").Inc()
		s.writeError(conn, status, reason)
		return
	}
	_ = conn.SetReadDeadline(time.Time{})

	cfg, ok := s.store.Get(podUID)
	if !ok {
		metrics.IngressConnectionsTotal.WithLabelValues("deny", "unknown_sandbox").Inc()
		s.writeError(conn, http.StatusNotFound, "unknown-sandbox")
		return
	}
	if !isTCPPortAllowed(cfg.Parameters.IngressPorts, port) {
		metrics.IngressConnectionsTotal.WithLabelValues("deny", "port_denied").Inc()
		s.writeError(conn, http.StatusForbidden, "port-not-permitted")
		return
	}

	dialCtx, dialCancel := context.WithTimeout(context.Background(), s.dialTimeout)
	defer dialCancel()
	if !s.registerConn(podUID, conn, dialCancel) {
		metrics.IngressConnectionsTotal.WithLabelValues("deny", "revoked").Inc()
		s.writeError(conn, http.StatusNotFound, "sandbox-revoked")
		return
	}
	defer s.untrackConn(podUID, conn)

	backend, err := s.dialPod(dialCtx, cfg, port)
	if err != nil {
		if errors.Is(err, errPodNotReady) {
			metrics.IngressConnectionsTotal.WithLabelValues("error", "not_ready").Inc()
			s.writeError(conn, http.StatusServiceUnavailable, "sandbox-not-ready")
			return
		}
		klog.InfoS("dra-agents-net ingress dial failed", "podUID", podUID, "guestIP", cfg.GuestIP, "port", port, "err", err)
		metrics.IngressConnectionsTotal.WithLabelValues("error", "dial_failed").Inc()
		s.writeError(conn, http.StatusBadGateway, "ingress-dial-failed")
		return
	}
	defer func() { _ = backend.Close() }()

	if !s.updateConnCancel(podUID, conn, func() {
		dialCancel()
		_ = backend.Close()
	}) {
		metrics.IngressConnectionsTotal.WithLabelValues("deny", "revoked").Inc()
		s.writeError(conn, http.StatusNotFound, "sandbox-revoked")
		return
	}

	_ = conn.SetWriteDeadline(time.Now().Add(s.headTimeout))
	if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	_ = conn.SetWriteDeadline(time.Time{})

	metrics.IngressConnectionsTotal.WithLabelValues("allow", "allowed").Inc()

	// Drain any bytes buffered by bufio.Reader before switching directly to conn.
	clientReader := io.Reader(conn)
	if br.Buffered() > 0 {
		buffered := make([]byte, br.Buffered())
		if n, _ := io.ReadFull(br, buffered); n > 0 {
			clientReader = io.MultiReader(strings.NewReader(string(buffered[:n])), conn)
		}
	}

	relayBidirectional(clientReader, conn, backend)
}

var errPodNotReady = errors.New("sandbox network namespace not ready")

func (s *Server) dialPod(ctx context.Context, cfg store.PodConfig, port int32) (net.Conn, error) {
	// For L2 sandboxes (such as gVisor or microVMs) where kube-netstack owns
	// the guest link, dial the guest IP directly through kube-netstack.
	if cfg.GuestIP != "" && s.dialGuest != nil {
		ip, err := netip.ParseAddr(cfg.GuestIP)
		if err != nil {
			return nil, fmt.Errorf("invalid guest IP %q for pod %s: %w", cfg.GuestIP, cfg.PodUID, err)
		}
		return s.dialGuest(ctx, cfg.PodUID, ip, uint16(port))
	}
	if cfg.NetNS == "" {
		return nil, errPodNotReady
	}
	portStr := strconv.FormatInt(int64(port), 10)
	conn, err := s.dialNetNS(cfg.NetNS, "tcp", net.JoinHostPort("127.0.0.1", portStr), s.dialTimeout)
	if err == nil || ctx.Err() != nil {
		return conn, err
	}
	// Fall back to IPv6 loopback for IPv6-only listeners inside the Pod netns.
	conn6, err6 := s.dialNetNS(cfg.NetNS, "tcp", net.JoinHostPort("::1", portStr), s.dialTimeout)
	if err6 == nil {
		return conn6, nil
	}
	return nil, err
}

func (s *Server) writeError(conn net.Conn, status int, reason string) {
	_ = conn.SetWriteDeadline(time.Now().Add(s.headTimeout))
	text := http.StatusText(status)
	if text == "" {
		text = "Error"
	}
	proxyStatus := apis.FormatProxyStatus("dra-agents-net-ingress", status, reason)
	_, _ = fmt.Fprintf(conn,
		"HTTP/1.1 %d %s\r\nProxy-Status: %s\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
		status, text, proxyStatus,
	)
}

func readConnectHead(br *bufio.Reader) (types.UID, int32, int, string) {
	line, err := br.ReadString('\n')
	if err != nil || !strings.HasSuffix(line, "\r\n") {
		return "", 0, http.StatusBadRequest, "malformed-request-line"
	}
	parts := strings.Split(strings.TrimSuffix(line, "\r\n"), " ")
	if len(parts) != 3 {
		return "", 0, http.StatusBadRequest, "malformed-request-line"
	}
	method, target, version := parts[0], parts[1], parts[2]
	if version != "HTTP/1.1" && version != "HTTP/1.0" {
		if strings.HasPrefix(version, "HTTP/") {
			return "", 0, http.StatusHTTPVersionNotSupported, "unsupported-version"
		}
		return "", 0, http.StatusBadRequest, "malformed-request-line"
	}
	if method != http.MethodConnect {
		return "", 0, http.StatusMethodNotAllowed, "method-not-allowed"
	}

	var hostHeader string
	hostCount := 0
	for {
		hline, err := br.ReadString('\n')
		if err != nil || !strings.HasSuffix(hline, "\r\n") {
			return "", 0, http.StatusBadRequest, "malformed-header"
		}
		trimmed := strings.TrimSuffix(hline, "\r\n")
		if trimmed == "" {
			break
		}
		k, v, ok := strings.Cut(trimmed, ":")
		if !ok || k == "" || strings.ContainsAny(k, " \t") {
			return "", 0, http.StatusBadRequest, "malformed-header"
		}
		if strings.EqualFold(k, "host") {
			hostCount++
			hostHeader = strings.TrimSpace(v)
		}
	}
	if hostCount > 1 {
		return "", 0, http.StatusBadRequest, "duplicate-host"
	}
	if version == "HTTP/1.1" && hostCount == 0 {
		return "", 0, http.StatusBadRequest, "missing-host"
	}
	if hostCount == 1 && !strings.EqualFold(hostHeader, target) {
		return "", 0, http.StatusBadRequest, "authority-mismatch"
	}

	rawUID, rawPort, err := net.SplitHostPort(target)
	if err != nil || rawUID == "" || rawPort == "" {
		return "", 0, http.StatusBadRequest, "malformed-authority"
	}
	if err := auth.ValidatePodUID(types.UID(rawUID)); err != nil {
		return "", 0, http.StatusBadRequest, "malformed-authority"
	}
	portNum, err := strconv.ParseInt(rawPort, 10, 32)
	if err != nil || portNum < 1 || portNum > 65535 {
		return "", 0, http.StatusBadRequest, "invalid-port"
	}
	return types.UID(rawUID), int32(portNum), 0, ""
}

func isTCPPortAllowed(ports []apis.IngressPort, port int32) bool {
	for _, p := range ports {
		if p.Contains(port, apis.IngressProtocolTCP) {
			return true
		}
	}
	return false
}

type closeWriter interface {
	CloseWrite() error
}

func relayBidirectional(clientR io.Reader, clientW net.Conn, backend net.Conn) {
	var wg sync.WaitGroup
	wg.Go(func() {
		_, _ = io.Copy(backend, clientR)
		if cw, ok := backend.(closeWriter); ok {
			_ = cw.CloseWrite()
		} else {
			_ = backend.Close()
		}
	})
	_, _ = io.Copy(clientW, backend)
	if cw, ok := clientW.(closeWriter); ok {
		_ = cw.CloseWrite()
	}
	_ = clientW.Close()
	wg.Wait()
}
