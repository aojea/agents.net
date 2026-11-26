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

// Package tunnel implements the per-node agents.net UDS listener manager that
// accepts intercepted HTTP CONNECT and RFC 9298 connect-udp streams from sandbox
// Pods and forwards them over authenticated TLS/mTLS/SPIFFE/JWT tunnels to the
// configured upstream gateway or portal.
package tunnel

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
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
	"github.com/aojea/agents.net/pkg/store"
)

const (
	// EgressSocketName is the standardized agents.net egress UDS filename.
	EgressSocketName = "egress.sock"

	defaultDialTimeout = 10 * time.Second
	defaultHeadTimeout = 10 * time.Second
	defaultMaxConns    = 1024
	defaultIdleSecs    = 300
)

// AuditRecord is a structured agents.net JSONL audit entry emitted per tunnel request.
type AuditRecord struct {
	Timestamp      string `json:"ts"`
	Sandbox        string `json:"sandbox"`
	PodUID         string `json:"pod_uid"`
	Connection     string `json:"conn"`
	Transport      string `json:"transport"`
	Target         string `json:"target,omitempty"`
	AuthMode       string `json:"auth_mode"`
	Decision       string `json:"decision"`
	UpstreamStatus int    `json:"upstream_status,omitempty"`
	Reason         string `json:"reason,omitempty"`
	BytesOut       int64  `json:"bytes_out,omitempty"`
	BytesIn        int64  `json:"bytes_in,omitempty"`
	DurationMS     int64  `json:"duration_ms,omitempty"`
}

// ListenerConfig configures a single Pod's agents.net egress UDS listener and its
// mTLS Policy Enforcement Point (PEP) forwarding channel.
type ListenerConfig struct {
	Identity               auth.WorkloadIdentity
	PolicyEnforcementPoint *apis.PolicyEnforcementPointConfig
	DNSMode                apis.DNSMode
	DNSEnforcementPoint    *apis.PolicyEnforcementPointConfig
	PodCertVolumeName      string
	MaxConnections         int
	IdleTimeoutSeconds     int
}

// ManagerOption customizes a tunnel Manager.
type ManagerOption func(*Manager)

// WithAuditWriter sets the JSONL audit destination (defaults to os.Stderr).
func WithAuditWriter(w io.Writer) ManagerOption {
	return func(m *Manager) {
		if w != nil {
			m.auditOut = w
		}
	}
}

// WithDialContext overrides raw network dialing for offline tests.
func WithDialContext(fn func(ctx context.Context, network, addr string) (net.Conn, error)) ManagerOption {
	return func(m *Manager) { m.dialNet = fn }
}

// WithTimeouts overrides dial and request-head read timeouts.
func WithTimeouts(dialTimeout, headTimeout time.Duration) ManagerOption {
	return func(m *Manager) {
		if dialTimeout > 0 {
			m.dialTimeout = dialTimeout
		}
		if headTimeout > 0 {
			m.headTimeout = headTimeout
		}
	}
}

// Manager owns per-Pod agents.net Unix domain socket listeners on a node.
type Manager struct {
	rootDir     string
	authRes     *auth.Resolver
	dialTimeout time.Duration
	headTimeout time.Duration
	dialNet     func(ctx context.Context, network, addr string) (net.Conn, error)

	auditMu  sync.Mutex
	auditOut io.Writer

	mu        sync.Mutex
	listeners map[types.UID]*sandboxListener
	podLocks  map[types.UID]*podLockEntry
	connSeq   atomic.Uint64
}

type podLockEntry struct {
	mu   sync.Mutex
	refs int
}

func (m *Manager) lockPod(podUID types.UID) func() {
	m.mu.Lock()
	entry := m.podLocks[podUID]
	if entry == nil {
		entry = &podLockEntry{}
		m.podLocks[podUID] = entry
	}
	entry.refs++
	m.mu.Unlock()

	entry.mu.Lock()
	return func() {
		entry.mu.Unlock()
		m.mu.Lock()
		entry.refs--
		if entry.refs == 0 {
			delete(m.podLocks, podUID)
		}
		m.mu.Unlock()
	}
}

// NewManager creates a Manager storing per-Pod sockets under rootDir.
func NewManager(rootDir string, authResolver *auth.Resolver, opts ...ManagerOption) (*Manager, error) {
	if rootDir == "" {
		return nil, errors.New("rootDir is required")
	}
	if authResolver == nil {
		authResolver = auth.NewResolver(auth.ResolverConfig{})
	}
	cleanRoot := filepath.Clean(rootDir)
	if err := os.MkdirAll(cleanRoot, 0o711); err != nil {
		return nil, fmt.Errorf("create tunnel socket root %q: %w", cleanRoot, err)
	}
	m := &Manager{
		rootDir:     cleanRoot,
		authRes:     authResolver,
		dialTimeout: defaultDialTimeout,
		headTimeout: defaultHeadTimeout,
		auditOut:    os.Stderr,
		listeners:   make(map[types.UID]*sandboxListener),
		podLocks:    make(map[types.UID]*podLockEntry),
	}
	for _, opt := range opts {
		opt(m)
	}
	return m, nil
}

func (m *Manager) safePodRootDir(podUID types.UID) (string, error) {
	if err := auth.ValidatePodUID(podUID); err != nil {
		return "", err
	}
	podRoot := filepath.Join(m.rootDir, string(podUID))
	rel, err := filepath.Rel(m.rootDir, podRoot)
	if err != nil || strings.HasPrefix(rel, "..") || filepath.IsAbs(rel) || strings.ContainsRune(rel, filepath.Separator) {
		return "", fmt.Errorf("pod directory %q escapes socket root %q", podRoot, m.rootDir)
	}
	return podRoot, nil
}

// EnsureListener creates host socket directories, resolves upstream auth material,
// starts the per-Pod egress.sock listener, and probes socket readiness before returning.
func (m *Manager) EnsureListener(ctx context.Context, podUID types.UID, cfg ListenerConfig) (store.SocketPaths, error) {
	podRoot, err := m.safePodRootDir(podUID)
	if err != nil {
		return store.SocketPaths{}, err
	}
	if cfg.MaxConnections <= 0 {
		cfg.MaxConnections = defaultMaxConns
	}
	if cfg.IdleTimeoutSeconds <= 0 {
		cfg.IdleTimeoutSeconds = defaultIdleSecs
	}

	// Serialize EnsureListener/Remove per podUID so concurrent preparations never
	// unlink a live egress.sock belonging to the same Pod.
	unlockPod := m.lockPod(podUID)
	defer unlockPod()

	m.mu.Lock()
	if existing, ok := m.listeners[podUID]; ok {
		paths := existing.paths
		m.mu.Unlock()
		existing.updateIdentity(cfg.Identity, false)
		return paths, nil
	}
	m.mu.Unlock()

	var dialer *upstreamDialer
	authMode := "none"
	if cfg.PolicyEnforcementPoint != nil && cfg.PolicyEnforcementPoint.URL != "" {
		clientCfg, err := m.authRes.Resolve(ctx, auth.ResolveRequest{
			PolicyEnforcementPoint: cfg.PolicyEnforcementPoint,
			PodNamespace:           cfg.Identity.Namespace,
			PodUID:                 podUID,
			PodCertVolumeName:      cfg.PodCertVolumeName,
		})
		if err != nil {
			return store.SocketPaths{}, fmt.Errorf("resolve PEP auth for pod %s: %w", podUID, err)
		}
		d, err := newUpstreamDialer(cfg.PolicyEnforcementPoint, clientCfg, m.dialTimeout, m.dialNet)
		if err != nil {
			_ = clientCfg.Close()
			return store.SocketPaths{}, fmt.Errorf("configure PEP dialer for pod %s: %w", podUID, err)
		}
		dialer = d
		authMode = clientCfg.AuthMode
	}

	var dnsDialer *upstreamDialer
	dnsAuthMode := authMode
	if cfg.DNSMode == apis.DNSModeDoH {
		if cfg.DNSEnforcementPoint != nil && cfg.DNSEnforcementPoint.URL != "" {
			dnsClientCfg, err := m.authRes.Resolve(ctx, auth.ResolveRequest{
				PolicyEnforcementPoint: cfg.DNSEnforcementPoint,
				PodNamespace:           cfg.Identity.Namespace,
				PodUID:                 podUID,
				PodCertVolumeName:      cfg.PodCertVolumeName,
			})
			if err != nil {
				if dialer != nil {
					_ = dialer.Close()
				}
				return store.SocketPaths{}, fmt.Errorf("resolve DNS PEP auth for pod %s: %w", podUID, err)
			}
			dd, err := newUpstreamDialer(cfg.DNSEnforcementPoint, dnsClientCfg, m.dialTimeout, m.dialNet)
			if err != nil {
				_ = dnsClientCfg.Close()
				if dialer != nil {
					_ = dialer.Close()
				}
				return store.SocketPaths{}, fmt.Errorf("configure DNS PEP dialer for pod %s: %w", podUID, err)
			}
			dnsDialer = dd
			dnsAuthMode = dnsClientCfg.AuthMode
		} else {
			dnsDialer = dialer
		}
	}
	closeDialers := func() {
		if dnsDialer != nil && dnsDialer != dialer {
			_ = dnsDialer.Close()
		}
		if dialer != nil {
			_ = dialer.Close()
		}
	}

	egressDir := filepath.Join(podRoot, "egress")
	if err := os.MkdirAll(egressDir, 0o711); err != nil {
		closeDialers()
		return store.SocketPaths{}, fmt.Errorf("mkdir egress dir %q: %w", egressDir, err)
	}
	paths := store.SocketPaths{
		PodRootDir:       podRoot,
		EgressDir:        egressDir,
		EgressSocketPath: filepath.Join(egressDir, EgressSocketName),
	}

	_ = os.Remove(paths.EgressSocketPath)
	ln, err := net.Listen("unix", paths.EgressSocketPath)
	if err != nil {
		closeDialers()
		return store.SocketPaths{}, fmt.Errorf("listen %q: %w", paths.EgressSocketPath, err)
	}
	if err := os.Chmod(paths.EgressSocketPath, 0o666); err != nil {
		_ = ln.Close()
		closeDialers()
		return store.SocketPaths{}, fmt.Errorf("chmod %q: %w", paths.EgressSocketPath, err)
	}

	revokeCtx, revokeCancel := context.WithCancel(context.Background())
	sl := &sandboxListener{
		manager:      m,
		podUID:       podUID,
		paths:        paths,
		ln:           ln,
		dialer:       dialer,
		authMode:     authMode,
		dnsMode:      cfg.DNSMode,
		dnsDialer:    dnsDialer,
		dnsAuthMode:  dnsAuthMode,
		maxConns:     cfg.MaxConnections,
		idleTimeout:  time.Duration(cfg.IdleTimeoutSeconds) * time.Second,
		revokeCtx:    revokeCtx,
		revokeCancel: revokeCancel,
		identity:     cfg.Identity,
		active:       make(map[net.Conn]func()),
	}

	m.mu.Lock()
	m.listeners[podUID] = sl
	metrics.ActiveSandboxes.Set(float64(len(m.listeners)))
	m.mu.Unlock()

	sl.wg.Go(func() { sl.acceptLoop(ln) })

	if err := probeUnixSocket(paths.EgressSocketPath, 2*time.Second); err != nil {
		_ = m.removeLocked(podUID, podRoot)
		return store.SocketPaths{}, fmt.Errorf("readiness probe failed for %q: %w", paths.EgressSocketPath, err)
	}

	return paths, nil
}

// ServeConn admits an already-connected stream (such as a kernel socketpair
// brokered for kube-netstack) directly into podUID's tunnel pipeline so it
// shares upstream auth, limits, metrics, and Revoke without requiring
// filesystem access to egress.sock.
func (m *Manager) ServeConn(podUID types.UID, conn net.Conn) error {
	if conn == nil {
		return errors.New("connection is required")
	}
	m.mu.Lock()
	sl := m.listeners[podUID]
	m.mu.Unlock()
	if sl == nil {
		_ = conn.Close()
		return fmt.Errorf("no sandbox listener found for pod %s", podUID)
	}
	if !sl.admitConn(conn) {
		return fmt.Errorf("sandbox listener for pod %s rejected connection", podUID)
	}
	return nil
}

// UpdateIdentity refreshes the attested Pod/Sandbox/Claim metadata for podUID.
// When revokeActive is true (for example on warm pool claim adoption), existing
// tunnels are immediately closed so new tunnels carry the updated identity.
func (m *Manager) UpdateIdentity(podUID types.UID, id auth.WorkloadIdentity, revokeActive bool) {
	m.mu.Lock()
	sl := m.listeners[podUID]
	m.mu.Unlock()
	if sl != nil {
		sl.updateIdentity(id, revokeActive)
	}
}

// Revoke immediately blocks new connections and closes all active tunnels for podUID.
func (m *Manager) Revoke(podUID types.UID) {
	m.mu.Lock()
	sl := m.listeners[podUID]
	m.mu.Unlock()
	if sl != nil {
		sl.revoke()
	}
}

// Rearm clears a prior StopPodSandbox revocation and arms a fresh revocation
// context for a newly created PodSandbox sharing the same Pod UID and DRA
// ResourceClaim.
func (m *Manager) Rearm(podUID types.UID) {
	m.mu.Lock()
	sl := m.listeners[podUID]
	m.mu.Unlock()
	if sl != nil {
		sl.rearm()
	}
}

// Remove stops the listener, kills active tunnels, closes upstream auth resources,
// and deletes the Pod's host socket directory.
func (m *Manager) Remove(podUID types.UID) error {
	podRoot, err := m.safePodRootDir(podUID)
	if err != nil {
		return err
	}
	unlockPod := m.lockPod(podUID)
	defer unlockPod()
	return m.removeLocked(podUID, podRoot)
}

func (m *Manager) removeLocked(podUID types.UID, podRoot string) error {
	m.mu.Lock()
	sl, ok := m.listeners[podUID]
	if ok {
		delete(m.listeners, podUID)
		metrics.ActiveSandboxes.Set(float64(len(m.listeners)))
	}
	m.mu.Unlock()

	if ok {
		sl.stop()
	}
	if err := os.RemoveAll(podRoot); err != nil {
		return fmt.Errorf("remove socket dir %q: %w", podRoot, err)
	}
	return nil
}

// Close shuts down all active listeners cleanly.
func (m *Manager) Close() {
	m.mu.Lock()
	all := make([]*sandboxListener, 0, len(m.listeners))
	for _, sl := range m.listeners {
		all = append(all, sl)
	}
	m.listeners = make(map[types.UID]*sandboxListener)
	metrics.ActiveSandboxes.Set(0)
	m.mu.Unlock()

	for _, sl := range all {
		sl.stop()
	}
}

func (m *Manager) emitAudit(rec AuditRecord) {
	rec.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	data, err := json.Marshal(rec)
	if err != nil {
		return
	}
	data = append(data, '\n')
	m.auditMu.Lock()
	defer m.auditMu.Unlock()
	_, _ = m.auditOut.Write(data)
}

func probeUnixSocket(path string, timeout time.Duration) error {
	conn, err := net.DialTimeout("unix", path, timeout)
	if err != nil {
		return err
	}
	return conn.Close()
}

type sandboxListener struct {
	manager     *Manager
	podUID      types.UID
	paths       store.SocketPaths
	ln          net.Listener
	dialer      *upstreamDialer
	authMode    string
	dnsMode     apis.DNSMode
	dnsDialer   *upstreamDialer
	dnsAuthMode string
	maxConns    int
	idleTimeout time.Duration

	mu           sync.RWMutex
	revokeCtx    context.Context
	revokeCancel context.CancelFunc
	identity     auth.WorkloadIdentity
	identityGen  uint64
	revoked      bool
	stopped      bool
	active       map[net.Conn]func()

	stopOnce sync.Once
	wg       sync.WaitGroup
}

func (l *sandboxListener) rearm() {
	l.mu.Lock()
	if l.stopped {
		l.mu.Unlock()
		return
	}
	oldCancel := l.revokeCancel
	closers := make([]func(), 0, len(l.active))
	for conn, closeFn := range l.active {
		closers = append(closers, closeFn)
		_ = conn.Close()
	}
	l.revokeCtx, l.revokeCancel = context.WithCancel(context.Background())
	l.revoked = false
	l.mu.Unlock()

	oldCancel()
	for _, fn := range closers {
		fn()
	}
}

func (l *sandboxListener) updateIdentity(id auth.WorkloadIdentity, revokeActive bool) {
	l.mu.Lock()
	l.identity = id
	var closers []func()
	if revokeActive {
		l.identityGen++
		for conn, closeFn := range l.active {
			closers = append(closers, closeFn)
			_ = conn.Close()
		}
	}
	l.mu.Unlock()
	for _, fn := range closers {
		fn()
	}
}

func (l *sandboxListener) revoke() {
	l.mu.Lock()
	cancel := l.revokeCancel
	l.revoked = true
	closers := make([]func(), 0, len(l.active))
	for conn, closeFn := range l.active {
		closers = append(closers, closeFn)
		_ = conn.Close()
	}
	l.mu.Unlock()
	cancel()
	for _, fn := range closers {
		fn()
	}
}

func (l *sandboxListener) stop() {
	l.stopOnce.Do(func() {
		l.mu.Lock()
		l.stopped = true
		l.mu.Unlock()

		l.revoke()
		_ = l.ln.Close()
		l.wg.Wait()
		if l.dnsDialer != nil && l.dnsDialer != l.dialer {
			_ = l.dnsDialer.Close()
		}
		if l.dialer != nil {
			_ = l.dialer.Close()
		}
	})
}

func (l *sandboxListener) acceptLoop(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		if !l.admitConn(conn) {
			l.mu.RLock()
			stopped := l.stopped
			l.mu.RUnlock()
			if stopped {
				return
			}
		}
	}
}

func (l *sandboxListener) admitConn(conn net.Conn) bool {
	l.mu.Lock()
	if l.stopped {
		l.mu.Unlock()
		_ = conn.Close()
		return false
	}
	if l.revoked {
		l.mu.Unlock()
		metrics.TunnelsTotal.WithLabelValues("tcp", l.authMode, "deny", "listener_revoked").Inc()
		writeH1Deny(conn, l.manager.headTimeout, http.StatusServiceUnavailable, "listener-revoked")
		_ = conn.Close()
		return false
	}
	if len(l.active) >= l.maxConns {
		l.mu.Unlock()
		metrics.TunnelsTotal.WithLabelValues("tcp", l.authMode, "deny", "max_connections").Inc()
		writeH1Deny(conn, l.manager.headTimeout, http.StatusServiceUnavailable, "busy")
		_ = conn.Close()
		return false
	}
	l.active[conn] = func() {}
	metrics.ActiveTunnels.Inc()
	// Start handler goroutine while holding l.mu so wg.Add(1) happens-before stop()'s wg.Wait().
	l.wg.Go(func() {
		defer func() {
			l.mu.Lock()
			delete(l.active, conn)
			l.mu.Unlock()
			metrics.ActiveTunnels.Dec()
			_ = conn.Close()
		}()
		l.serveConn(conn)
	})
	l.mu.Unlock()
	return true
}

func (l *sandboxListener) setConnCloser(conn net.Conn, gen uint64, fn func()) bool {
	l.mu.Lock()
	if l.revoked || l.stopped || l.identityGen != gen {
		l.mu.Unlock()
		return false
	}
	if _, ok := l.active[conn]; ok {
		l.active[conn] = fn
	}
	l.mu.Unlock()
	return true
}

func (l *sandboxListener) snapshotIdentityAndContext() (auth.WorkloadIdentity, uint64, context.Context) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.identity, l.identityGen, l.revokeCtx
}

func (l *sandboxListener) snapshotIdentity() auth.WorkloadIdentity {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.identity
}

func (l *sandboxListener) serveConn(conn net.Conn) {
	start := time.Now()
	connID := strconv.FormatUint(l.manager.connSeq.Add(1), 10)
	_ = conn.SetReadDeadline(time.Now().Add(l.manager.headTimeout))
	limiter := &boundedReader{r: conn, remaining: maxHeadBytes}
	br := bufio.NewReader(limiter)

	h, err := readHead(br)
	if err != nil {
		if he, ok := errors.AsType[*headError](err); ok {
			metrics.TunnelsTotal.WithLabelValues("tcp", l.authMode, "deny", "malformed").Inc()
			l.emitAudit(AuditRecord{
				Connection: connID,
				Transport:  "tcp",
				Decision:   "deny",
				Reason:     he.reason,
			})
			writeH1Deny(conn, l.manager.headTimeout, he.status, he.reason)
		}
		return
	}
	_ = conn.SetReadDeadline(time.Time{})
	limiter.remaining = -1

	if h.isDoH {
		l.serveDoH(conn, br, h, connID, start)
		return
	}

	transport := "tcp"
	if h.isUDP {
		transport = "udp"
	}
	target := net.JoinHostPort(h.host, h.port)

	if l.dialer == nil {
		metrics.TunnelsTotal.WithLabelValues(transport, l.authMode, "deny", "upstream_unavailable").Inc()
		l.emitAudit(AuditRecord{
			Connection: connID,
			Transport:  transport,
			Target:     target,
			Decision:   "deny",
			Reason:     "upstream-unconfigured",
		})
		writeH1Deny(conn, l.manager.headTimeout, http.StatusServiceUnavailable, "upstream-unconfigured")
		return
	}

	id, idGen, revokeCtx := l.snapshotIdentityAndContext()
	dialCtx, cancel := context.WithTimeout(revokeCtx, l.manager.dialTimeout)
	defer cancel()
	dialStart := time.Now()
	var up *upstreamTunnel
	if h.isUDP {
		up, err = l.dialer.dialUDP(dialCtx, h.host, h.port, id)
	} else {
		up, err = l.dialer.dialTCP(dialCtx, h.host, h.port, id)
	}
	metrics.TunnelDialDurationSeconds.WithLabelValues(l.dialer.negotiatedProtocol(h.isUDP), l.authMode).Observe(time.Since(dialStart).Seconds())

	if err != nil {
		if denied, ok := errors.AsType[*upstreamDeniedError](err); ok {
			clientStatus := denied.status
			if clientStatus < 400 || clientStatus > 599 {
				clientStatus = http.StatusBadGateway
			}
			metricReason := "upstream_denied"
			if denied.reason == "upstream-auth-failed" || clientStatus == http.StatusProxyAuthRequired {
				metricReason = "upstream_auth_failed"
			}
			metrics.TunnelsTotal.WithLabelValues(transport, l.authMode, "deny", metricReason).Inc()
			l.emitAudit(AuditRecord{
				Connection:     connID,
				Transport:      transport,
				Target:         target,
				Decision:       "deny",
				UpstreamStatus: denied.status,
				Reason:         denied.reason,
				DurationMS:     time.Since(start).Milliseconds(),
			})
			if denied.proxyStatus != "" {
				writeH1RawDeny(conn, l.manager.headTimeout, clientStatus, denied.proxyStatus)
			} else {
				writeH1Deny(conn, l.manager.headTimeout, clientStatus, denied.reason)
			}
			return
		}
		klog.ErrorS(err, "upstream tunnel dial failed",
			"podUID", l.podUID,
			"sandbox", id.Namespace+"/"+id.PodName,
			"target", target,
			"upstream", l.dialer.target.address,
			"authMode", l.authMode,
		)
		metrics.TunnelsTotal.WithLabelValues(transport, l.authMode, "error", "upstream_unavailable").Inc()
		l.emitAudit(AuditRecord{
			Connection: connID,
			Transport:  transport,
			Target:     target,
			Decision:   "error",
			Reason:     "upstream-connect-failed",
			DurationMS: time.Since(start).Milliseconds(),
		})
		writeH1Deny(conn, l.manager.headTimeout, http.StatusBadGateway, "upstream-connect-failed")
		return
	}
	defer up.close()
	if !l.setConnCloser(conn, idGen, up.close) {
		return
	}

	_ = conn.SetWriteDeadline(time.Now().Add(l.manager.headTimeout))
	switch {
	case h.isUDP:
		_, err = io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: connect-udp\r\nCapsule-Protocol: ?1\r\n\r\n")
	case h.isHTTPProxy:
		_, err = io.WriteString(up.w, h.originReqHead)
	default:
		_, err = io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
	}
	_ = conn.SetWriteDeadline(time.Time{})
	if err != nil {
		return
	}

	metrics.TunnelsTotal.WithLabelValues(transport, l.authMode, "allow", "allowed").Inc()
	outN, inN := relayStream(br, conn, up, l.idleTimeout, func() { _ = conn.Close() })
	l.emitAudit(AuditRecord{
		Connection:     connID,
		Transport:      transport,
		Target:         target,
		Decision:       "allow",
		UpstreamStatus: http.StatusOK,
		Reason:         "allowed",
		BytesOut:       outN,
		BytesIn:        inN,
		DurationMS:     time.Since(start).Milliseconds(),
	})
}

func (l *sandboxListener) serveDoH(conn net.Conn, br *bufio.Reader, h *requestHead, connID string, start time.Time) {
	if l.dnsMode != apis.DNSModeDoH {
		metrics.TunnelsTotal.WithLabelValues("dns", l.authMode, "deny", "doh_disabled").Inc()
		l.emitAudit(AuditRecord{
			Connection: connID,
			Transport:  "dns",
			Target:     dohPath,
			Decision:   "deny",
			Reason:     "doh-disabled",
		})
		writeH1Deny(conn, l.manager.headTimeout, http.StatusMethodNotAllowed, "doh-disabled")
		return
	}
	if l.dnsDialer == nil {
		metrics.TunnelsTotal.WithLabelValues("dns", l.dnsAuthMode, "deny", "upstream_unavailable").Inc()
		l.emitAudit(AuditRecord{
			Connection: connID,
			Transport:  "dns",
			Target:     dohPath,
			Decision:   "deny",
			Reason:     "upstream-unconfigured",
		})
		writeH1Deny(conn, l.manager.headTimeout, http.StatusServiceUnavailable, "upstream-unconfigured")
		return
	}

	_ = conn.SetReadDeadline(time.Now().Add(l.manager.headTimeout))
	query := make([]byte, h.contentLength)
	if _, err := io.ReadFull(br, query); err != nil {
		return
	}
	_ = conn.SetReadDeadline(time.Time{})

	id, _, revokeCtx := l.snapshotIdentityAndContext()
	dialCtx, cancel := context.WithTimeout(revokeCtx, l.manager.dialTimeout)
	defer cancel()

	dialStart := time.Now()
	reply, err := l.dnsDialer.doDoH(dialCtx, query, id)
	metrics.TunnelDialDurationSeconds.WithLabelValues(l.dnsDialer.negotiatedProtocol(false), l.dnsAuthMode).Observe(time.Since(dialStart).Seconds())
	if err != nil {
		if denied, ok := errors.AsType[*upstreamDeniedError](err); ok {
			clientStatus := denied.status
			if clientStatus < 400 || clientStatus > 599 {
				clientStatus = http.StatusBadGateway
			}
			metrics.TunnelsTotal.WithLabelValues("dns", l.dnsAuthMode, "deny", "upstream_denied").Inc()
			l.emitAudit(AuditRecord{
				Connection:     connID,
				Transport:      "dns",
				Target:         dohPath,
				Decision:       "deny",
				UpstreamStatus: denied.status,
				Reason:         denied.reason,
				DurationMS:     time.Since(start).Milliseconds(),
			})
			if denied.proxyStatus != "" {
				writeH1RawDeny(conn, l.manager.headTimeout, clientStatus, denied.proxyStatus)
			} else {
				writeH1Deny(conn, l.manager.headTimeout, clientStatus, denied.reason)
			}
			return
		}
		klog.ErrorS(err, "upstream DoH query failed",
			"podUID", l.podUID,
			"sandbox", id.Namespace+"/"+id.PodName,
			"upstream", l.dnsDialer.target.address,
			"authMode", l.dnsAuthMode,
		)
		metrics.TunnelsTotal.WithLabelValues("dns", l.dnsAuthMode, "error", "upstream_unavailable").Inc()
		l.emitAudit(AuditRecord{
			Connection: connID,
			Transport:  "dns",
			Target:     dohPath,
			Decision:   "error",
			Reason:     "upstream-connect-failed",
			DurationMS: time.Since(start).Milliseconds(),
		})
		writeH1Deny(conn, l.manager.headTimeout, http.StatusBadGateway, "upstream-connect-failed")
		return
	}

	_ = conn.SetWriteDeadline(time.Now().Add(l.manager.headTimeout))
	head := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", dohMediaType, len(reply))
	if _, err := io.WriteString(conn, head); err != nil {
		return
	}
	if _, err := conn.Write(reply); err != nil {
		return
	}
	metrics.TunnelsTotal.WithLabelValues("dns", l.dnsAuthMode, "allow", "allowed").Inc()
	l.emitAudit(AuditRecord{
		Connection:     connID,
		Transport:      "dns",
		Target:         dohPath,
		Decision:       "allow",
		UpstreamStatus: http.StatusOK,
		Reason:         "allowed",
		BytesOut:       int64(len(query)),
		BytesIn:        int64(len(reply)),
		DurationMS:     time.Since(start).Milliseconds(),
	})
}

func (l *sandboxListener) emitAudit(rec AuditRecord) {
	id := l.snapshotIdentity()
	rec.PodUID = string(l.podUID)
	rec.AuthMode = l.authMode
	if id.Namespace != "" && id.PodName != "" {
		rec.Sandbox = id.Namespace + "/" + id.PodName
	}
	l.manager.emitAudit(rec)
}
