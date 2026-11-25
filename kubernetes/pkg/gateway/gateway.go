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

// Package gateway implements a stateless Kubernetes ingress gateway for
// dra.agents.net. It watches resource.k8s.io/v1 ResourceClaims, extracts the
// structured dra.agents.net/v1alpha1 DeviceStatus.Ingress endpoint published in
// ResourceClaim.status.devices[].data, and reverse-proxies inbound HTTP traffic
// over HTTP/1.1 CONNECT tunnels to the target node's dra-agents-net ingress
// bridge without relying on Pod IPs.
package gateway

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	resourceapi "k8s.io/api/resource/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/aojea/agents.net/kubernetes/pkg/apis"
)

const (
	// HeaderNamespace selects the target Pod namespace for header-routed requests.
	HeaderNamespace = "X-Agents-Net-Namespace"
	// HeaderPod selects the target Pod name for header-routed requests.
	HeaderPod = "X-Agents-Net-Pod"
	// HeaderPodUID selects the target Pod UID directly for header-routed requests.
	HeaderPodUID = "X-Agents-Net-Pod-Uid"
	// HeaderPort selects an explicit pinned port (defaults to the first pinned port).
	HeaderPort = "X-Agents-Net-Port"

	defaultDialTimeout  = 10 * time.Second
	maxConnectHeadSize  = 16 * 1024
	maxInterimResponses = 8
)

// RouteEntry holds the live ingress routing target discovered from one ResourceClaim.
type RouteEntry struct {
	ClaimKey     string
	PodNamespace string
	PodName      string
	PodUID       string
	SandboxID    string
	NodeName     string
	Ingress      apis.IngressStatus
}

// Registry maintains a thread-safe index of live Pod ingress endpoints discovered
// from ResourceClaim.status.devices[].data.
type Registry struct {
	driverName string

	mu       sync.RWMutex
	byClaim  map[string]RouteEntry
	byPod    map[string]RouteEntry
	byPodUID map[string]RouteEntry
}

// NewRegistry creates an empty Registry filtering ResourceClaim device status entries
// by driverName (defaults to apis.DriverName).
func NewRegistry(driverName string) *Registry {
	if driverName == "" {
		driverName = apis.DriverName
	}
	return &Registry{
		driverName: driverName,
		byClaim:    make(map[string]RouteEntry),
		byPod:      make(map[string]RouteEntry),
		byPodUID:   make(map[string]RouteEntry),
	}
}

// SyncClaim indexes or removes the ingress endpoint advertised by claim.
// Claims that are not Ready, have no Pod reservation, or advertise no IngressStatus
// are evicted immediately so revoked sandboxes stop receiving traffic.
func (r *Registry) SyncClaim(claim *resourceapi.ResourceClaim) {
	if claim == nil {
		return
	}
	claimKey := claim.Namespace + "/" + claim.Name
	entry, ok := r.extractRoute(claim, claimKey)

	r.mu.Lock()
	defer r.mu.Unlock()
	r.deleteLocked(claimKey)
	if !ok {
		return
	}
	r.byClaim[claimKey] = entry
	if entry.PodNamespace != "" && entry.PodName != "" {
		r.byPod[podKey(entry.PodNamespace, entry.PodName)] = entry
	}
	if entry.PodUID != "" {
		r.byPodUID[entry.PodUID] = entry
	}
}

// DeleteClaim removes any route previously discovered from namespace/name.
func (r *Registry) DeleteClaim(namespace, name string) {
	claimKey := namespace + "/" + name
	r.mu.Lock()
	defer r.mu.Unlock()
	r.deleteLocked(claimKey)
}

func (r *Registry) deleteLocked(claimKey string) {
	prev, ok := r.byClaim[claimKey]
	if !ok {
		return
	}
	delete(r.byClaim, claimKey)
	pk := podKey(prev.PodNamespace, prev.PodName)
	if cur, exists := r.byPod[pk]; exists && cur.ClaimKey == claimKey {
		delete(r.byPod, pk)
	}
	if cur, exists := r.byPodUID[prev.PodUID]; exists && cur.ClaimKey == claimKey {
		delete(r.byPodUID, prev.PodUID)
	}
}

// LookupByPod returns the live ingress route for namespace/podName.
func (r *Registry) LookupByPod(namespace, podName string) (RouteEntry, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	e, ok := r.byPod[podKey(namespace, podName)]
	return e, ok
}

// LookupByUID returns the live ingress route for podUID.
func (r *Registry) LookupByUID(podUID string) (RouteEntry, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	e, ok := r.byPodUID[podUID]
	return e, ok
}

func (r *Registry) extractRoute(claim *resourceapi.ResourceClaim, claimKey string) (RouteEntry, bool) {
	if len(claim.Status.ReservedFor) != 1 {
		return RouteEntry{}, false
	}
	ref := claim.Status.ReservedFor[0]
	if ref.APIGroup != "" || ref.Resource != "pods" || ref.Name == "" || ref.UID == "" {
		return RouteEntry{}, false
	}

	for i := range claim.Status.Devices {
		dev := &claim.Status.Devices[i]
		if dev.Driver != r.driverName || dev.Data == nil || len(dev.Data.Raw) == 0 {
			continue
		}
		if !isDeviceReady(dev.Conditions) {
			return RouteEntry{}, false
		}
		var status apis.DeviceStatus
		if err := json.Unmarshal(dev.Data.Raw, &status); err != nil {
			continue
		}
		if status.APIVersion != apis.DeviceStatusAPIVersion || status.Kind != apis.DeviceStatusKind {
			continue
		}
		if status.PodUID != "" && status.PodUID != string(ref.UID) {
			return RouteEntry{}, false
		}
		if status.Ingress == nil || status.Ingress.Endpoint == "" || status.Ingress.Target == "" || len(status.Ingress.Ports) == 0 {
			return RouteEntry{}, false
		}
		if status.Ingress.Protocol != apis.IngressTunnelProtocolHTTPConnect {
			return RouteEntry{}, false
		}
		return RouteEntry{
			ClaimKey:     claimKey,
			PodNamespace: claim.Namespace,
			PodName:      ref.Name,
			PodUID:       string(ref.UID),
			SandboxID:    status.SandboxID,
			NodeName:     status.NodeName,
			Ingress:      *status.Ingress,
		}, true
	}
	return RouteEntry{}, false
}

func isDeviceReady(conds []metav1.Condition) bool {
	for _, c := range conds {
		if c.Type == "Ready" {
			return c.Status == metav1.ConditionTrue
		}
	}
	return false
}

func podKey(ns, name string) string {
	return ns + "/" + name
}

// AuditRecord captures one ingress delivery decision per spec/draft/ingress.md §2.
type AuditRecord struct {
	Timestamp string `json:"ts"`
	Direction string `json:"direction"`
	Namespace string `json:"namespace,omitempty"`
	Pod       string `json:"pod,omitempty"`
	PodUID    string `json:"pod_uid,omitempty"`
	SandboxID string `json:"sandbox_id,omitempty"`
	Endpoint  string `json:"endpoint,omitempty"`
	Port      int32  `json:"port,omitempty"`
	Method    string `json:"method"`
	Path      string `json:"path"`
	Status    int    `json:"status"`
	Reason    string `json:"reason,omitempty"`
}

// Config configures an agents.net ingress gateway Handler.
type Config struct {
	Registry    *Registry
	TLSConfig   *tls.Config
	DialTimeout time.Duration
	AuditWriter io.Writer
}

// Handler routes external HTTP requests to isolated Pods discovered through Registry.
type Handler struct {
	registry    *Registry
	tlsConfig   *tls.Config
	dialTimeout time.Duration

	auditMu  sync.Mutex
	auditOut io.Writer
}

// NewHandler constructs an HTTP Handler backed by cfg.Registry.
func NewHandler(cfg Config) (*Handler, error) {
	if cfg.Registry == nil {
		return nil, errors.New("registry is required")
	}
	dialTimeout := cfg.DialTimeout
	if dialTimeout <= 0 {
		dialTimeout = defaultDialTimeout
	}
	auditOut := cfg.AuditWriter
	if auditOut == nil {
		auditOut = os.Stdout
	}
	return &Handler{
		registry:    cfg.Registry,
		tlsConfig:   cfg.TLSConfig,
		dialTimeout: dialTimeout,
		auditOut:    auditOut,
	}, nil
}

// ServeHTTP handles /healthz and routes sandbox ingress requests via path
// (/agents/<namespace>/<pod>[:<port>]/<path>) or X-Agents-Net-* headers.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/healthz" {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok\n")
		return
	}

	target, forwardPath, err := resolveRequestTarget(r)
	if err != nil {
		h.writeError(w, r, RouteEntry{}, 0, http.StatusBadRequest, "invalid-target", err.Error())
		return
	}

	var (
		entry RouteEntry
		found bool
	)
	if target.podUID != "" {
		entry, found = h.registry.LookupByUID(target.podUID)
	} else {
		entry, found = h.registry.LookupByPod(target.namespace, target.podName)
	}
	if !found {
		h.writeError(w, r, RouteEntry{PodNamespace: target.namespace, PodName: target.podName, PodUID: target.podUID}, target.port, http.StatusNotFound, "unknown-sandbox", "no active agents.net ingress route for target pod")
		return
	}

	port := target.port
	if port == 0 {
		port = entry.Ingress.Ports[0].Port
	}
	if !isPortPinned(entry.Ingress.Ports, port) {
		h.writeError(w, r, entry, port, http.StatusForbidden, "port-not-permitted", fmt.Sprintf("port %d is not in ingressPorts allowlist", port))
		return
	}

	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return h.dialConnectBridge(ctx, entry.Ingress, port)
		},
		DisableKeepAlives:     true,
		ResponseHeaderTimeout: 30 * time.Second,
	}
	defer tr.CloseIdleConnections()

	var bridgeErr error
	proxy := &httputil.ReverseProxy{
		Transport: tr,
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(&url.URL{
				Scheme: "http",
				Host:   fmt.Sprintf("127.0.0.1:%d", port),
			})
			pr.Out.URL.Path = forwardPath
			pr.Out.URL.RawPath = ""
			pr.Out.Host = fmt.Sprintf("127.0.0.1:%d", port)
			pr.Out.Header.Del(HeaderNamespace)
			pr.Out.Header.Del(HeaderPod)
			pr.Out.Header.Del(HeaderPodUID)
			pr.Out.Header.Del(HeaderPort)
		},
		ErrorHandler: func(rw http.ResponseWriter, _ *http.Request, err error) {
			bridgeErr = err
			var be *bridgeDeniedError
			if errors.As(err, &be) {
				if be.proxyStatus != "" {
					rw.Header().Set("Proxy-Status", be.proxyStatus)
				} else {
					rw.Header().Set("Proxy-Status", apis.FormatProxyStatus("agents-net-gateway", be.status, "bridge-denied"))
				}
				http.Error(rw, be.Error(), be.status)
				return
			}
			rw.Header().Set("Proxy-Status", apis.FormatProxyStatus("agents-net-gateway", http.StatusBadGateway, "ingress-dial-failed"))
			http.Error(rw, "agents.net ingress bridge error", http.StatusBadGateway)
		},
	}

	rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	proxy.ServeHTTP(rec, r)

	reason := "delivered"
	if bridgeErr != nil {
		reason = bridgeErr.Error()
	}
	h.audit(AuditRecord{
		Direction: "ingress",
		Namespace: entry.PodNamespace,
		Pod:       entry.PodName,
		PodUID:    entry.PodUID,
		SandboxID: entry.SandboxID,
		Endpoint:  entry.Ingress.Endpoint,
		Port:      port,
		Method:    r.Method,
		Path:      forwardPath,
		Status:    rec.status,
		Reason:    reason,
	})
}

type requestTarget struct {
	namespace string
	podName   string
	podUID    string
	port      int32
}

// resolveRequestTarget parses either:
//   - /agents/<namespace>/<pod>[:<port>][/<rest>]
//   - X-Agents-Net-Pod (+ optional X-Agents-Net-Namespace, X-Agents-Net-Port)
//   - X-Agents-Net-Pod-Uid (+ optional X-Agents-Net-Port)
func resolveRequestTarget(r *http.Request) (requestTarget, string, error) {
	if rest, ok := strings.CutPrefix(r.URL.Path, "/agents/"); ok {
		parts := strings.SplitN(rest, "/", 3)
		if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
			return requestTarget{}, "", errors.New("path must be /agents/<namespace>/<pod>[:<port>]/<path>")
		}
		ns := parts[0]
		podSpec := parts[1]
		forwardPath := "/"
		if len(parts) == 3 && parts[2] != "" {
			forwardPath = "/" + parts[2]
		}
		podName := podSpec
		var port int32
		if name, portStr, hasPort := strings.Cut(podSpec, ":"); hasPort {
			p, err := parsePort(portStr)
			if err != nil {
				return requestTarget{}, "", err
			}
			podName = name
			port = p
		}
		if podName == "" {
			return requestTarget{}, "", errors.New("pod name is required")
		}
		return requestTarget{namespace: ns, podName: podName, port: port}, forwardPath, nil
	}

	podUID := strings.TrimSpace(r.Header.Get(HeaderPodUID))
	podName := strings.TrimSpace(r.Header.Get(HeaderPod))
	if podUID == "" && podName == "" {
		return requestTarget{}, "", errors.New("specify /agents/<namespace>/<pod>/... or X-Agents-Net-Pod / X-Agents-Net-Pod-Uid header")
	}
	ns := strings.TrimSpace(r.Header.Get(HeaderNamespace))
	if ns == "" {
		ns = "default"
	}
	var port int32
	if rawPort := strings.TrimSpace(r.Header.Get(HeaderPort)); rawPort != "" {
		p, err := parsePort(rawPort)
		if err != nil {
			return requestTarget{}, "", err
		}
		port = p
	}
	forwardPath := r.URL.Path
	if forwardPath == "" {
		forwardPath = "/"
	}
	return requestTarget{namespace: ns, podName: podName, podUID: podUID, port: port}, forwardPath, nil
}

func parsePort(raw string) (int32, error) {
	v, err := strconv.Atoi(raw)
	if err != nil || v < 1 || v > 65535 {
		return 0, fmt.Errorf("invalid port %q", raw)
	}
	return int32(v), nil
}

func isPortPinned(ports []apis.IngressPort, port int32) bool {
	for _, p := range ports {
		if p.Contains(port, apis.IngressProtocolTCP) {
			return true
		}
	}
	return false
}

type bridgeDeniedError struct {
	status      int
	proxyStatus string
	reason      string
}

func (e *bridgeDeniedError) Error() string {
	return fmt.Sprintf("ingress bridge rejected CONNECT (%d): %s", e.status, e.reason)
}

func (h *Handler) dialConnectBridge(ctx context.Context, ing apis.IngressStatus, port int32) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: h.dialTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", ing.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("dial ingress bridge %s: %w", ing.Endpoint, err)
	}

	if ing.TLS {
		var tlsCfg *tls.Config
		if h.tlsConfig != nil {
			tlsCfg = h.tlsConfig.Clone()
		} else {
			tlsCfg = &tls.Config{MinVersion: tls.VersionTLS12}
		}
		if ing.ServerName != "" {
			tlsCfg.ServerName = ing.ServerName
		} else if tlsCfg.ServerName == "" {
			if host, _, err := net.SplitHostPort(ing.Endpoint); err == nil {
				tlsCfg.ServerName = host
			}
		}
		tlsConn := tls.Client(conn, tlsCfg)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("TLS handshake to ingress bridge %s: %w", ing.Endpoint, err)
		}
		conn = tlsConn
	}

	authority := net.JoinHostPort(ing.Target, strconv.FormatInt(int64(port), 10))
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(h.dialTimeout))
	}

	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", authority, authority)
	if _, err := io.WriteString(conn, req); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("write CONNECT to ingress bridge: %w", err)
	}

	br := bufio.NewReader(io.LimitReader(conn, maxConnectHeadSize))
	resp, err := readFinalResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("read CONNECT response from ingress bridge: %w", err)
	}
	_ = conn.SetDeadline(time.Time{})

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		ps := resp.Header.Get("Proxy-Status")
		_ = conn.Close()
		return nil, &bridgeDeniedError{
			status:      resp.StatusCode,
			proxyStatus: ps,
			reason:      resp.Status,
		}
	}

	// Preserve any trailing bytes already buffered by bufio.Reader before reading directly from conn.
	if br.Buffered() > 0 {
		buf, err := br.Peek(br.Buffered())
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
		pre := append([]byte(nil), buf...)
		return &bufferedConn{Conn: conn, pre: pre}, nil
	}
	return conn, nil
}

type bufferedConn struct {
	net.Conn
	pre []byte
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	if len(c.pre) > 0 {
		n := copy(p, c.pre)
		c.pre = c.pre[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func readFinalResponse(br *bufio.Reader, req *http.Request) (*http.Response, error) {
	for interim := range maxInterimResponses + 1 {
		resp, err := http.ReadResponse(br, req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode < 100 || resp.StatusCode >= 200 {
			return resp, nil
		}
		if interim == maxInterimResponses {
			return nil, fmt.Errorf("ingress bridge sent more than %d interim responses", maxInterimResponses)
		}
	}
	return nil, errors.New("unexpected interim response loop termination")
}

func (h *Handler) writeError(w http.ResponseWriter, r *http.Request, entry RouteEntry, port int32, status int, reason, msg string) {
	w.Header().Set("Proxy-Status", apis.FormatProxyStatus("agents-net-gateway", status, reason))
	http.Error(w, msg, status)
	h.audit(AuditRecord{
		Direction: "ingress",
		Namespace: entry.PodNamespace,
		Pod:       entry.PodName,
		PodUID:    entry.PodUID,
		SandboxID: entry.SandboxID,
		Endpoint:  entry.Ingress.Endpoint,
		Port:      port,
		Method:    r.Method,
		Path:      r.URL.Path,
		Status:    status,
		Reason:    reason,
	})
}

func (h *Handler) audit(rec AuditRecord) {
	rec.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	line, err := json.Marshal(rec)
	if err != nil {
		return
	}
	h.auditMu.Lock()
	defer h.auditMu.Unlock()
	_, _ = h.auditOut.Write(append(line, '\n'))
}
