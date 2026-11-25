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

// Package auth implements mandatory mTLS upstream authentication for dra-agents-net:
//   - MTLS (rotating PEM client certificate from a host or mounted directory)
//   - SPIFFE (Workload API X.509-SVID)
//   - PodCertificate (KEP-4317 kubelet-projected PKCS#8+chain credential bundle)
package auth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"

	"github.com/aojea/agents.net/kubernetes/pkg/apis"
	"github.com/aojea/agents.net/kubernetes/pkg/catrust"
)

const (
	// DefaultKubeletRootDir is the default host kubelet data directory.
	DefaultKubeletRootDir = "/var/lib/kubelet"

	// DefaultSPIFFEWorkloadSocket is the default SPIFFE Workload API UDS path.
	DefaultSPIFFEWorkloadSocket = "/run/spire/agent-sockets/spire-agent.sock"

	// Standardized agents.net attested workload identity headers (SPEC.md Part 1)
	// forwarded on mTLS upstream CONNECT and connect-udp requests.
	HeaderPrincipal  = "Agents-Net-Principal"
	HeaderGeneration = "Agents-Net-Generation"
	HeaderAttributes = "Agents-Net-Attributes"
)

// AuthMode metric label values (strictly bounded enum).
const (
	AuthModeUnix           = "unix"
	AuthModeMTLS           = "mtls"
	AuthModeSPIFFE         = "spiffe"
	AuthModePodCertificate = "pod_certificate"
)

// WorkloadIdentity holds the platform-attested Pod and node metadata asserted by
// kubelet, DRA, NRI, and the node-scoped Pod informer.
type WorkloadIdentity struct {
	Namespace      string
	PodName        string
	PodUID         types.UID
	SandboxID      string
	ServiceAccount string
	NodeName       string
	Custom         map[string]string
}

// AttestedHeaders formats the WorkloadIdentity into the portable SPEC.md Part 1
// Agents-Net-* headers (including an RFC 8941 dictionary in Agents-Net-Attributes).
func (id WorkloadIdentity) AttestedHeaders() http.Header {
	h := make(http.Header, 3)

	if principal := id.principal(); principal != "" && isSafeHeaderValue(principal) {
		h.Set(HeaderPrincipal, principal)
	}
	generation := id.SandboxID
	if generation == "" {
		generation = string(id.PodUID)
	}
	if generation != "" && isSafeHeaderValue(generation) {
		h.Set(HeaderGeneration, generation)
	}

	attrs := make(map[string]string, 5+len(id.Custom))
	for k, v := range id.Custom {
		if sfKey := sanitizeSFKey(k); sfKey != "" && isSafeHeaderValue(v) {
			attrs[sfKey] = v
		}
	}
	// Platform-attested Kubernetes fields always take precedence over custom keys.
	if id.Namespace != "" {
		attrs["ns"] = id.Namespace
	}
	if id.PodName != "" {
		attrs["pod"] = id.PodName
	}
	if id.PodUID != "" {
		attrs["pod_uid"] = string(id.PodUID)
	}
	if id.ServiceAccount != "" {
		attrs["sa"] = id.ServiceAccount
	}
	if id.NodeName != "" {
		attrs["node"] = id.NodeName
	}
	if dict := formatSFStringDict(attrs); dict != "" {
		h.Set(HeaderAttributes, dict)
	}
	return h
}

func (id WorkloadIdentity) principal() string {
	switch {
	case id.Namespace != "" && id.ServiceAccount != "" && id.PodName != "":
		return "k8s://" + id.Namespace + "/" + id.ServiceAccount + "/" + id.PodName
	case id.Namespace != "" && id.PodName != "":
		return "k8s://" + id.Namespace + "/" + id.PodName
	case id.PodUID != "":
		return "k8s://" + string(id.PodUID)
	default:
		return ""
	}
}

// formatSFStringDict encodes m as an RFC 8941 Structured Fields dictionary of
// quoted strings with deterministic key order.
func formatSFStringDict(m map[string]string) string {
	if len(m) == 0 {
		return ""
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)

	var b strings.Builder
	for _, k := range keys {
		v := m[k]
		if v == "" || !isSafeHeaderValue(v) {
			continue
		}
		if b.Len() > 0 {
			b.WriteString(", ")
		}
		b.WriteString(k)
		b.WriteString(`="`)
		for i := range len(v) {
			c := v[i]
			if c == '\\' || c == '"' {
				b.WriteByte('\\')
			}
			b.WriteByte(c)
		}
		b.WriteByte('"')
	}
	return b.String()
}

// sanitizeSFKey normalizes raw into a valid RFC 8941 key (lcalpha *(lcalpha / DIGIT / "_" / "-" / "." / "*")).
func sanitizeSFKey(raw string) string {
	var b strings.Builder
	b.Grow(len(raw))
	for i := range len(raw) {
		c := raw[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		ok := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.'
		if !ok {
			continue
		}
		if b.Len() == 0 && (c < 'a' || c > 'z') {
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

// isSafeHeaderValue reports whether v contains only RFC 9110 visible ASCII / SP bytes.
func isSafeHeaderValue(v string) bool {
	for i := range len(v) {
		c := v[i]
		if c < 0x20 || c >= 0x7f {
			return false
		}
	}
	return true
}

// ValidatePodUID checks that uid is a safe sandbox identifier ([A-Za-z0-9._-], 1..128 bytes).
func ValidatePodUID(uid types.UID) error {
	s := string(uid)
	if len(s) == 0 || len(s) > 128 || s == "." || s == ".." {
		return fmt.Errorf("invalid podUID %q", s)
	}
	for i := range len(s) {
		c := s[i]
		ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.'
		if !ok {
			return fmt.Errorf("invalid podUID %q: illegal character %q", s, c)
		}
	}
	return nil
}

func validateVolumeName(name string) error {
	if len(name) == 0 || len(name) > 63 {
		return fmt.Errorf("invalid volume name %q: length must be 1..63", name)
	}
	for i := range len(name) {
		c := name[i]
		ok := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'
		if !ok || ((i == 0 || i == len(name)-1) && c == '-') {
			return fmt.Errorf("invalid volume name %q: must be a DNS-1123 label", name)
		}
	}
	return nil
}

func safePodProjectedFilePath(kubeletRoot string, podUID types.UID, volumeName, defaultVol, fileName string) (string, error) {
	if err := ValidatePodUID(podUID); err != nil {
		return "", err
	}
	if volumeName == "" {
		volumeName = defaultVol
	}
	if err := validateVolumeName(volumeName); err != nil {
		return "", err
	}
	base := filepath.Clean(filepath.Join(kubeletRoot, "pods", string(podUID), "volumes", "kubernetes.io~projected"))
	full := filepath.Join(base, volumeName, fileName)
	rel, err := filepath.Rel(base, full)
	if err != nil || strings.HasPrefix(rel, "..") || filepath.IsAbs(rel) {
		return "", fmt.Errorf("projected path %q escapes pod volume root", full)
	}
	return full, nil
}

type fileStamp struct {
	mtime time.Time
	size  int64
	ino   uint64
}

func stampFromFileInfo(info os.FileInfo) fileStamp {
	st := fileStamp{mtime: info.ModTime(), size: info.Size()}
	if sys, ok := info.Sys().(*syscall.Stat_t); ok && sys != nil {
		st.ino = sys.Ino
	}
	return st
}

// ClientConfig holds resolved mTLS material for dialing a PEP.
type ClientConfig struct {
	// AuthMode is the bounded metric label identifying the active authentication mode.
	AuthMode string

	// TLSConfig is used to establish the mTLS transport connection to an https:// PEP.
	TLSConfig *tls.Config

	closeFn func() error
}

// Close releases any per-Pod resources held by the ClientConfig.
func (c *ClientConfig) Close() error {
	if c == nil || c.closeFn == nil {
		return nil
	}
	return c.closeFn()
}

// ResolverConfig configures the node-wide upstream authentication resolver.
type ResolverConfig struct {
	KubeletRootDir              string
	DefaultSPIFFEWorkloadSocket string
	KubeClient                  kubernetes.Interface
}

// Resolver produces live-rotating mTLS ClientConfigs for upstream PEP connections
// and caches shared node-level SPIFFE Workload API sources.
type Resolver struct {
	kubeletRootDir              string
	defaultSPIFFEWorkloadSocket string
	kubeClient                  kubernetes.Interface

	mu            sync.Mutex
	spiffeSources map[string]*workloadapi.X509Source
}

// NewResolver constructs a node-wide upstream auth Resolver.
func NewResolver(cfg ResolverConfig) *Resolver {
	kubeletRoot := cfg.KubeletRootDir
	if kubeletRoot == "" {
		kubeletRoot = DefaultKubeletRootDir
	}
	spiffeSock := cfg.DefaultSPIFFEWorkloadSocket
	if spiffeSock == "" {
		if env := os.Getenv("SPIFFE_ENDPOINT_SOCKET"); env != "" {
			spiffeSock = env
		} else {
			spiffeSock = DefaultSPIFFEWorkloadSocket
		}
	}
	return &Resolver{
		kubeletRootDir:              kubeletRoot,
		defaultSPIFFEWorkloadSocket: spiffeSock,
		kubeClient:                  cfg.KubeClient,
		spiffeSources:               make(map[string]*workloadapi.X509Source),
	}
}

// Close shuts down cached node-level SPIFFE Workload API sources.
func (r *Resolver) Close() error {
	r.mu.Lock()
	sources := r.spiffeSources
	r.spiffeSources = make(map[string]*workloadapi.X509Source)
	r.mu.Unlock()

	var errs []error
	for _, src := range sources {
		if err := src.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// ResolveRequest identifies the target Policy Enforcement Point (PEP), Pod namespace/UID,
// and optional kubelet projected volume name for PodCertificate auth.
type ResolveRequest struct {
	PolicyEnforcementPoint *apis.PolicyEnforcementPointConfig
	PodNamespace           string
	PodUID                 types.UID
	PodCertVolumeName      string
}

// Resolve builds the mandatory mTLS ClientConfig for req (or local Unix capability socket).
func (r *Resolver) Resolve(ctx context.Context, req ResolveRequest) (*ClientConfig, error) {
	if req.PolicyEnforcementPoint == nil || strings.TrimSpace(req.PolicyEnforcementPoint.URL) == "" {
		return nil, errors.New("policyEnforcementPoint url is required")
	}

	u, err := url.Parse(strings.TrimSpace(req.PolicyEnforcementPoint.URL))
	if err != nil {
		return nil, fmt.Errorf("parse policyEnforcementPoint url %q: %w", req.PolicyEnforcementPoint.URL, err)
	}
	switch u.Scheme {
	case "unix":
		if u.Path == "" && u.Opaque == "" {
			return nil, fmt.Errorf("unix policyEnforcementPoint url %q missing socket path", req.PolicyEnforcementPoint.URL)
		}
		if req.PolicyEnforcementPoint.Auth == nil {
			return &ClientConfig{AuthMode: AuthModeUnix}, nil
		}
	case "https":
		if u.Hostname() == "" {
			return nil, fmt.Errorf("https policyEnforcementPoint url %q missing host", req.PolicyEnforcementPoint.URL)
		}
		if req.PolicyEnforcementPoint.Auth == nil || req.PolicyEnforcementPoint.Auth.Type == "" {
			return nil, errors.New("mTLS auth (MTLS, SPIFFE, or PodCertificate) is required for https:// policyEnforcementPoint")
		}
	default:
		return nil, fmt.Errorf("unsupported policyEnforcementPoint url scheme %q (want https or unix; plaintext http is forbidden)", u.Scheme)
	}

	switch req.PolicyEnforcementPoint.Auth.Type {
	case apis.PEPAuthTypeMTLS:
		return r.resolveMTLS(ctx, req)
	case apis.PEPAuthTypeSPIFFE:
		return r.resolveSPIFFE(ctx, req)
	case apis.PEPAuthTypePodCertificate:
		return r.resolvePodCertificate(ctx, req)
	default:
		return nil, fmt.Errorf("unsupported PEP auth type %q", req.PolicyEnforcementPoint.Auth.Type)
	}
}

// buildServerTLSConfig constructs a tls.Config verifying the PEP server certificate
// against the configured CA bundle (or system roots) and optional SPIFFE ID constraints.
func (r *Resolver) buildServerTLSConfig(ctx context.Context, tlsSpec *apis.PEPTLS, namespace string) (*tls.Config, error) {
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	if tlsSpec == nil {
		return cfg, nil
	}
	cfg.ServerName = tlsSpec.ServerName

	if len(tlsSpec.CACertificateRefs) > 0 {
		pemBytes, err := catrust.LoadSourcesPEM(ctx, r.kubeClient, tlsSpec.CACertificateRefs, namespace)
		if err != nil {
			return nil, fmt.Errorf("load upstream TLS caCertificateRefs: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, errors.New("no valid CA certificates in upstream TLS caCertificateRefs")
		}
		cfg.RootCAs = pool
	}

	if tlsSpec.TrustDomain != "" || len(tlsSpec.AcceptedSPIFFEIDs) > 0 {
		allowedIDs, allowedDomain, err := parseSPIFFEConstraints(tlsSpec)
		if err != nil {
			return nil, err
		}
		// When verifying by SPIFFE URI SAN without DNS hostname match, perform chain
		// verification explicitly against RootCAs and validate the peer's SPIFFE ID.
		cfg.InsecureSkipVerify = true
		roots := cfg.RootCAs
		cfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			return verifySPIFFEPeerChain(rawCerts, roots, allowedDomain, allowedIDs)
		}
	}

	return cfg, nil
}

func parseSPIFFEConstraints(tlsSpec *apis.PEPTLS) ([]spiffeid.ID, spiffeid.TrustDomain, error) {
	var allowedDomain spiffeid.TrustDomain
	if tlsSpec.TrustDomain != "" {
		td, err := spiffeid.TrustDomainFromString(tlsSpec.TrustDomain)
		if err != nil {
			return nil, spiffeid.TrustDomain{}, fmt.Errorf("invalid trustDomain %q: %w", tlsSpec.TrustDomain, err)
		}
		allowedDomain = td
	}
	var allowedIDs []spiffeid.ID
	for _, raw := range tlsSpec.AcceptedSPIFFEIDs {
		id, err := spiffeid.FromString(raw)
		if err != nil {
			return nil, spiffeid.TrustDomain{}, fmt.Errorf("invalid accepted SPIFFE ID %q: %w", raw, err)
		}
		allowedIDs = append(allowedIDs, id)
	}
	return allowedIDs, allowedDomain, nil
}

func verifySPIFFEPeerChain(rawCerts [][]byte, roots *x509.CertPool, allowedDomain spiffeid.TrustDomain, allowedIDs []spiffeid.ID) error {
	if len(rawCerts) == 0 {
		return errors.New("upstream presented no certificates")
	}
	certs := make([]*x509.Certificate, 0, len(rawCerts))
	for _, raw := range rawCerts {
		c, err := x509.ParseCertificate(raw)
		if err != nil {
			return fmt.Errorf("parse upstream certificate: %w", err)
		}
		certs = append(certs, c)
	}
	intermediates := x509.NewCertPool()
	for _, c := range certs[1:] {
		intermediates.AddCert(c)
	}
	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if _, err := certs[0].Verify(opts); err != nil {
		return fmt.Errorf("verify upstream certificate chain: %w", err)
	}

	peerID, err := x509svid.IDFromCert(certs[0])
	if err != nil {
		return fmt.Errorf("extract upstream SPIFFE ID: %w", err)
	}
	if len(allowedIDs) > 0 {
		if !slices.Contains(allowedIDs, peerID) {
			return fmt.Errorf("upstream SPIFFE ID %q is not in acceptedSPIFFEIDs", peerID.String())
		}
	}
	if !allowedDomain.IsZero() && peerID.TrustDomain() != allowedDomain {
		return fmt.Errorf("upstream SPIFFE trust domain %q does not match %q", peerID.TrustDomain().Name(), allowedDomain.Name())
	}
	return nil
}
