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

// Package apis defines the Kubernetes DRA OpaqueDeviceConfiguration schema and
// constants for dra-agents-net (driver: dra.agents.net, apiVersion:
// dra.agents.net/v1alpha1, kind: DriverConfig).
package apis

import (
	"slices"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	// DriverName is the Kubernetes DRA driver name and NRI plugin name for dra-agents-net.
	DriverName = "dra.agents.net"

	// DefaultDeviceClassName is the default DRA DeviceClass referencing DriverName.
	DefaultDeviceClassName = DriverName

	// DriverConfigAPIVersion is the apiVersion stamped in dra-agents-net's
	// DeviceClass and ResourceClaim OpaqueDeviceConfiguration payload.
	DriverConfigAPIVersion = "dra.agents.net/v1alpha1"

	// DriverConfigKind is the kind stamped in dra-agents-net's
	// OpaqueDeviceConfiguration payload.
	DriverConfigKind = "DriverConfig"

	// DeviceStatusAPIVersion is the apiVersion stamped in ResourceClaim.status.devices[].data.
	DeviceStatusAPIVersion = DriverConfigAPIVersion

	// DeviceStatusKind is the kind stamped in ResourceClaim.status.devices[].data.
	DeviceStatusKind = "DeviceStatus"

	// IngressTunnelProtocolHTTPConnect identifies the node HTTP/1.1 CONNECT ingress bridge
	// protocol ("CONNECT <target>:<port> HTTP/1.1").
	IngressTunnelProtocolHTTPConnect = "http-connect"

	// PodClaimName is the default Pod.spec.resourceClaims[].name and ResourceClaim
	// device request name used with dra-agents-net.
	PodClaimName = "agents-net"

	// Tun2ConnectSidecarName is the native sidecar container name injected by workload
	// controllers when adapterMode is TunSidecar.
	Tun2ConnectSidecarName = "agents-net-tun2connect"

	// PodCertVolumeName is the projected volume name used for KEP-4317 PodCertificate
	// authentication.
	PodCertVolumeName = "agents-net-pod-cert"

	// PodCertBundleFile is the credential bundle filename written by kubelet inside
	// PodCertVolumeName.
	PodCertBundleFile = "credential-bundle.pem"

	// DefaultProxyPort is the default Pod loopback port (127.0.0.1:15001) bound via
	// socketat when adapterMode is ExplicitProxy.
	DefaultProxyPort int32 = 15001
)

// ConfinementMode defines how the backing Pod is isolated from direct network egress.
type ConfinementMode string

const (
	// ConfinementModePodNetworkIsolated places the Pod in a loopback-only network
	// namespace (KEP-6313) with no CNI attachment and no Pod IP.
	ConfinementModePodNetworkIsolated ConfinementMode = "PodNetworkIsolated"

	// ConfinementModeNetworkPolicyDenyAll isolates Pods on CNI clusters without KEP-6313.
	// With nicBlockMode=DropAll (default), dra-agents-net flushes non-loopback routes and
	// attaches tc clsact drop filters inside the Pod netns. With nicBlockMode=Disabled,
	// eth0 isolation and kubelet probes are deferred to CNI NetworkPolicy.
	ConfinementModeNetworkPolicyDenyAll ConfinementMode = "NetworkPolicyDenyAll"
)

// NICBlockMode controls whether dra-agents-net flushes non-loopback routes and attaches
// tc clsact drop filters inside the Pod network namespace under NetworkPolicyDenyAll.
// This setting is restricted to DeviceClass (FromClass).
type NICBlockMode string

const (
	// NICBlockModeDropAll (default) flushes non-loopback routes and attaches tc clsact
	// matchall DROP filters on ingress and egress of every non-loopback NIC inside the
	// Pod netns (excluding tuntap in HostTun and TunSidecar modes).
	NICBlockModeDropAll NICBlockMode = "DropAll"

	// NICBlockModeDisabled leaves eth0 routes and tc filters untouched so CNI NetworkPolicy
	// enforces isolation while preserving host-to-Pod kubelet probes and CNI flow logs.
	NICBlockModeDisabled NICBlockMode = "Disabled"
)

// AdapterMode defines how the Pod network namespace connects to the per-Pod
// agents.net egress channel managed by dra-agents-net.
type AdapterMode string

const (
	// AdapterModeHostTun (default) creates a persistent TUN device (tun0) inside the
	// Pod netns during NRI RunPodSandbox and terminates TCP, UDP, and VirtualDNS in
	// userspace on the host via tun2connect, requiring no sidecar container and no
	// Pod capabilities while capturing clients that ignore HTTP_PROXY transparently.
	AdapterModeHostTun AdapterMode = "HostTun"

	// AdapterModeTunSidecar injects one tun2connect native sidecar per Pod netns.
	AdapterModeTunSidecar AdapterMode = "TunSidecar"

	// AdapterModeExplicitProxy binds 127.0.0.1:<port> inside the Pod loopback netns
	// via socketat alongside egress.sock and injects proxy environment variables.
	AdapterModeExplicitProxy AdapterMode = "ExplicitProxy"
)

// DNSMode selects how HostTun resolves guest DNS queries.
type DNSMode string

const (
	// DNSModeSynthetic (default) answers queries locally with synthetic IPs
	// (198.18.0.0/15, 100::/64) and strips search/ndots from /etc/resolv.conf.
	DNSModeSynthetic DNSMode = "Synthetic"

	// DNSModeDoH forwards guest DNS queries via RFC 8484 DNS-over-HTTPS through
	// the unified Traffic PEP (or an optional separate DNS PEP), returning real
	// NXDOMAIN/REFUSED so resolv.conf search lists and retries work natively
	// while rewriting positive answers into synthetic IPs.
	DNSModeDoH DNSMode = "DoH"
)

// DNSConfig configures HostTun Virtual DNS resolution and resolv.conf search behavior.
// Restricted strictly to DeviceClass (FromClass).
type DNSConfig struct {
	Mode DNSMode `json:"mode,omitempty"`
	// EnforcementPoint optionally specifies a dedicated DNS PEP speaking RFC 8484
	// DoH (POST /dns-query). When omitted under DNSModeDoH, queries reuse the
	// Pod's primary PolicyEnforcementPoint over the same mTLS HTTP/2 session.
	EnforcementPoint *PolicyEnforcementPointConfig `json:"enforcementPoint,omitempty"`
	// ClusterDomain sets the Kubernetes cluster DNS suffix used in /etc/resolv.conf
	// search lists under DNSModeDoH (default: "cluster.local").
	ClusterDomain string `json:"clusterDomain,omitempty"`
	// PreserveSearchDomains controls whether /etc/resolv.conf includes Kubernetes
	// search domains and options ndots:5 under DNSModeDoH (default: true).
	PreserveSearchDomains *bool `json:"preserveSearchDomains,omitempty"`
}

// DeepCopy returns a deep copy of d.
func (d *DNSConfig) DeepCopy() *DNSConfig {
	if d == nil {
		return nil
	}
	out := *d
	out.EnforcementPoint = d.EnforcementPoint.DeepCopy()
	if d.PreserveSearchDomains != nil {
		v := *d.PreserveSearchDomains
		out.PreserveSearchDomains = &v
	}
	return &out
}

// PEPAuthType selects the mandatory mTLS authentication mechanism to the PEP.
type PEPAuthType string

const (
	PEPAuthTypeMTLS           PEPAuthType = "MTLS"
	PEPAuthTypeSPIFFE         PEPAuthType = "SPIFFE"
	PEPAuthTypePodCertificate PEPAuthType = "PodCertificate"
)

// CATrustMode controls how declarative Pod CA certificates are exposed to containers.
type CATrustMode string

const (
	CATrustModeNone      CATrustMode = "None"
	CATrustModeMountOnly CATrustMode = "MountOnly"
	CATrustModeInjectEnv CATrustMode = "InjectEnv"
)

// CABundleMode controls whether custom CA certificates append to or replace system roots.
type CABundleMode string

const (
	CABundleModeAppendSystemRoots CABundleMode = "AppendSystemRoots"
	CABundleModeReplace           CABundleMode = "Replace"
)

// CASourceType selects the Kubernetes or host source of a PEM CA certificate bundle.
type CASourceType string

const (
	CASourceTypeConfigMap          CASourceType = "ConfigMap"
	CASourceTypeClusterTrustBundle CASourceType = "ClusterTrustBundle"
	CASourceTypeHostPath           CASourceType = "HostPath"
)

// IngressProtocol defines the transport protocol for an explicit ingress port.
type IngressProtocol string

const (
	IngressProtocolTCP IngressProtocol = "TCP"
)

// ConfigMapKeyRef selects a key inside a ConfigMap in the Pod namespace.
type ConfigMapKeyRef struct {
	Name string `json:"name"`
	Key  string `json:"key,omitempty"`
}

// ClusterTrustBundleRef selects Kubernetes ClusterTrustBundle objects by exact name
// or by signerName and optional labelSelector.
type ClusterTrustBundleRef struct {
	Name          string                `json:"name,omitempty"`
	SignerName    string                `json:"signerName,omitempty"`
	LabelSelector *metav1.LabelSelector `json:"labelSelector,omitempty"`
}

// CASource defines one PEM CA certificate bundle source.
type CASource struct {
	Type               CASourceType           `json:"type"`
	ConfigMapRef       *ConfigMapKeyRef       `json:"configMapRef,omitempty"`
	ClusterTrustBundle *ClusterTrustBundleRef `json:"clusterTrustBundle,omitempty"`
	HostPath           string                 `json:"hostPath,omitempty"`
}

// DeepCopy returns a deep copy of s.
func (s *CASource) DeepCopy() *CASource {
	if s == nil {
		return nil
	}
	out := *s
	if s.ConfigMapRef != nil {
		cm := *s.ConfigMapRef
		out.ConfigMapRef = &cm
	}
	if s.ClusterTrustBundle != nil {
		ctb := *s.ClusterTrustBundle
		if s.ClusterTrustBundle.LabelSelector != nil {
			ctb.LabelSelector = s.ClusterTrustBundle.LabelSelector.DeepCopy()
		}
		out.ClusterTrustBundle = &ctb
	}
	return &out
}

// CATrustConfig defines declarative Pod CA certificate bundles.
type CATrustConfig struct {
	Mode       CATrustMode  `json:"mode,omitempty"`
	BundleMode CABundleMode `json:"bundleMode,omitempty"`
	Sources    []CASource   `json:"sources,omitempty"`
}

// DeepCopy returns a deep copy of c.
func (c *CATrustConfig) DeepCopy() *CATrustConfig {
	if c == nil {
		return nil
	}
	out := *c
	if len(c.Sources) > 0 {
		out.Sources = make([]CASource, len(c.Sources))
		for i := range c.Sources {
			out.Sources[i] = *c.Sources[i].DeepCopy()
		}
	}
	return &out
}

// ExplicitProxyConfig configures the Pod loopback HTTP proxy listener in ExplicitProxy mode.
type ExplicitProxyConfig struct {
	Port    *int32   `json:"port,omitempty"`
	NoProxy []string `json:"noProxy,omitempty"`
}

// DeepCopy returns a deep copy of p.
func (p *ExplicitProxyConfig) DeepCopy() *ExplicitProxyConfig {
	if p == nil {
		return nil
	}
	out := *p
	if p.Port != nil {
		v := *p.Port
		out.Port = &v
	}
	if len(p.NoProxy) > 0 {
		out.NoProxy = slices.Clone(p.NoProxy)
	}
	return &out
}

// IngressPort declares one allowed container TCP port or inclusive port range
// (when EndPort is set) exposed through the host ingress bridge.
type IngressPort struct {
	Port     int32           `json:"port"`
	EndPort  int32           `json:"endPort,omitempty"`
	Protocol IngressProtocol `json:"protocol,omitempty"`
}

// Contains reports whether port and proto fall within p. An empty protocol on
// either side defaults to TCP; EndPort == 0 matches only p.Port.
func (p IngressPort) Contains(port int32, proto IngressProtocol) bool {
	pProto := p.Protocol
	if pProto == "" {
		pProto = IngressProtocolTCP
	}
	if proto == "" {
		proto = IngressProtocolTCP
	}
	if pProto != proto {
		return false
	}
	end := p.EndPort
	if end == 0 {
		end = p.Port
	}
	return port >= p.Port && port <= end
}

// FormatProxyStatus builds an RFC 9209 Proxy-Status field value using the
// standardized agents.net structure ("<member>; error=<type>; reason=<token>").
func FormatProxyStatus(member string, status int, reason string) string {
	cleanMember := sanitizeProxyStatusToken(member)
	if cleanMember == "" {
		cleanMember = "dra-agents-net"
	}
	cleanReason := sanitizeProxyStatusToken(reason)
	if cleanReason == "" {
		cleanReason = "error"
	}
	return cleanMember + "; error=" + proxyErrorType(status, cleanReason) + "; reason=" + cleanReason
}

func proxyErrorType(status int, reason string) string {
	switch reason {
	case "port-not-permitted", "ingress-port-denied", "not-on-allowlist",
		"port-not-allowed", "transport-not-allowed", "udp-disabled",
		"identity-unknown", "listener-revoked", "upstream-denied":
		return "http_request_denied"
	case "unknown-sandbox", "sandbox-revoked":
		return "destination_not_found"
	case "busy", "max-connections-exceeded":
		return "connection_limit_reached"
	case "upstream-unconfigured", "policy-unavailable":
		return "proxy_configuration_error"
	case "unsupported-version", "unsupported-http-version":
		return "http_protocol_error"
	case "ingress-dial-failed", "upstream-connect-failed", "sandbox-not-ready", "dial-failed", "upstream-auth-failed", "bridge-tls-required":
		return "destination_unavailable"
	}
	switch status {
	case 403, 407:
		return "http_request_denied"
	case 404:
		return "destination_not_found"
	case 502, 503, 504:
		return "destination_unavailable"
	case 505:
		return "http_protocol_error"
	default:
		return "http_request_error"
	}
}

func sanitizeProxyStatusToken(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := range len(s) {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' {
			b.WriteByte(c)
		}
	}
	return b.String()
}

// DeviceStatus is the structured DRA status payload published by dra-agents-net in
// ResourceClaim.status.devices[].data once a Pod's sandbox is prepared and running.
type DeviceStatus struct {
	APIVersion string         `json:"apiVersion"`
	Kind       string         `json:"kind"`
	NodeName   string         `json:"nodeName"`
	PodUID     string         `json:"podUID"`
	SandboxID  string         `json:"sandboxID,omitempty"`
	Ingress    *IngressStatus `json:"ingress,omitempty"`
}

// IngressStatus advertises how an authorized cluster ingress gateway or router
// reaches a Pod's pinned loopback ports via the node mTLS HTTP CONNECT ingress bridge.
type IngressStatus struct {
	// Endpoint is the routable host:port of the node ingress bridge (for example "10.0.0.5:15080").
	Endpoint string `json:"endpoint"`
	// Protocol identifies the bridge tunnel protocol ("http-connect").
	Protocol string `json:"protocol"`
	// Target is the CONNECT authority host (Pod UID), used in "CONNECT <target>:<port> HTTP/1.1".
	Target string `json:"target"`
	// TLS reports whether Endpoint requires mTLS.
	TLS bool `json:"tls"`
	// ServerName is the optional TLS server name expected by Endpoint.
	ServerName string `json:"serverName,omitempty"`
	// Ports lists the controller-authorized loopback ports exposed by this Pod.
	Ports []IngressPort `json:"ports"`
}

// PEPTLS configures server TLS verification for the Policy Enforcement Point (PEP).
type PEPTLS struct {
	ServerName        string     `json:"serverName,omitempty"`
	CACertificateRefs []CASource `json:"caCertificateRefs,omitempty"`
	TrustDomain       string     `json:"trustDomain,omitempty"`
	AcceptedSPIFFEIDs []string   `json:"acceptedSPIFFEIDs,omitempty"`
}

// DeepCopy returns a deep copy of t.
func (t *PEPTLS) DeepCopy() *PEPTLS {
	if t == nil {
		return nil
	}
	out := *t
	if len(t.CACertificateRefs) > 0 {
		out.CACertificateRefs = make([]CASource, len(t.CACertificateRefs))
		for i := range t.CACertificateRefs {
			out.CACertificateRefs[i] = *t.CACertificateRefs[i].DeepCopy()
		}
	}
	if len(t.AcceptedSPIFFEIDs) > 0 {
		out.AcceptedSPIFFEIDs = slices.Clone(t.AcceptedSPIFFEIDs)
	}
	return &out
}

// MTLSAuth configures rotating client mTLS credentials from a host or mounted directory
// containing tls.crt and tls.key.
type MTLSAuth struct {
	CertDir string `json:"certDir"`
}

// SPIFFEAuth configures SPIFFE Workload API X.509-SVID mTLS authentication.
type SPIFFEAuth struct {
	WorkloadSocketPath string `json:"workloadSocketPath,omitempty"`
}

// PodCertificateAuth configures KEP-4317 kubelet-projected PodCertificate mTLS authentication.
type PodCertificateAuth struct {
	SignerName string `json:"signerName"`
}

// PEPAuth is a discriminated union selecting mandatory mTLS client authentication to the PEP.
type PEPAuth struct {
	Type           PEPAuthType         `json:"type"`
	MTLS           *MTLSAuth           `json:"mtls,omitempty"`
	SPIFFE         *SPIFFEAuth         `json:"spiffe,omitempty"`
	PodCertificate *PodCertificateAuth `json:"podCertificate,omitempty"`
}

// DeepCopy returns a deep copy of a.
func (a *PEPAuth) DeepCopy() *PEPAuth {
	if a == nil {
		return nil
	}
	out := *a
	if a.MTLS != nil {
		m := *a.MTLS
		out.MTLS = &m
	}
	if a.SPIFFE != nil {
		s := *a.SPIFFE
		out.SPIFFE = &s
	}
	if a.PodCertificate != nil {
		pc := *a.PodCertificate
		out.PodCertificate = &pc
	}
	return &out
}

// PolicyEnforcementPointConfig defines the Policy Enforcement Point (PEP) endpoint.
type PolicyEnforcementPointConfig struct {
	URL  string   `json:"url"`
	TLS  *PEPTLS  `json:"tls,omitempty"`
	Auth *PEPAuth `json:"auth,omitempty"`
}

// DeepCopy returns a deep copy of p.
func (p *PolicyEnforcementPointConfig) DeepCopy() *PolicyEnforcementPointConfig {
	if p == nil {
		return nil
	}
	out := *p
	out.TLS = p.TLS.DeepCopy()
	out.Auth = p.Auth.DeepCopy()
	return &out
}
