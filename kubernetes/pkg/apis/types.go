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

// Package apis defines the internal Kubernetes DRA OpaqueDeviceConfiguration
// wire schema and constants for the dra-agents-net Kubernetes Network Driver
// (driver: dra.agents.net, apiVersion: dra.agents.net/v1alpha1, kind: DriverConfig).
//
// Any Kubernetes workload (raw Pods, Deployments, StatefulSets, or sandbox
// controllers such as agent-sandbox) attaches agents.net traffic plumbing via
// standard Kubernetes DeviceClass, ResourceClaimTemplate, and ResourceClaim objects.
package apis

import (
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
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
	// authentication when isolated on the tun2connect native sidecar.
	PodCertVolumeName = "agents-net-pod-cert"

	// PodCertBundleFile is the credential bundle filename written by kubelet inside
	// PodCertVolumeName.
	PodCertBundleFile = "credential-bundle.pem"

	// SATokenVolumeName is the projected volume name used for Pod-mode
	// ServiceAccountToken authentication when isolated on the tun2connect sidecar.
	SATokenVolumeName = "agents-net-sa-token"

	// SATokenFile is the token filename written by kubelet inside SATokenVolumeName.
	SATokenFile = "token"

	// DefaultProxyPort is the default Pod loopback port (127.0.0.1:15001) bound via
	// socketat when adapterMode is ExplicitProxy.
	DefaultProxyPort int32 = 15001

	// ClaimUIDLabel is the optional Pod label key carrying the owning claim UID
	// (set by workload controllers such as agent-sandbox SandboxClaim adoption).
	ClaimUIDLabel = "agents.x-k8s.io/claim-uid"

	// ClaimNameAnnotation is the optional Pod annotation key carrying the owning claim name
	// (set by workload controllers such as agent-sandbox SandboxClaim adoption).
	ClaimNameAnnotation = "agents.x-k8s.io/claim-name"
)

// ConfinementMode defines how the backing Pod is isolated from direct network egress.
type ConfinementMode string

const (
	// ConfinementModePodNetworkIsolated places the Pod in a loopback-only network
	// namespace (KEP-6313) with no CNI attachment and no Pod IP.
	ConfinementModePodNetworkIsolated ConfinementMode = "PodNetworkIsolated"

	// ConfinementModeNetworkPolicyDenyAll pairs a deny-all NetworkPolicy with NRI
	// RunPodSandbox non-loopback route flushing and tc clsact NIC blocking for clusters without KEP-6313.
	ConfinementModeNetworkPolicyDenyAll ConfinementMode = "NetworkPolicyDenyAll"
)

// NICBlockMode controls whether dra-agents-net attaches pure-netlink tc clsact
// drop filters (ingress and egress) to non-loopback NICs inside the Pod network
// namespace. This is a driver-only, DeviceClass-restricted (FromClass) setting.
type NICBlockMode string

const (
	// NICBlockModeDropAll (default) attaches tc clsact matchall DROP filters to
	// both ingress and egress of every non-loopback NIC inside the Pod netns
	// (excluding tuntap in TunSidecar mode), isolating the Pod independently of
	// CNI NetworkPolicy enforcement.
	NICBlockModeDropAll NICBlockMode = "DropAll"

	// NICBlockModeDisabled disables tc NIC blocking and relies only on non-loopback
	// route flushing and external CNI NetworkPolicy enforcement.
	NICBlockModeDisabled NICBlockMode = "Disabled"
)

// AdapterMode defines how the Pod network namespace connects to the per-Pod
// agents.net egress channel managed by dra-agents-net.
type AdapterMode string

const (
	// AdapterModeTunSidecar injects one tun2connect native sidecar per Pod netns.
	AdapterModeTunSidecar AdapterMode = "TunSidecar"

	// AdapterModeTunVM attaches one tun2connect per microVM over vsock or Unix socket.
	AdapterModeTunVM AdapterMode = "TunVM"

	// AdapterModeExplicitProxy binds 127.0.0.1:<port> inside the Pod loopback netns
	// via socketat and injects multi-language proxy environment variables.
	AdapterModeExplicitProxy AdapterMode = "ExplicitProxy"
)

// PEPAuthType selects the authentication mechanism to the Policy Enforcement Point (PEP).
type PEPAuthType string

const (
	PEPAuthTypeMTLS                PEPAuthType = "MTLS"
	PEPAuthTypeSPIFFE              PEPAuthType = "SPIFFE"
	PEPAuthTypePodCertificate      PEPAuthType = "PodCertificate"
	PEPAuthTypeServiceAccountToken PEPAuthType = "ServiceAccountToken"
)

// SPIFFEMode selects node-level or per-Pod delegated SPIFFE X.509-SVID authentication.
type SPIFFEMode string

const (
	SPIFFEModeNode         SPIFFEMode = "Node"
	SPIFFEModeDelegatedPod SPIFFEMode = "DelegatedPod"
)

// PodCertificateKeyType selects the private key algorithm for KEP-4317 PodCertificate.
type PodCertificateKeyType string

const (
	PodCertificateKeyTypeECDSAP256 PodCertificateKeyType = "ECDSAP256"
	PodCertificateKeyTypeECDSAP384 PodCertificateKeyType = "ECDSAP384"
	PodCertificateKeyTypeED25519   PodCertificateKeyType = "ED25519"
	PodCertificateKeyTypeRSA3072   PodCertificateKeyType = "RSA3072"
)

// ServiceAccountTokenMode selects node-level or Pod-projected JWT authentication.
type ServiceAccountTokenMode string

const (
	ServiceAccountTokenModeNode ServiceAccountTokenMode = "Node"
	ServiceAccountTokenModePod  ServiceAccountTokenMode = "Pod"
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
	CASourceTypeSecret             CASourceType = "Secret"
	CASourceTypeClusterTrustBundle CASourceType = "ClusterTrustBundle"
	CASourceTypeHostPath           CASourceType = "HostPath"
)

// IngressProtocol defines the transport protocol for an explicit ingress port.
type IngressProtocol string

const (
	IngressProtocolTCP IngressProtocol = "TCP"
	IngressProtocolUDP IngressProtocol = "UDP"
)

// ConfigMapKeyRef selects a key inside a ConfigMap in the Pod namespace.
type ConfigMapKeyRef struct {
	Name string `json:"name"`
	Key  string `json:"key,omitempty"`
}

// SecretKeyRef selects a key inside a Secret in the Pod namespace.
// Only valid CERTIFICATE PEM blocks are extracted; private keys are never exposed.
type SecretKeyRef struct {
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
	SecretRef          *SecretKeyRef          `json:"secretRef,omitempty"`
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
	if s.SecretRef != nil {
		sec := *s.SecretRef
		out.SecretRef = &sec
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

// IngressPort declares one allowed container port or inclusive port range
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
	case "ingress-dial-failed", "upstream-connect-failed", "sandbox-not-ready", "dial-failed", "upstream-auth-failed":
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
// Cluster routers and ingress gateways watch ResourceClaims and read this payload
// to discover how to attract and tunnel traffic to isolated Pods without relying on
// a Pod IP.
type DeviceStatus struct {
	APIVersion string         `json:"apiVersion"`
	Kind       string         `json:"kind"`
	NodeName   string         `json:"nodeName"`
	PodUID     string         `json:"podUID"`
	SandboxID  string         `json:"sandboxID,omitempty"`
	Ingress    *IngressStatus `json:"ingress,omitempty"`
}

// IngressStatus advertises how an authorized cluster ingress gateway or router
// reaches a Pod's pinned loopback ports via the node HTTP CONNECT ingress bridge.
type IngressStatus struct {
	// Endpoint is the routable host:port of the node ingress bridge (for example "10.0.0.5:15080").
	Endpoint string `json:"endpoint"`
	// Protocol identifies the bridge tunnel protocol ("http-connect").
	Protocol string `json:"protocol"`
	// Target is the CONNECT authority host (Pod UID), used in "CONNECT <target>:<port> HTTP/1.1".
	Target string `json:"target"`
	// TLS reports whether Endpoint requires TLS/mTLS.
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

// MTLSAuth configures client mTLS credentials from a host directory or Kubernetes Secret.
type MTLSAuth struct {
	CertDir   string                       `json:"certDir,omitempty"`
	SecretRef *corev1.LocalObjectReference `json:"secretRef,omitempty"`
}

// SPIFFEAuth configures SPIFFE Workload API or SPIRE Delegated Identity authentication.
type SPIFFEAuth struct {
	Mode                SPIFFEMode `json:"mode,omitempty"`
	WorkloadSocketPath  string     `json:"workloadSocketPath,omitempty"`
	DelegatedSocketPath string     `json:"delegatedSocketPath,omitempty"`
}

// PodCertificateAuth configures KEP-4317 kubelet-projected PodCertificate authentication.
type PodCertificateAuth struct {
	SignerName           string                `json:"signerName"`
	KeyType              PodCertificateKeyType `json:"keyType,omitempty"`
	MaxExpirationSeconds *int32                `json:"maxExpirationSeconds,omitempty"`
}

// ServiceAccountTokenAuth configures audience-bound Kubernetes ServiceAccount JWT authentication.
type ServiceAccountTokenAuth struct {
	Audience          string                  `json:"audience"`
	Mode              ServiceAccountTokenMode `json:"mode,omitempty"`
	ExpirationSeconds *int32                  `json:"expirationSeconds,omitempty"`
}

// PEPAuth is a discriminated union selecting client authentication to the Policy Enforcement Point (PEP).
type PEPAuth struct {
	Type                PEPAuthType              `json:"type"`
	MTLS                *MTLSAuth                `json:"mtls,omitempty"`
	SPIFFE              *SPIFFEAuth              `json:"spiffe,omitempty"`
	PodCertificate      *PodCertificateAuth      `json:"podCertificate,omitempty"`
	ServiceAccountToken *ServiceAccountTokenAuth `json:"serviceAccountToken,omitempty"`
}

// DeepCopy returns a deep copy of a.
func (a *PEPAuth) DeepCopy() *PEPAuth {
	if a == nil {
		return nil
	}
	out := *a
	if a.MTLS != nil {
		m := *a.MTLS
		if a.MTLS.SecretRef != nil {
			ref := *a.MTLS.SecretRef
			m.SecretRef = &ref
		}
		out.MTLS = &m
	}
	if a.SPIFFE != nil {
		s := *a.SPIFFE
		out.SPIFFE = &s
	}
	if a.PodCertificate != nil {
		pc := *a.PodCertificate
		if a.PodCertificate.MaxExpirationSeconds != nil {
			v := *a.PodCertificate.MaxExpirationSeconds
			pc.MaxExpirationSeconds = &v
		}
		out.PodCertificate = &pc
	}
	if a.ServiceAccountToken != nil {
		sa := *a.ServiceAccountToken
		if a.ServiceAccountToken.ExpirationSeconds != nil {
			v := *a.ServiceAccountToken.ExpirationSeconds
			sa.ExpirationSeconds = &v
		}
		out.ServiceAccountToken = &sa
	}
	return &out
}

// PolicyEnforcementPointConfig defines the Policy Enforcement Point (PEP) proxy or portal endpoint.
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
