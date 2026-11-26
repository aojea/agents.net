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

// Package params decodes and layers DRA OpaqueDeviceConfiguration parameters
// (DeviceClass FromClass DriverConfig merged with ResourceClaim FromClaim
// DriverConfig) for dra-agents-net.
package params

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/url"
	"slices"
	"strings"

	resourceapi "k8s.io/api/resource/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/aojea/agents.net/kubernetes/pkg/apis"
)

const (
	// DefaultMaxConnections is the default per-Pod concurrent tunnel limit.
	DefaultMaxConnections int32 = 1024

	// MaxAllowedConnections caps MaxConnections to prevent per-Pod FD exhaustion.
	MaxAllowedConnections int32 = 65535

	// DefaultIdleTimeoutSeconds is the default idle timeout for forwarded tunnels.
	DefaultIdleTimeoutSeconds int32 = 300

	// MaxIdleTimeoutSeconds caps IdleTimeoutSeconds to 24 hours.
	MaxIdleTimeoutSeconds int32 = 86400
)

// NetworkParameters is the merged dra.agents.net/v1alpha1 DriverConfig for a
// single prepared Pod, decoded from ordered Kubernetes DRA
// OpaqueDeviceConfiguration entries (FromClass defaults layered with FromClaim
// workload overrides).
type NetworkParameters struct {
	metav1.TypeMeta        `json:",inline"`
	ConfinementMode        apis.ConfinementMode               `json:"confinementMode,omitempty"`
	NICBlockMode           apis.NICBlockMode                  `json:"nicBlockMode,omitempty"`
	AdapterMode            apis.AdapterMode                   `json:"adapterMode,omitempty"`
	PolicyEnforcementPoint *apis.PolicyEnforcementPointConfig `json:"policyEnforcementPoint,omitempty"`
	CATrust                *apis.CATrustConfig                `json:"caTrust,omitempty"`
	Proxy                  *apis.ExplicitProxyConfig          `json:"proxy,omitempty"`
	IngressPorts           []apis.IngressPort                 `json:"ingressPorts,omitempty"`
	PodCertVolumeName      string                             `json:"podCertVolumeName,omitempty"`
	MaxConnections         *int32                             `json:"maxConnections,omitempty"`
	IdleTimeoutSeconds     *int32                             `json:"idleTimeoutSeconds,omitempty"`
	// Custom holds admin-attested string key-value attributes from DeviceClass
	// forwarded in the RFC 8941 Agents-Net-Attributes header.
	Custom map[string]string `json:"custom,omitempty"`
}

// EffectiveAdapterMode returns the configured AdapterMode or the default (HostTun).
func (p NetworkParameters) EffectiveAdapterMode() apis.AdapterMode {
	if p.AdapterMode != "" {
		return p.AdapterMode
	}
	return apis.AdapterModeHostTun
}

// EffectiveNICBlockMode returns the configured NICBlockMode or the default (DropAll).
func (p NetworkParameters) EffectiveNICBlockMode() apis.NICBlockMode {
	if p.NICBlockMode != "" {
		return p.NICBlockMode
	}
	return apis.NICBlockModeDropAll
}

// EffectiveProxyPort returns the configured ExplicitProxy loopback port or the default (15001).
func (p NetworkParameters) EffectiveProxyPort() int32 {
	if p.Proxy != nil && p.Proxy.Port != nil && *p.Proxy.Port > 0 {
		return *p.Proxy.Port
	}
	return apis.DefaultProxyPort
}

// Defaults returns a NetworkParameters initialized with safe defaults.
func Defaults() NetworkParameters {
	return NetworkParameters{
		ConfinementMode:    apis.ConfinementModePodNetworkIsolated,
		NICBlockMode:       apis.NICBlockModeDropAll,
		AdapterMode:        apis.AdapterModeHostTun,
		MaxConnections:     new(DefaultMaxConnections),
		IdleTimeoutSeconds: new(DefaultIdleTimeoutSeconds),
	}
}

// Decode merges all matching OpaqueDeviceConfiguration entries from a DRA allocation
// (DeviceClass DriverConfig defaults first, then ResourceClaim DriverConfig overrides).
func Decode(configs []resourceapi.DeviceAllocationConfiguration, driverName string) (NetworkParameters, error) {
	return DecodeForRequest(configs, driverName, "")
}

// DecodeForRequest merges OpaqueDeviceConfiguration entries matching driverName and
// requestName (when non-empty), applying DeviceClass (FromClass) entries strictly
// before ResourceClaim (FromClaim) entries. Security-sensitive fields (confinementMode,
// nicBlockMode, adapterMode, policyEnforcementPoint, podCertVolumeName, custom attributes,
// HostPath CA sources, and resource limits) are restricted strictly to DeviceClass.
func DecodeForRequest(configs []resourceapi.DeviceAllocationConfiguration, driverName, requestName string) (NetworkParameters, error) {
	out := Defaults()

	// Apply FromClass configurations first, then FromClaim configurations, regardless of slice ordering.
	classCfgs := make([]resourceapi.DeviceAllocationConfiguration, 0, len(configs))
	claimCfgs := make([]resourceapi.DeviceAllocationConfiguration, 0, len(configs))
	for _, cfg := range configs {
		if cfg.Opaque == nil || cfg.Opaque.Driver != driverName || len(cfg.Opaque.Parameters.Raw) == 0 {
			continue
		}
		if requestName != "" && len(cfg.Requests) > 0 && !slices.Contains(cfg.Requests, requestName) {
			continue
		}
		if cfg.Source == resourceapi.AllocationConfigSourceClass {
			classCfgs = append(classCfgs, cfg)
		} else {
			claimCfgs = append(claimCfgs, cfg)
		}
	}

	apply := func(cfg resourceapi.DeviceAllocationConfiguration, fromClass bool) error {
		layer, err := unmarshalLayer(cfg.Opaque.Parameters.Raw, driverName)
		if err != nil {
			return err
		}
		if !fromClass {
			if err := validateClaimLayer(&layer); err != nil {
				return err
			}
		}
		Merge(&out, &layer)
		return nil
	}

	for _, cfg := range classCfgs {
		if err := apply(cfg, true); err != nil {
			return out, err
		}
	}
	for _, cfg := range claimCfgs {
		if err := apply(cfg, false); err != nil {
			return out, err
		}
	}
	if err := out.Validate(); err != nil {
		return out, err
	}
	return out, nil
}

func unmarshalLayer(raw []byte, driverName string) (NetworkParameters, error) {
	var layer NetworkParameters
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&layer); err != nil {
		return NetworkParameters{}, fmt.Errorf("unmarshal opaque parameters for driver %q: %w", driverName, err)
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return NetworkParameters{}, fmt.Errorf("unexpected trailing data in opaque parameters for driver %q", driverName)
	}
	if layer.Kind != "" && layer.Kind != apis.DriverConfigKind {
		return NetworkParameters{}, fmt.Errorf("unsupported opaque parameter kind %q for driver %q (expected %q)", layer.Kind, driverName, apis.DriverConfigKind)
	}
	if layer.APIVersion != "" && layer.APIVersion != apis.DriverConfigAPIVersion {
		return NetworkParameters{}, fmt.Errorf("unsupported opaque parameter apiVersion %q for driver %q (expected %q)", layer.APIVersion, driverName, apis.DriverConfigAPIVersion)
	}
	return layer, nil
}

// validateClaimLayer enforces the trust boundary between cluster-admin DeviceClass
// (FromClass) and namespace-scoped ResourceClaim (FromClaim) configuration.
// Namespace claims may only configure workload-local ingressPorts, explicit proxy
// port/noProxy, and non-HostPath caTrust sources.
func validateClaimLayer(layer *NetworkParameters) error {
	if layer.ConfinementMode != "" {
		return fmt.Errorf("confinementMode is restricted to DeviceClass configuration")
	}
	if layer.NICBlockMode != "" {
		return fmt.Errorf("nicBlockMode is restricted to DeviceClass configuration")
	}
	if layer.AdapterMode != "" {
		return fmt.Errorf("adapterMode is restricted to DeviceClass configuration")
	}
	if layer.PolicyEnforcementPoint != nil {
		return fmt.Errorf("policyEnforcementPoint is restricted to DeviceClass configuration")
	}
	if layer.PodCertVolumeName != "" {
		return fmt.Errorf("podCertVolumeName is restricted to DeviceClass configuration")
	}
	if layer.MaxConnections != nil || layer.IdleTimeoutSeconds != nil {
		return fmt.Errorf("maxConnections and idleTimeoutSeconds are restricted to DeviceClass configuration")
	}
	if len(layer.Custom) > 0 {
		return fmt.Errorf("custom attested attributes are restricted to DeviceClass configuration")
	}
	if layer.CATrust != nil {
		for _, src := range layer.CATrust.Sources {
			if src.Type == apis.CASourceTypeHostPath || src.HostPath != "" {
				return fmt.Errorf("caTrust hostPath source is restricted to DeviceClass configuration")
			}
		}
	}
	return nil
}

// Validate checks bounds, enum values, mandatory mTLS rules, and safe identifiers.
func (p NetworkParameters) Validate() error {
	switch p.ConfinementMode {
	case "", apis.ConfinementModePodNetworkIsolated, apis.ConfinementModeNetworkPolicyDenyAll:
	default:
		return fmt.Errorf("invalid confinementMode %q", p.ConfinementMode)
	}
	switch p.NICBlockMode {
	case "", apis.NICBlockModeDropAll, apis.NICBlockModeDisabled:
	default:
		return fmt.Errorf("invalid nicBlockMode %q", p.NICBlockMode)
	}
	switch p.AdapterMode {
	case "", apis.AdapterModeHostTun, apis.AdapterModeExplicitProxy, apis.AdapterModeTunSidecar:
	default:
		return fmt.Errorf("invalid adapterMode %q", p.AdapterMode)
	}
	if p.PolicyEnforcementPoint != nil {
		if err := validatePEP(p.PolicyEnforcementPoint); err != nil {
			return err
		}
	}
	if p.MaxConnections != nil && (*p.MaxConnections < 1 || *p.MaxConnections > MaxAllowedConnections) {
		return fmt.Errorf("maxConnections %d out of range [1, %d]", *p.MaxConnections, MaxAllowedConnections)
	}
	if p.IdleTimeoutSeconds != nil && (*p.IdleTimeoutSeconds < 1 || *p.IdleTimeoutSeconds > MaxIdleTimeoutSeconds) {
		return fmt.Errorf("idleTimeoutSeconds %d out of range [1, %d]", *p.IdleTimeoutSeconds, MaxIdleTimeoutSeconds)
	}
	if p.Proxy != nil {
		if p.Proxy.Port != nil && (*p.Proxy.Port < 1 || *p.Proxy.Port > 65535) {
			return fmt.Errorf("proxy.port %d out of range [1, 65535]", *p.Proxy.Port)
		}
		for _, entry := range p.Proxy.NoProxy {
			if strings.ContainsAny(entry, " \t\r\n\"'|") {
				return fmt.Errorf("invalid proxy.noProxy entry %q: contains forbidden characters", entry)
			}
		}
	}
	if p.PodCertVolumeName != "" && !isDNS1123Label(p.PodCertVolumeName) {
		return fmt.Errorf("invalid podCertVolumeName %q: must be a DNS-1123 label", p.PodCertVolumeName)
	}
	for _, port := range p.IngressPorts {
		if port.Port < 1 || port.Port > 65535 {
			return fmt.Errorf("ingressPort %d out of range [1, 65535]", port.Port)
		}
		if port.EndPort != 0 && (port.EndPort < port.Port || port.EndPort > 65535) {
			return fmt.Errorf("ingressPort endPort %d out of range [%d, 65535]", port.EndPort, port.Port)
		}
		switch port.Protocol {
		case "", apis.IngressProtocolTCP:
		default:
			return fmt.Errorf("invalid ingressPort protocol %q (only TCP is supported)", port.Protocol)
		}
	}
	if p.CATrust != nil {
		switch p.CATrust.Mode {
		case "", apis.CATrustModeNone, apis.CATrustModeMountOnly, apis.CATrustModeInjectEnv:
		default:
			return fmt.Errorf("invalid caTrust.mode %q", p.CATrust.Mode)
		}
		switch p.CATrust.BundleMode {
		case "", apis.CABundleModeAppendSystemRoots, apis.CABundleModeReplace:
		default:
			return fmt.Errorf("invalid caTrust.bundleMode %q", p.CATrust.BundleMode)
		}
	}
	return nil
}

func validatePEP(pep *apis.PolicyEnforcementPointConfig) error {
	rawURL := strings.TrimSpace(pep.URL)
	if rawURL == "" {
		return nil
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid policyEnforcementPoint.url %q: %w", pep.URL, err)
	}
	switch u.Scheme {
	case "https":
		if u.Hostname() == "" {
			return fmt.Errorf("policyEnforcementPoint.url %q missing host", pep.URL)
		}
		if pep.Auth == nil || pep.Auth.Type == "" {
			return fmt.Errorf("policyEnforcementPoint.auth (MTLS, SPIFFE, or PodCertificate) is required for https:// endpoints")
		}
		switch pep.Auth.Type {
		case apis.PEPAuthTypeMTLS, apis.PEPAuthTypeSPIFFE, apis.PEPAuthTypePodCertificate:
		default:
			return fmt.Errorf("invalid policyEnforcementPoint.auth.type %q", pep.Auth.Type)
		}
	case "unix":
		if u.Path == "" && u.Opaque == "" {
			return fmt.Errorf("policyEnforcementPoint.url %q missing unix socket path", pep.URL)
		}
	default:
		return fmt.Errorf("unsupported policyEnforcementPoint.url scheme %q (want https or unix; plaintext http is forbidden)", u.Scheme)
	}
	return nil
}

func isDNS1123Label(s string) bool {
	if len(s) == 0 || len(s) > 63 {
		return false
	}
	for i := range len(s) {
		c := s[i]
		isLower := c >= 'a' && c <= 'z'
		isDigit := c >= '0' && c <= '9'
		if !isLower && !isDigit && c != '-' {
			return false
		}
		if (i == 0 || i == len(s)-1) && c == '-' {
			return false
		}
	}
	return true
}

// Merge overlays non-empty fields from src onto dst.
func Merge(dst, src *NetworkParameters) {
	if dst == nil || src == nil {
		return
	}
	if src.ConfinementMode != "" {
		dst.ConfinementMode = src.ConfinementMode
	}
	if src.NICBlockMode != "" {
		dst.NICBlockMode = src.NICBlockMode
	}
	if src.AdapterMode != "" {
		dst.AdapterMode = src.AdapterMode
	}
	if src.PolicyEnforcementPoint != nil {
		dst.PolicyEnforcementPoint = mergePEP(dst.PolicyEnforcementPoint, src.PolicyEnforcementPoint)
	}
	if src.CATrust != nil {
		dst.CATrust = mergeCATrust(dst.CATrust, src.CATrust)
	}
	if src.Proxy != nil {
		dst.Proxy = mergeProxy(dst.Proxy, src.Proxy)
	}
	if len(src.IngressPorts) > 0 {
		dst.IngressPorts = slices.Clone(src.IngressPorts)
	}
	if src.PodCertVolumeName != "" {
		dst.PodCertVolumeName = src.PodCertVolumeName
	}
	if src.MaxConnections != nil {
		dst.MaxConnections = new(*src.MaxConnections)
	}
	if src.IdleTimeoutSeconds != nil {
		dst.IdleTimeoutSeconds = new(*src.IdleTimeoutSeconds)
	}
	if len(src.Custom) > 0 {
		if dst.Custom == nil {
			dst.Custom = make(map[string]string, len(src.Custom))
		}
		maps.Copy(dst.Custom, src.Custom)
	}
}

func mergeCATrust(base, overlay *apis.CATrustConfig) *apis.CATrustConfig {
	if base == nil {
		return overlay.DeepCopy()
	}
	out := base.DeepCopy()
	if overlay.Mode != "" {
		out.Mode = overlay.Mode
	}
	if overlay.BundleMode != "" {
		out.BundleMode = overlay.BundleMode
	}
	if len(overlay.Sources) > 0 {
		for i := range overlay.Sources {
			out.Sources = append(out.Sources, *overlay.Sources[i].DeepCopy())
		}
	}
	return out
}

func mergeProxy(base, overlay *apis.ExplicitProxyConfig) *apis.ExplicitProxyConfig {
	if base == nil {
		return overlay.DeepCopy()
	}
	out := base.DeepCopy()
	if overlay.Port != nil {
		out.Port = new(*overlay.Port)
	}
	if len(overlay.NoProxy) > 0 {
		out.NoProxy = append(out.NoProxy, overlay.NoProxy...)
	}
	return out
}

func mergePEP(base, overlay *apis.PolicyEnforcementPointConfig) *apis.PolicyEnforcementPointConfig {
	if base == nil {
		return overlay.DeepCopy()
	}
	out := base.DeepCopy()
	if overlay.URL != "" {
		out.URL = overlay.URL
	}
	if overlay.TLS != nil {
		if out.TLS == nil {
			out.TLS = overlay.TLS.DeepCopy()
		} else {
			if overlay.TLS.ServerName != "" {
				out.TLS.ServerName = overlay.TLS.ServerName
			}
			if len(overlay.TLS.CACertificateRefs) > 0 {
				out.TLS.CACertificateRefs = make([]apis.CASource, len(overlay.TLS.CACertificateRefs))
				for i := range overlay.TLS.CACertificateRefs {
					out.TLS.CACertificateRefs[i] = *overlay.TLS.CACertificateRefs[i].DeepCopy()
				}
			}
			if overlay.TLS.TrustDomain != "" {
				out.TLS.TrustDomain = overlay.TLS.TrustDomain
			}
			if len(overlay.TLS.AcceptedSPIFFEIDs) > 0 {
				out.TLS.AcceptedSPIFFEIDs = slices.Clone(overlay.TLS.AcceptedSPIFFEIDs)
			}
		}
	}
	if overlay.Auth != nil && overlay.Auth.Type != "" {
		out.Auth = overlay.Auth.DeepCopy()
	}
	return out
}
