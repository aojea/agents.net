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
	"encoding/json"
	"fmt"
	"maps"
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
	SATokenVolumeName      string                             `json:"saTokenVolumeName,omitempty"`
	MaxConnections         *int32                             `json:"maxConnections,omitempty"`
	IdleTimeoutSeconds     *int32                             `json:"idleTimeoutSeconds,omitempty"`
	// Custom holds string key-value metadata forwarded as attested Agents-Net-Param-* headers.
	Custom map[string]string `json:"custom,omitempty"`
	// Opaque holds arbitrary private JSON configuration objects supplied via DRA Opaque config.
	Opaque map[string]json.RawMessage `json:"opaque,omitempty"`
}

// EffectiveAdapterMode returns the configured AdapterMode or the default (ExplicitProxy).
func (p NetworkParameters) EffectiveAdapterMode() apis.AdapterMode {
	if p.AdapterMode != "" {
		return p.AdapterMode
	}
	return apis.AdapterModeExplicitProxy
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
		AdapterMode:        apis.AdapterModeExplicitProxy,
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
// before ResourceClaim (FromClaim) entries. Privileged host-node fields (HostPath,
// MTLS.CertDir, SPIFFE socket overrides, and per-Pod resource limits) are rejected
// unless sourced from FromClass.
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
	if err := json.Unmarshal(raw, &layer); err != nil {
		return NetworkParameters{}, fmt.Errorf("unmarshal opaque parameters for driver %q: %w", driverName, err)
	}
	if layer.Kind != "" && layer.Kind != apis.DriverConfigKind {
		return NetworkParameters{}, fmt.Errorf("unsupported opaque parameter kind %q for driver %q (expected %q)", layer.Kind, driverName, apis.DriverConfigKind)
	}
	if layer.APIVersion != "" && layer.APIVersion != apis.DriverConfigAPIVersion {
		return NetworkParameters{}, fmt.Errorf("unsupported opaque parameter apiVersion %q for driver %q (expected %q)", layer.APIVersion, driverName, apis.DriverConfigAPIVersion)
	}
	return layer, nil
}

// validateClaimLayer rejects host-node filesystem/socket references and admin resource
// limit overrides when supplied by a namespace-scoped ResourceClaim (FromClaim) rather
// than a cluster-admin DeviceClass (FromClass).
func validateClaimLayer(layer *NetworkParameters) error {
	if layer.CATrust != nil {
		for _, src := range layer.CATrust.Sources {
			if src.Type == apis.CASourceTypeHostPath || src.HostPath != "" {
				return fmt.Errorf("caTrust hostPath source is restricted to DeviceClass configuration")
			}
		}
	}
	if pep := layer.PolicyEnforcementPoint; pep != nil {
		if pep.TLS != nil {
			for _, src := range pep.TLS.CACertificateRefs {
				if src.Type == apis.CASourceTypeHostPath || src.HostPath != "" {
					return fmt.Errorf("policyEnforcementPoint.tls hostPath CA source is restricted to DeviceClass configuration")
				}
			}
		}
		if pep.Auth != nil {
			if pep.Auth.MTLS != nil && pep.Auth.MTLS.CertDir != "" {
				return fmt.Errorf("mtls.certDir is restricted to DeviceClass configuration")
			}
			if pep.Auth.SPIFFE != nil && (pep.Auth.SPIFFE.WorkloadSocketPath != "" || pep.Auth.SPIFFE.DelegatedSocketPath != "") {
				return fmt.Errorf("spiffe host socket path overrides are restricted to DeviceClass configuration")
			}
		}
	}
	if layer.MaxConnections != nil || layer.IdleTimeoutSeconds != nil {
		return fmt.Errorf("maxConnections and idleTimeoutSeconds are restricted to DeviceClass configuration")
	}
	if layer.NICBlockMode != "" {
		return fmt.Errorf("nicBlockMode is restricted to DeviceClass configuration")
	}
	return nil
}

// Validate checks bounds, enum values, and safe identifiers on decoded NetworkParameters.
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
	case "", apis.AdapterModeExplicitProxy, apis.AdapterModeTunSidecar, apis.AdapterModeTunVM:
	default:
		return fmt.Errorf("invalid adapterMode %q", p.AdapterMode)
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
	if p.SATokenVolumeName != "" && !isDNS1123Label(p.SATokenVolumeName) {
		return fmt.Errorf("invalid saTokenVolumeName %q: must be a DNS-1123 label", p.SATokenVolumeName)
	}
	for _, port := range p.IngressPorts {
		if port.Port < 1 || port.Port > 65535 {
			return fmt.Errorf("ingressPort %d out of range [1, 65535]", port.Port)
		}
		switch port.Protocol {
		case "", apis.IngressProtocolTCP, apis.IngressProtocolUDP:
		default:
			return fmt.Errorf("invalid ingressPort protocol %q", port.Protocol)
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
	if src.SATokenVolumeName != "" {
		dst.SATokenVolumeName = src.SATokenVolumeName
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
	if len(src.Opaque) > 0 {
		if dst.Opaque == nil {
			dst.Opaque = make(map[string]json.RawMessage, len(src.Opaque))
		}
		for k, v := range src.Opaque {
			dst.Opaque[k] = slices.Clone(v)
		}
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
