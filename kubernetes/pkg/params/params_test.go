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

package params

import (
	"testing"

	resourceapi "k8s.io/api/resource/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/aojea/agents.net/kubernetes/pkg/apis"
)

func TestDecodeLayersClassAndClaimDriverConfig(t *testing.T) {
	configs := []resourceapi.DeviceAllocationConfiguration{
		{
			Source: resourceapi.AllocationConfigSourceClass,
			DeviceConfiguration: resourceapi.DeviceConfiguration{
				Opaque: &resourceapi.OpaqueDeviceConfiguration{
					Driver: apis.DriverName,
					Parameters: runtime.RawExtension{Raw: []byte(`{
						"apiVersion": "dra.agents.net/v1alpha1",
						"kind": "DriverConfig",
						"confinementMode": "PodNetworkIsolated",
						"adapterMode": "ExplicitProxy",
						"proxy": {"port": 18080, "noProxy": [".internal.corp"]},
						"policyEnforcementPoint": {
							"url": "https://tenant-pep.team-a.svc:8443",
							"tls": {"trustDomain": "cluster.local"},
							"auth": {"type": "SPIFFE"}
						},
						"caTrust": {
							"mode": "InjectEnv",
							"sources": [{"type": "HostPath", "hostPath": "/etc/corp/ca.crt"}]
						},
						"custom": {"env": "prod", "region": "us-central1"},
						"maxConnections": 128
					}`)},
				},
			},
		},
		{
			// Foreign driver entry must be ignored.
			Source: resourceapi.AllocationConfigSourceClass,
			DeviceConfiguration: resourceapi.DeviceConfiguration{
				Opaque: &resourceapi.OpaqueDeviceConfiguration{
					Driver:     "dra.other.io",
					Parameters: runtime.RawExtension{Raw: []byte(`{"adapterMode": "Unknown"}`)},
				},
			},
		},
		{
			Source: resourceapi.AllocationConfigSourceClaim,
			DeviceConfiguration: resourceapi.DeviceConfiguration{
				Opaque: &resourceapi.OpaqueDeviceConfiguration{
					Driver: apis.DriverName,
					Parameters: runtime.RawExtension{Raw: []byte(`{
						"apiVersion": "dra.agents.net/v1alpha1",
						"kind": "DriverConfig",
						"proxy": {"noProxy": [".team-a.local"]},
						"caTrust": {
							"sources": [{"type": "ConfigMap", "configMapRef": {"name": "team-ca"}}]
						},
						"ingressPorts": [{"port": 8080, "protocol": "TCP"}, {"port": 9000, "endPort": 9005, "protocol": "TCP"}]
					}`)},
				},
			},
		},
	}

	got, err := Decode(configs, apis.DriverName)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.ConfinementMode != apis.ConfinementModePodNetworkIsolated {
		t.Fatalf("ConfinementMode = %q, want PodNetworkIsolated", got.ConfinementMode)
	}
	if got.AdapterMode != apis.AdapterModeExplicitProxy {
		t.Fatalf("AdapterMode = %q, want ExplicitProxy from DeviceClass DriverConfig", got.AdapterMode)
	}
	if got.EffectiveProxyPort() != 18080 {
		t.Fatalf("EffectiveProxyPort = %d, want 18080 from DeviceClass DriverConfig", got.EffectiveProxyPort())
	}
	if got.Proxy == nil || len(got.Proxy.NoProxy) != 2 || got.Proxy.NoProxy[0] != ".internal.corp" || got.Proxy.NoProxy[1] != ".team-a.local" {
		t.Fatalf("unexpected Proxy config: %+v", got.Proxy)
	}
	if got.CATrust == nil || len(got.CATrust.Sources) != 2 {
		t.Fatalf("expected merged 2 CA sources from class+claim, got %+v", got.CATrust)
	}
	if got.PolicyEnforcementPoint == nil || got.PolicyEnforcementPoint.URL != "https://tenant-pep.team-a.svc:8443" {
		t.Fatalf("PEP url = %+v, want tenant PEP", got.PolicyEnforcementPoint)
	}
	if got.PolicyEnforcementPoint.TLS == nil || got.PolicyEnforcementPoint.TLS.TrustDomain != "cluster.local" {
		t.Fatalf("expected DeviceClass TLS trustDomain preserved, got %+v", got.PolicyEnforcementPoint.TLS)
	}
	if got.PolicyEnforcementPoint.Auth == nil || got.PolicyEnforcementPoint.Auth.Type != apis.PEPAuthTypeSPIFFE {
		t.Fatalf("expected DeviceClass auth preserved, got %+v", got.PolicyEnforcementPoint.Auth)
	}
	if len(got.IngressPorts) != 2 || got.IngressPorts[0].Port != 8080 || got.IngressPorts[1].Port != 9000 || got.IngressPorts[1].EndPort != 9005 {
		t.Fatalf("unexpected ingressPorts: %+v", got.IngressPorts)
	}
	if got.Custom["region"] != "us-central1" || got.Custom["env"] != "prod" {
		t.Fatalf("unexpected class custom params: %+v", got.Custom)
	}
	if got.MaxConnections == nil || *got.MaxConnections != 128 {
		t.Fatalf("maxConnections = %v, want 128", got.MaxConnections)
	}
}

func TestDecodeRejectsPrivilegedClaimFieldsAndUnknownKeys(t *testing.T) {
	// 1. Out-of-order configs: FromClaim appears before FromClass, yet FromClass still applies first.
	reversed := []resourceapi.DeviceAllocationConfiguration{
		{
			Source:   resourceapi.AllocationConfigSourceClaim,
			Requests: []string{"agents-net"},
			DeviceConfiguration: resourceapi.DeviceConfiguration{
				Opaque: &resourceapi.OpaqueDeviceConfiguration{
					Driver:     apis.DriverName,
					Parameters: runtime.RawExtension{Raw: []byte(`{"ingressPorts":[{"port":8080}],"proxy":{"port":19000}}`)},
				},
			},
		},
		{
			Source:   resourceapi.AllocationConfigSourceClass,
			Requests: []string{"agents-net"},
			DeviceConfiguration: resourceapi.DeviceConfiguration{
				Opaque: &resourceapi.OpaqueDeviceConfiguration{
					Driver:     apis.DriverName,
					Parameters: runtime.RawExtension{Raw: []byte(`{"confinementMode":"PodNetworkIsolated","proxy":{"port":15001},"custom":{"c":"1"}}`)},
				},
			},
		},
		{
			Source:   resourceapi.AllocationConfigSourceClaim,
			Requests: []string{"other-request"},
			DeviceConfiguration: resourceapi.DeviceConfiguration{
				Opaque: &resourceapi.OpaqueDeviceConfiguration{
					Driver:     apis.DriverName,
					Parameters: runtime.RawExtension{Raw: []byte(`{"ingressPorts":[{"port":9999}]}`)},
				},
			},
		},
	}
	got, err := DecodeForRequest(reversed, apis.DriverName, "agents-net")
	if err != nil {
		t.Fatalf("DecodeForRequest: %v", err)
	}
	if got.EffectiveProxyPort() != 19000 {
		t.Fatalf("EffectiveProxyPort = %d, want 19000 (claim overlays class)", got.EffectiveProxyPort())
	}
	if len(got.IngressPorts) != 1 || got.IngressPorts[0].Port != 8080 {
		t.Fatalf("unexpected ingressPorts: %+v", got.IngressPorts)
	}
	if got.Custom["c"] != "1" {
		t.Fatalf("unexpected class custom: %+v", got.Custom)
	}

	// 2. FromClass (DeviceClass) validation: nicBlockMode, mandatory mTLS, unknown fields, UDP rejection.
	optOut, err := Decode([]resourceapi.DeviceAllocationConfiguration{
		{
			Source: resourceapi.AllocationConfigSourceClass,
			DeviceConfiguration: resourceapi.DeviceConfiguration{
				Opaque: &resourceapi.OpaqueDeviceConfiguration{
					Driver:     apis.DriverName,
					Parameters: runtime.RawExtension{Raw: []byte(`{"nicBlockMode":"Disabled"}`)},
				},
			},
		},
	}, apis.DriverName)
	if err != nil {
		t.Fatalf("Decode FromClass nicBlockMode=Disabled: %v", err)
	}
	if optOut.EffectiveNICBlockMode() != apis.NICBlockModeDisabled {
		t.Fatalf("EffectiveNICBlockMode() = %q, want Disabled", optOut.EffectiveNICBlockMode())
	}

	rejectedClass := []struct {
		name string
		raw  string
	}{
		{"invalid nicBlockMode", `{"nicBlockMode":"BogusMode"}`},
		{"unknown JSON field", `{"unknownField":true}`},
		{"plaintext http PEP URL", `{"policyEnforcementPoint":{"url":"http://pep:8080"}}`},
		{"https PEP without mandatory mTLS auth", `{"policyEnforcementPoint":{"url":"https://pep:8443"}}`},
		{"unsupported UDP ingressPort", `{"ingressPorts":[{"port":53,"protocol":"UDP"}]}`},
		{"path traversal podCertVolumeName", `{"podCertVolumeName":"../../etc"}`},
	}
	for _, tc := range rejectedClass {
		t.Run("class/"+tc.name, func(t *testing.T) {
			_, err := Decode([]resourceapi.DeviceAllocationConfiguration{
				{
					Source: resourceapi.AllocationConfigSourceClass,
					DeviceConfiguration: resourceapi.DeviceConfiguration{
						Opaque: &resourceapi.OpaqueDeviceConfiguration{
							Driver:     apis.DriverName,
							Parameters: runtime.RawExtension{Raw: []byte(tc.raw)},
						},
					},
				},
			}, apis.DriverName)
			if err == nil {
				t.Fatalf("expected error for class %s, got nil", tc.name)
			}
		})
	}

	// 3. FromClaim MUST reject all cluster-admin fields (PEP hijack, confinement downgrade,
	// adapterMode flip, spoofed custom attributes, hostPath CA, limits, and unknown fields).
	rejectedClaims := []struct {
		name string
		raw  string
	}{
		{"confinementMode downgrade", `{"confinementMode":"NetworkPolicyDenyAll"}`},
		{"adapterMode TunSidecar escalation", `{"adapterMode":"TunSidecar"}`},
		{"policyEnforcementPoint hijack", `{"policyEnforcementPoint":{"url":"https://attacker.example:8443","auth":{"type":"SPIFFE"}}}`},
		{"policyEnforcementPoint unix SSRF", `{"policyEnforcementPoint":{"url":"unix:///var/run/nri/nri.sock"}}`},
		{"custom attested attribute spoof", `{"custom":{"tenant":"admin"}}`},
		{"caTrust hostPath", `{"caTrust":{"sources":[{"type":"HostPath","hostPath":"/etc/shadow"}]}}`},
		{"maxConnections override", `{"maxConnections":99999}`},
		{"idleTimeoutSeconds override", `{"idleTimeoutSeconds":99999}`},
		{"nicBlockMode Disabled override", `{"nicBlockMode":"Disabled"}`},
		{"podCertVolumeName override", `{"podCertVolumeName":"my-cert"}`},
		{"bad noProxy chars", `{"proxy":{"noProxy":["ok.local","bad host"]}}`},
		{"ingress endPort below port", `{"ingressPorts":[{"port":9005,"endPort":9000}]}`},
		{"ingress endPort above 65535", `{"ingressPorts":[{"port":9000,"endPort":70000}]}`},
		{"unknown JSON field", `{"typoField":"x"}`},
	}
	for _, tc := range rejectedClaims {
		t.Run("claim/"+tc.name, func(t *testing.T) {
			_, err := Decode([]resourceapi.DeviceAllocationConfiguration{
				{
					Source: resourceapi.AllocationConfigSourceClaim,
					DeviceConfiguration: resourceapi.DeviceConfiguration{
						Opaque: &resourceapi.OpaqueDeviceConfiguration{
							Driver:     apis.DriverName,
							Parameters: runtime.RawExtension{Raw: []byte(tc.raw)},
						},
					},
				},
			}, apis.DriverName)
			if err == nil {
				t.Fatalf("expected error for claim %s, got nil", tc.name)
			}
		})
	}
}
