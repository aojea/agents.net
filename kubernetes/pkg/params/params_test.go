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
							"tls": {"trustDomain": "cluster.local"},
							"auth": {"type": "SPIFFE", "spiffe": {"mode": "Node"}}
						},
						"caTrust": {
							"mode": "InjectEnv",
							"sources": [{"type": "HostPath", "hostPath": "/etc/corp/ca.crt"}]
						},
						"custom": {"env": "prod", "region": "us-central1"},
						"opaque": {"vendorFlag": {"tier": "gold"}},
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
					Parameters: runtime.RawExtension{Raw: []byte(`{"adapterMode": "TunVM"}`)},
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
						"confinementMode": "NetworkPolicyDenyAll",
						"policyEnforcementPoint": {
							"url": "https://tenant-pep.team-a.svc:8443"
						},
						"caTrust": {
							"sources": [{"type": "ConfigMap", "configMapRef": {"name": "team-ca"}}]
						},
						"ingressPorts": [{"port": 8080, "protocol": "TCP"}, {"port": 9000, "endPort": 9005, "protocol": "TCP"}],
						"custom": {
							"env": "staging",
							"tenant": "team-a"
						}
					}`)},
				},
			},
		},
	}

	got, err := Decode(configs, apis.DriverName)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.ConfinementMode != apis.ConfinementModeNetworkPolicyDenyAll {
		t.Fatalf("ConfinementMode = %q, want NetworkPolicyDenyAll", got.ConfinementMode)
	}
	if got.AdapterMode != apis.AdapterModeExplicitProxy {
		t.Fatalf("AdapterMode = %q, want ExplicitProxy from DeviceClass DriverConfig", got.AdapterMode)
	}
	if got.EffectiveProxyPort() != 18080 {
		t.Fatalf("EffectiveProxyPort = %d, want 18080 from DeviceClass DriverConfig", got.EffectiveProxyPort())
	}
	if got.Proxy == nil || len(got.Proxy.NoProxy) != 1 || got.Proxy.NoProxy[0] != ".internal.corp" {
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
	if got.Custom["region"] != "us-central1" || got.Custom["env"] != "staging" || got.Custom["tenant"] != "team-a" {
		t.Fatalf("unexpected merged custom params: %+v", got.Custom)
	}
	if string(got.Opaque["vendorFlag"]) != `{"tier": "gold"}` {
		t.Fatalf("unexpected opaque field: %s", string(got.Opaque["vendorFlag"]))
	}
	if got.MaxConnections == nil || *got.MaxConnections != 128 {
		t.Fatalf("maxConnections = %v, want 128", got.MaxConnections)
	}
}

func TestDecodeStandaloneDriverConfigClaim(t *testing.T) {
	configs := []resourceapi.DeviceAllocationConfiguration{
		{
			Source: resourceapi.AllocationConfigSourceClaim,
			DeviceConfiguration: resourceapi.DeviceConfiguration{
				Opaque: &resourceapi.OpaqueDeviceConfiguration{
					Driver: apis.DriverName,
					Parameters: runtime.RawExtension{Raw: []byte(`{
						"apiVersion": "dra.agents.net/v1alpha1",
						"kind": "DriverConfig",
						"adapterMode": "TunSidecar",
						"policyEnforcementPoint": {
							"url": "https://standalone-pep.svc:8443"
						},
						"custom": {"app": "raw-pod"}
					}`)},
				},
			},
		},
	}

	got, err := Decode(configs, apis.DriverName)
	if err != nil {
		t.Fatalf("Decode standalone DriverConfig: %v", err)
	}
	if got.AdapterMode != apis.AdapterModeTunSidecar {
		t.Fatalf("AdapterMode = %q, want TunSidecar", got.AdapterMode)
	}
	if got.PolicyEnforcementPoint == nil || got.PolicyEnforcementPoint.URL != "https://standalone-pep.svc:8443" {
		t.Fatalf("unexpected PEP: %+v", got.PolicyEnforcementPoint)
	}
	if got.Custom["app"] != "raw-pod" {
		t.Fatalf("custom[app] = %q, want raw-pod", got.Custom["app"])
	}
}

func TestDecodeRejectsPrivilegedClaimFieldsAndOrdersClassBeforeClaim(t *testing.T) {
	// 1. Out-of-order configs: FromClaim appears before FromClass, yet FromClass still applies first.
	reversed := []resourceapi.DeviceAllocationConfiguration{
		{
			Source:   resourceapi.AllocationConfigSourceClaim,
			Requests: []string{"agents-net"},
			DeviceConfiguration: resourceapi.DeviceConfiguration{
				Opaque: &resourceapi.OpaqueDeviceConfiguration{
					Driver:     apis.DriverName,
					Parameters: runtime.RawExtension{Raw: []byte(`{"confinementMode":"NetworkPolicyDenyAll","custom":{"k":"from-claim"}}`)},
				},
			},
		},
		{
			Source:   resourceapi.AllocationConfigSourceClass,
			Requests: []string{"agents-net"},
			DeviceConfiguration: resourceapi.DeviceConfiguration{
				Opaque: &resourceapi.OpaqueDeviceConfiguration{
					Driver:     apis.DriverName,
					Parameters: runtime.RawExtension{Raw: []byte(`{"confinementMode":"PodNetworkIsolated","custom":{"k":"from-class","c":"1"}}`)},
				},
			},
		},
		{
			Source:   resourceapi.AllocationConfigSourceClaim,
			Requests: []string{"other-request"},
			DeviceConfiguration: resourceapi.DeviceConfiguration{
				Opaque: &resourceapi.OpaqueDeviceConfiguration{
					Driver:     apis.DriverName,
					Parameters: runtime.RawExtension{Raw: []byte(`{"custom":{"k":"wrong-request"}}`)},
				},
			},
		},
	}
	got, err := DecodeForRequest(reversed, apis.DriverName, "agents-net")
	if err != nil {
		t.Fatalf("DecodeForRequest: %v", err)
	}
	if got.ConfinementMode != apis.ConfinementModeNetworkPolicyDenyAll {
		t.Fatalf("ConfinementMode = %q, want NetworkPolicyDenyAll (claim overlays class)", got.ConfinementMode)
	}
	if got.EffectiveNICBlockMode() != apis.NICBlockModeDropAll {
		t.Fatalf("default EffectiveNICBlockMode() = %q, want DropAll", got.EffectiveNICBlockMode())
	}
	if got.Custom["k"] != "from-claim" || got.Custom["c"] != "1" {
		t.Fatalf("unexpected merged custom: %+v", got.Custom)
	}

	// 1b. FromClass (DeviceClass) MAY set nicBlockMode: Disabled (opt-out) and invalid values fail.
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
	if _, err := Decode([]resourceapi.DeviceAllocationConfiguration{
		{
			Source: resourceapi.AllocationConfigSourceClass,
			DeviceConfiguration: resourceapi.DeviceConfiguration{
				Opaque: &resourceapi.OpaqueDeviceConfiguration{
					Driver:     apis.DriverName,
					Parameters: runtime.RawExtension{Raw: []byte(`{"nicBlockMode":"BogusMode"}`)},
				},
			},
		},
	}, apis.DriverName); err == nil {
		t.Fatal("expected error for invalid nicBlockMode, got nil")
	}

	// 2. FromClaim must reject host-level paths, socket overrides, nicBlockMode, and resource limits.
	rejectedClaims := []struct {
		name string
		raw  string
	}{
		{"caTrust hostPath", `{"caTrust":{"sources":[{"type":"HostPath","hostPath":"/etc/shadow"}]}}`},
		{"pep tls hostPath", `{"policyEnforcementPoint":{"url":"https://pep:8443","tls":{"caCertificateRefs":[{"type":"HostPath","hostPath":"/dev/zero"}]}}}`},
		{"mtls certDir", `{"policyEnforcementPoint":{"url":"https://pep:8443","auth":{"type":"MTLS","mtls":{"certDir":"/etc/kubernetes/pki"}}}}`},
		{"spiffe workloadSocketPath", `{"policyEnforcementPoint":{"url":"https://pep:8443","auth":{"type":"SPIFFE","spiffe":{"workloadSocketPath":"/run/containerd/containerd.sock"}}}}`},
		{"spiffe delegatedSocketPath", `{"policyEnforcementPoint":{"url":"https://pep:8443","auth":{"type":"SPIFFE","spiffe":{"mode":"DelegatedPod","delegatedSocketPath":"/run/spire/admin.sock"}}}}`},
		{"maxConnections override", `{"maxConnections":99999}`},
		{"idleTimeoutSeconds override", `{"idleTimeoutSeconds":99999}`},
		{"nicBlockMode Disabled override", `{"nicBlockMode":"Disabled"}`},
		{"nicBlockMode DropAll override", `{"nicBlockMode":"DropAll"}`},
		{"path traversal podCertVolumeName", `{"podCertVolumeName":"../../etc"}`},
		{"bad noProxy chars", `{"proxy":{"noProxy":["ok.local","bad host"]}}`},
		{"ingress endPort below port", `{"ingressPorts":[{"port":9005,"endPort":9000}]}`},
		{"ingress endPort above 65535", `{"ingressPorts":[{"port":9000,"endPort":70000}]}`},
	}
	for _, tc := range rejectedClaims {
		t.Run(tc.name, func(t *testing.T) {
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
				t.Fatalf("expected error for %s, got nil", tc.name)
			}
		})
	}
}
