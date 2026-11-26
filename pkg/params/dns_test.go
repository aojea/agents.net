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
	k8sruntime "k8s.io/apimachinery/pkg/runtime"

	"github.com/aojea/agents.net/pkg/apis"
)

func TestDNSConfigDecodingAndTrustBoundary(t *testing.T) {
	// 1. Valid unified DoH mode from DeviceClass.
	cfgs := []resourceapi.DeviceAllocationConfiguration{
		{
			Source: resourceapi.AllocationConfigSourceClass,
			DeviceConfiguration: resourceapi.DeviceConfiguration{
				Opaque: &resourceapi.OpaqueDeviceConfiguration{
					Driver: apis.DriverName,
					Parameters: k8sruntime.RawExtension{
						Raw: []byte(`{
							"apiVersion": "dra.agents.net/v1alpha1",
							"kind": "DriverConfig",
							"dns": {
								"mode": "DoH",
								"clusterDomain": "corp.local"
							}
						}`),
					},
				},
			},
		},
	}
	got, err := Decode(cfgs, apis.DriverName)
	if err != nil {
		t.Fatalf("Decode valid DoH class config: %v", err)
	}
	if got.EffectiveDNSMode() != apis.DNSModeDoH {
		t.Fatalf("EffectiveDNSMode = %q, want DoH", got.EffectiveDNSMode())
	}
	if got.EffectiveClusterDomain() != "corp.local" {
		t.Fatalf("EffectiveClusterDomain = %q, want corp.local", got.EffectiveClusterDomain())
	}
	if !got.EffectivePreserveSearchDomains() {
		t.Fatal("EffectivePreserveSearchDomains = false, want default true")
	}

	// 2. ResourceClaim (FromClaim) MUST NOT override dns configuration.
	claimAttempt := append(cfgs, resourceapi.DeviceAllocationConfiguration{
		Source: resourceapi.AllocationConfigSourceClaim,
		DeviceConfiguration: resourceapi.DeviceConfiguration{
			Opaque: &resourceapi.OpaqueDeviceConfiguration{
				Driver: apis.DriverName,
				Parameters: k8sruntime.RawExtension{
					Raw: []byte(`{"dns": {"mode": "Synthetic"}}`),
				},
			},
		},
	})
	if _, err := Decode(claimAttempt, apis.DriverName); err == nil {
		t.Fatal("expected ResourceClaim dns override to be rejected")
	}

	// 3. Separate dns.enforcementPoint enforces mandatory mTLS for https://.
	noAuthDNS := []resourceapi.DeviceAllocationConfiguration{
		{
			Source: resourceapi.AllocationConfigSourceClass,
			DeviceConfiguration: resourceapi.DeviceConfiguration{
				Opaque: &resourceapi.OpaqueDeviceConfiguration{
					Driver: apis.DriverName,
					Parameters: k8sruntime.RawExtension{
						Raw: []byte(`{
							"dns": {
								"mode": "DoH",
								"enforcementPoint": {
									"url": "https://dns-pep.system.svc:8443"
								}
							}
						}`),
					},
				},
			},
		},
	}
	if _, err := Decode(noAuthDNS, apis.DriverName); err == nil {
		t.Fatal("expected https:// dns.enforcementPoint without auth to fail validation")
	}

	// 4. Invalid dns.mode rejected.
	badMode := []resourceapi.DeviceAllocationConfiguration{
		{
			Source: resourceapi.AllocationConfigSourceClass,
			DeviceConfiguration: resourceapi.DeviceConfiguration{
				Opaque: &resourceapi.OpaqueDeviceConfiguration{
					Driver: apis.DriverName,
					Parameters: k8sruntime.RawExtension{
						Raw: []byte(`{"dns": {"mode": "InvalidMode"}}`),
					},
				},
			},
		},
	}
	if _, err := Decode(badMode, apis.DriverName); err == nil {
		t.Fatal("expected invalid dns.mode to fail validation")
	}
}
