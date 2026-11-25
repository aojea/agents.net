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

package gateway

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	resourceapi "k8s.io/api/resource/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"

	"github.com/aojea/agents.net/kubernetes/pkg/apis"
	"github.com/aojea/agents.net/kubernetes/pkg/ingress"
	"github.com/aojea/agents.net/kubernetes/pkg/params"
	"github.com/aojea/agents.net/kubernetes/pkg/store"
)

func makeStatusClaim(ns, claimName, podName, podUID, endpoint string, ready metav1.ConditionStatus, ports []apis.IngressPort) *resourceapi.ResourceClaim {
	devStatus := apis.DeviceStatus{
		APIVersion: apis.DeviceStatusAPIVersion,
		Kind:       apis.DeviceStatusKind,
		NodeName:   "worker-1",
		PodUID:     podUID,
		SandboxID:  "sb-1",
	}
	if len(ports) > 0 && endpoint != "" {
		devStatus.Ingress = &apis.IngressStatus{
			Endpoint: endpoint,
			Protocol: apis.IngressTunnelProtocolHTTPConnect,
			Target:   podUID,
			Ports:    ports,
		}
	}
	raw, _ := json.Marshal(devStatus)
	return &resourceapi.ResourceClaim{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns,
			Name:      claimName,
		},
		Status: resourceapi.ResourceClaimStatus{
			ReservedFor: []resourceapi.ResourceClaimConsumerReference{
				{
					Resource: "pods",
					Name:     podName,
					UID:      types.UID(podUID),
				},
			},
			Devices: []resourceapi.AllocatedDeviceStatus{
				{
					Driver: apis.DriverName,
					Pool:   "worker-1",
					Device: "agents-net",
					Conditions: []metav1.Condition{
						{Type: "Ready", Status: ready},
					},
					Data: &runtime.RawExtension{Raw: raw},
				},
			},
		},
	}
}

func TestGatewayDiscoversFromResourceClaimAndProxiesThroughIngressBridge(t *testing.T) {
	// 1. Start a local HTTP server standing in for the isolated Pod's loopback service.
	podApp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(HeaderPod) != "" {
			t.Errorf("routing header %s leaked upstream", HeaderPod)
		}
		_, _ = io.WriteString(w, "pod-reply:"+r.URL.Path)
	}))
	defer podApp.Close()
	podAppAddr := strings.TrimPrefix(podApp.URL, "http://")

	// 2. Start a real dra-agents-net ingress.Server whose dialNetNS connects to podApp.
	st, err := store.New(nil)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	const podUID = "11111111-1111-1111-1111-111111111111"
	if err := st.Upsert(store.PodConfig{
		PodUID:       podUID,
		PodName:      "web-agent",
		PodNamespace: "demo",
		NetNS:        "/proc/self/ns/net",
		Parameters: params.NetworkParameters{
			IngressPorts: []apis.IngressPort{{Port: 8080, Protocol: apis.IngressProtocolTCP}},
		},
	}); err != nil {
		t.Fatalf("store.Upsert: %v", err)
	}

	bridgeSrv, err := ingress.NewServer(ingress.Config{
		ListenAddr: "127.0.0.1:0",
		Store:      st,
		DialNetNS: func(_, _, _ string, timeout time.Duration) (net.Conn, error) {
			return net.DialTimeout("tcp", podAppAddr, timeout)
		},
	})
	if err != nil {
		t.Fatalf("ingress.NewServer: %v", err)
	}
	bridgeAddr, err := bridgeSrv.Start()
	if err != nil {
		t.Fatalf("bridgeSrv.Start: %v", err)
	}
	defer func() { _ = bridgeSrv.Close() }()

	// 3. Populate Registry from a ResourceClaim carrying Option 3 DeviceStatus.Ingress.
	reg := NewRegistry(apis.DriverName)
	claim := makeStatusClaim("demo", "web-agent-agents-net", "web-agent", podUID, bridgeAddr.String(), metav1.ConditionTrue, []apis.IngressPort{
		{Port: 8080, Protocol: apis.IngressProtocolTCP},
	})
	reg.SyncClaim(claim)

	h, err := NewHandler(Config{Registry: reg, AuditWriter: io.Discard})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	gwSrv := httptest.NewServer(h)
	defer gwSrv.Close()

	// 4. Path-routed request reaches the Pod via CONNECT <podUID>:8080.
	resp, err := http.Get(gwSrv.URL + "/agents/demo/web-agent/hello/world")
	if err != nil {
		t.Fatalf("GET path route: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "pod-reply:/hello/world" {
		t.Fatalf("path route = %d %q, want 200 pod-reply:/hello/world", resp.StatusCode, string(body))
	}

	// 5. Header-routed request reaches the Pod without leaking X-Agents-Net-* headers.
	req, _ := http.NewRequest(http.MethodGet, gwSrv.URL+"/from-headers", nil)
	req.Header.Set(HeaderNamespace, "demo")
	req.Header.Set(HeaderPod, "web-agent")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET header route: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "pod-reply:/from-headers" {
		t.Fatalf("header route = %d %q, want 200 pod-reply:/from-headers", resp.StatusCode, string(body))
	}

	// 6. Unpinned port returns 403 port-not-permitted.
	resp, err = http.Get(gwSrv.URL + "/agents/demo/web-agent:9999/secret")
	if err != nil {
		t.Fatalf("GET unpinned port: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("unpinned port status = %d, want 403", resp.StatusCode)
	}

	// 7. Revoking Ready=False on the ResourceClaim immediately evicts the route (404).
	revoked := makeStatusClaim("demo", "web-agent-agents-net", "web-agent", podUID, "", metav1.ConditionFalse, nil)
	reg.SyncClaim(revoked)

	resp, err = http.Get(gwSrv.URL + "/agents/demo/web-agent/after-revoke")
	if err != nil {
		t.Fatalf("GET after revoke: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("after revoke status = %d, want 404", resp.StatusCode)
	}
}
