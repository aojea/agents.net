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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"io"
	"math/big"
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

func makeBridgeMTLSConfigs(t *testing.T) (serverTLS, clientTLS *tls.Config) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen CA key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-bridge-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)

	issue := func(cn string, isServer bool) tls.Certificate {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		serial, _ := rand.Int(rand.Reader, big.NewInt(1<<60))
		tmpl := &x509.Certificate{
			SerialNumber: serial,
			Subject:      pkix.Name{CommonName: cn},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			DNSNames:     []string{cn},
			IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		}
		if isServer {
			tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		} else {
			tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &k.PublicKey, caKey)
		if err != nil {
			t.Fatalf("create leaf cert: %v", err)
		}
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
	}

	srvCert := issue("dra-agents-net.local", true)
	cliCert := issue("agents-net-ingress-gateway", false)

	serverTLS = &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{srvCert},
		ClientCAs:    caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}
	clientTLS = &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cliCert},
		RootCAs:      caPool,
		ServerName:   "dra-agents-net.local",
	}
	return serverTLS, clientTLS
}

func makeStatusClaim(ns, claimName, podName, podUID, endpoint string, useTLS bool, ready metav1.ConditionStatus, ports []apis.IngressPort) *resourceapi.ResourceClaim {
	devStatus := apis.DeviceStatus{
		APIVersion: apis.DeviceStatusAPIVersion,
		Kind:       apis.DeviceStatusKind,
		NodeName:   "worker-1",
		PodUID:     podUID,
		SandboxID:  "sb-1",
	}
	if len(ports) > 0 && endpoint != "" {
		devStatus.Ingress = &apis.IngressStatus{
			Endpoint:   endpoint,
			Protocol:   apis.IngressTunnelProtocolHTTPConnect,
			Target:     podUID,
			TLS:        useTLS,
			ServerName: "dra-agents-net.local",
			Ports:      ports,
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

func TestGatewayDiscoversFromResourceClaimAndProxiesThroughMTLSBridge(t *testing.T) {
	srvTLS, cliTLS := makeBridgeMTLSConfigs(t)

	// 1. Start a local HTTP server standing in for the isolated Pod's loopback service.
	podApp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(HeaderPod) != "" {
			t.Errorf("routing header %s leaked upstream", HeaderPod)
		}
		_, _ = io.WriteString(w, "pod-reply:"+r.URL.Path)
	}))
	defer podApp.Close()
	podAppAddr := strings.TrimPrefix(podApp.URL, "http://")

	// 2. Start a real mTLS dra-agents-net ingress.Server whose dialNetNS connects to podApp.
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
			IngressPorts: []apis.IngressPort{
				{Port: 8080, Protocol: apis.IngressProtocolTCP},
				{Port: 9000, EndPort: 9005, Protocol: apis.IngressProtocolTCP},
			},
		},
	}); err != nil {
		t.Fatalf("store.Upsert: %v", err)
	}

	bridgeSrv, err := ingress.NewServer(ingress.Config{
		ListenAddr: "127.0.0.1:0",
		Store:      st,
		TLSConfig:  srvTLS,
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

	// 3. Verify NewHandler requires mTLS by default.
	reg := NewRegistry(apis.DriverName)
	if _, err := NewHandler(Config{Registry: reg, AuditWriter: io.Discard}); err == nil {
		t.Fatal("expected NewHandler without TLSConfig to fail closed")
	}

	claim := makeStatusClaim("demo", "web-agent-agents-net", "web-agent", podUID, bridgeAddr.String(), true, metav1.ConditionTrue, []apis.IngressPort{
		{Port: 8080, Protocol: apis.IngressProtocolTCP},
		{Port: 9000, EndPort: 9005, Protocol: apis.IngressProtocolTCP},
	})
	reg.SyncClaim(claim)

	h, err := NewHandler(Config{Registry: reg, TLSConfig: cliTLS, AuditWriter: io.Discard})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	defer h.Close()
	gwSrv := httptest.NewServer(h)
	defer gwSrv.Close()

	// 4. Path-routed request reaches the Pod via mTLS CONNECT <podUID>:8080.
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

	// 5b. Port within an inclusive ingressPort range succeeds.
	resp, err = http.Get(gwSrv.URL + "/agents/demo/web-agent:9003/range-ok")
	if err != nil {
		t.Fatalf("GET range port: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "pod-reply:/range-ok" {
		t.Fatalf("range port = %d %q, want 200 pod-reply:/range-ok", resp.StatusCode, string(body))
	}

	// 6. Unpinned port returns 403 with RFC 9209 Proxy-Status.
	resp, err = http.Get(gwSrv.URL + "/agents/demo/web-agent:9999/secret")
	if err != nil {
		t.Fatalf("GET unpinned port: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(resp.Header.Get("Proxy-Status"), "error=http_request_denied; reason=port-not-permitted") {
		t.Fatalf("unpinned port status = %d Proxy-Status=%q, want 403 port-not-permitted", resp.StatusCode, resp.Header.Get("Proxy-Status"))
	}

	// 6b. Plaintext downgrade attempt (tls: false in ResourceClaim status) MUST be rejected.
	downgraded := makeStatusClaim("demo", "plain-claim", "plain-agent", "22222222-2222-2222-2222-222222222222", bridgeAddr.String(), false, metav1.ConditionTrue, []apis.IngressPort{
		{Port: 8080, Protocol: apis.IngressProtocolTCP},
	})
	reg.SyncClaim(downgraded)
	resp, err = http.Get(gwSrv.URL + "/agents/demo/plain-agent/nope")
	if err != nil {
		t.Fatalf("GET downgraded claim: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway || !strings.Contains(resp.Header.Get("Proxy-Status"), "reason=bridge-tls-required") {
		t.Fatalf("downgraded claim status = %d Proxy-Status=%q, want 502 bridge-tls-required", resp.StatusCode, resp.Header.Get("Proxy-Status"))
	}

	// 7. Revoking Ready=False on the ResourceClaim immediately evicts the route (404 + Proxy-Status).
	revoked := makeStatusClaim("demo", "web-agent-agents-net", "web-agent", podUID, "", true, metav1.ConditionFalse, nil)
	reg.SyncClaim(revoked)

	resp, err = http.Get(gwSrv.URL + "/agents/demo/web-agent/after-revoke")
	if err != nil {
		t.Fatalf("GET after revoke: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound || !strings.Contains(resp.Header.Get("Proxy-Status"), "error=destination_not_found; reason=unknown-sandbox") {
		t.Fatalf("after revoke status = %d Proxy-Status=%q, want 404 unknown-sandbox", resp.StatusCode, resp.Header.Get("Proxy-Status"))
	}
}
