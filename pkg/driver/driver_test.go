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

package driver

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	nriapi "github.com/containerd/nri/pkg/api"
	corev1 "k8s.io/api/core/v1"
	resourceapi "k8s.io/api/resource/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/dynamic-resource-allocation/kubeletplugin"

	"github.com/aojea/agents.net/pkg/apis"
	"github.com/aojea/agents.net/pkg/auth"
	"github.com/aojea/agents.net/pkg/catrust"
	"github.com/aojea/agents.net/pkg/params"
	"github.com/aojea/agents.net/pkg/store"
	"github.com/aojea/agents.net/pkg/tunnel"
)

type fakeNetNS struct {
	verifiedPaths      []string
	flushedPaths       []string
	blockedPaths       []string
	listenedAddrs      []string
	hostTunPaths       []string
	hostTunPreserveNIC []bool
	hostTunCleaned     []string
	hostTunClosed      int
	verifyErr          error
	flushErr           error
	blockErr           error
	hasRoutes          bool
	hasRoutesErr       error
	nicsUnblocked      bool
	nicsCheckErr       error
	listenErr          error
	hostTunErr         error
}

type fakeCloser struct {
	onClose func()
}

func (f fakeCloser) Close() error {
	if f.onClose != nil {
		f.onClose()
	}
	return nil
}

func (f *fakeNetNS) VerifyLoopbackOnly(path string, _ bool) error {
	f.verifiedPaths = append(f.verifiedPaths, path)
	return f.verifyErr
}

func (f *fakeNetNS) FlushNonLoopbackRoutes(path string) error {
	f.flushedPaths = append(f.flushedPaths, path)
	return f.flushErr
}

func (f *fakeNetNS) HasNonLoopbackRoutes(_ string) (bool, error) {
	return f.hasRoutes, f.hasRoutesErr
}

func (f *fakeNetNS) BlockNonLoopbackNICs(path string, _ bool) error {
	f.blockedPaths = append(f.blockedPaths, path)
	return f.blockErr
}

func (f *fakeNetNS) VerifyNonLoopbackNICsBlocked(_ string, _ bool) (bool, error) {
	return !f.nicsUnblocked, f.nicsCheckErr
}

func (f *fakeNetNS) ListenAt(path, network, address string) (net.Listener, error) {
	f.listenedAddrs = append(f.listenedAddrs, path+"@"+address)
	if f.listenErr != nil {
		return nil, f.listenErr
	}
	// Bind an ephemeral host loopback listener in offline unit tests.
	return net.Listen(network, "127.0.0.1:0")
}

func (f *fakeNetNS) StartHostTun(req HostTunRequest) (io.Closer, error) {
	f.hostTunPaths = append(f.hostTunPaths, req.NetNSPath)
	f.hostTunPreserveNIC = append(f.hostTunPreserveNIC, req.PreserveNICReturn)
	if f.hostTunErr != nil {
		return nil, f.hostTunErr
	}
	return fakeCloser{onClose: func() { f.hostTunClosed++ }}, nil
}

func (f *fakeNetNS) CleanupHostTun(path string) error {
	f.hostTunCleaned = append(f.hostTunCleaned, path)
	return nil
}

func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "anet-")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func writeTestCAPEM(t *testing.T, path, cn string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatalf("write CA cert: %v", err)
	}
}

func makeTestClaim(podUID, claimUID types.UID, p params.NetworkParameters) *resourceapi.ResourceClaim {
	raw, _ := json.Marshal(p)
	return &resourceapi.ResourceClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "claim-1",
			Namespace: "agents",
			UID:       claimUID,
		},
		Status: resourceapi.ResourceClaimStatus{
			ReservedFor: []resourceapi.ResourceClaimConsumerReference{
				{Resource: "pods", Name: "sb-1", UID: podUID},
			},
			Allocation: &resourceapi.AllocationResult{
				Devices: resourceapi.DeviceAllocationResult{
					Results: []resourceapi.DeviceRequestAllocationResult{
						{
							Request: apis.PodClaimName,
							Driver:  apis.DriverName,
							Pool:    "worker-1",
							Device:  DefaultDeviceName,
							ShareID: new(types.UID("11111111-1111-1111-1111-111111111111")),
						},
					},
					Config: []resourceapi.DeviceAllocationConfiguration{
						{
							Source: resourceapi.AllocationConfigSourceClass,
							DeviceConfiguration: resourceapi.DeviceConfiguration{
								Opaque: &resourceapi.OpaqueDeviceConfiguration{
									Driver:     apis.DriverName,
									Parameters: runtime.RawExtension{Raw: raw},
								},
							},
						},
					},
				},
			},
		},
	}
}

func envMap(kvList []*nriapi.KeyValue) map[string]string {
	out := make(map[string]string, len(kvList))
	for _, kv := range kvList {
		out[kv.Key] = kv.Value
	}
	return out
}

func TestBuildResourceSliceConsumableCapacityAndHealth(t *testing.T) {
	ctx := t.Context()
	st, _ := store.New(nil)
	tm, _ := tunnel.NewManager(shortTempDir(t), nil, tunnel.WithAuditWriter(io.Discard))
	defer tm.Close()

	// Auto-detect consumable sandbox capacity from Node.Status.Allocatable.Pods() (> 128
	// to verify DRAConsumableCapacity still fits in a single ResourceSlice with 1 device).
	fakeClient := fake.NewClientset(&corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "worker-1"},
		Status: corev1.NodeStatus{
			Addresses: []corev1.NodeAddress{
				{Type: corev1.NodeInternalIP, Address: "10.0.0.42"},
			},
			Allocatable: corev1.ResourceList{
				corev1.ResourcePods: resource.MustParse("200"),
			},
		},
	})

	drv, err := New(Config{
		NodeName:   "worker-1",
		KubeClient: fakeClient,
		Store:      st,
		Tunnel:     tm,
		NetNS:      &fakeNetNS{},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	drv.resolveNodeInfo(ctx)
	if drv.nodeIP != "10.0.0.42" {
		t.Fatalf("resolved nodeIP = %q, want 10.0.0.42", drv.nodeIP)
	}

	res := drv.BuildResourceSlice()
	pool := res.Pools["worker-1"]
	if len(pool.Slices) != 1 {
		t.Fatalf("expected 1 ResourceSlice for DRAConsumableCapacity, got %d", len(pool.Slices))
	}
	if len(pool.Slices[0].Devices) != 1 {
		t.Fatalf("slice[0] devices = %d, want 1", len(pool.Slices[0].Devices))
	}

	dev := pool.Slices[0].Devices[0]
	if dev.Name != DefaultDeviceName {
		t.Fatalf("device name = %q, want %q", dev.Name, DefaultDeviceName)
	}
	if dev.AllowMultipleAllocations == nil || !*dev.AllowMultipleAllocations {
		t.Fatalf("expected AllowMultipleAllocations=true, got %+v", dev.AllowMultipleAllocations)
	}
	capEntry, ok := dev.Capacity[CapacitySandboxes]
	if !ok {
		t.Fatalf("expected %q capacity on device, got %+v", CapacitySandboxes, dev.Capacity)
	}
	if got := capEntry.Value.Value(); got != 200 {
		t.Fatalf("sandboxes capacity = %d, want 200", got)
	}
	if capEntry.RequestPolicy == nil || capEntry.RequestPolicy.Default == nil || capEntry.RequestPolicy.Default.Value() != 1 {
		t.Fatalf("expected RequestPolicy.Default=1, got %+v", capEntry.RequestPolicy)
	}
	if len(capEntry.RequestPolicy.ValidValues) != 1 || capEntry.RequestPolicy.ValidValues[0].Value() != 1 {
		t.Fatalf("expected RequestPolicy.ValidValues=[1], got %+v", capEntry.RequestPolicy.ValidValues)
	}
	if len(dev.Taints) != 0 {
		t.Fatalf("expected no DRADeviceTaints, got %+v", dev.Taints)
	}

	// Marking unhealthy withdraws the slice cleanly without DRADeviceTaints.
	if err := drv.SetHealthy(ctx, false); err != nil {
		t.Fatalf("SetHealthy(false): %v", err)
	}
	if got := len(drv.BuildResourceSlice().Pools["worker-1"].Slices); got != 0 {
		t.Fatalf("expected 0 slices when unhealthy, got %d", got)
	}
}

func TestReportResourceClaimDeviceStatusPropagatesShareID(t *testing.T) {
	ctx := t.Context()
	st, _ := store.New(nil)
	tm, _ := tunnel.NewManager(shortTempDir(t), nil, tunnel.WithAuditWriter(io.Discard))
	defer tm.Close()

	shareID := types.UID("22222222-2222-2222-2222-222222222222")
	claim := makeTestClaim("pod-uid-share", "claim-uid-share", params.NetworkParameters{
		ConfinementMode: apis.ConfinementModePodNetworkIsolated,
		AdapterMode:     apis.AdapterModeExplicitProxy,
	})
	claim.Status.Allocation.Devices.Results[0].ShareID = &shareID

	fakeClient := fake.NewClientset(claim)
	drv, err := New(Config{
		NodeName:          "worker-1",
		KubeClient:        fakeClient,
		Store:             st,
		Tunnel:            tm,
		NetNS:             &fakeNetNS{},
		IngressBridgeAddr: ":15080",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	drv.nriConnected.Store(true)

	results, err := drv.PrepareResourceClaims(ctx, []*resourceapi.ResourceClaim{claim})
	if err != nil {
		t.Fatalf("PrepareResourceClaims: %v", err)
	}
	if res := results[claim.UID]; res.Err != nil {
		t.Fatalf("prepare result err: %v", res.Err)
	}
	if err := drv.RunPodSandbox(ctx, &nriapi.PodSandbox{
		Id:        "sandbox-share",
		Uid:       "pod-uid-share",
		Name:      "sb-1",
		Namespace: "agents",
		Linux: &nriapi.LinuxPodSandbox{
			Namespaces: []*nriapi.LinuxNamespace{{Type: "network", Path: "/proc/self/ns/net"}},
		},
	}); err != nil {
		t.Fatalf("RunPodSandbox: %v", err)
	}
	drv.statusWG.Wait()

	updated, err := fakeClient.ResourceV1().ResourceClaims(claim.Namespace).Get(ctx, claim.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get updated ResourceClaim: %v", err)
	}
	if len(updated.Status.Devices) != 1 {
		t.Fatalf("expected 1 AllocatedDeviceStatus, got %d", len(updated.Status.Devices))
	}
	got := updated.Status.Devices[0]
	if got.Device != DefaultDeviceName || got.ShareID == nil || *got.ShareID != string(shareID) {
		t.Fatalf("unexpected AllocatedDeviceStatus: device=%q shareID=%v (want %q / %q)", got.Device, got.ShareID, DefaultDeviceName, shareID)
	}
	if got.NetworkData != nil {
		t.Fatalf("expected nil NetworkData, got %+v", got.NetworkData)
	}
	if got.Data == nil || len(got.Data.Raw) == 0 {
		t.Fatalf("expected structured DeviceStatus in AllocatedDeviceStatus.Data")
	}
	var devStatus apis.DeviceStatus
	if err := json.Unmarshal(got.Data.Raw, &devStatus); err != nil {
		t.Fatalf("unmarshal DeviceStatus: %v", err)
	}
	if devStatus.APIVersion != apis.DeviceStatusAPIVersion || devStatus.Kind != apis.DeviceStatusKind {
		t.Fatalf("unexpected DeviceStatus type meta: %+v", devStatus)
	}
	if devStatus.NodeName != "worker-1" || devStatus.PodUID != "pod-uid-share" || devStatus.SandboxID != "sandbox-share" {
		t.Fatalf("unexpected DeviceStatus identity: %+v", devStatus)
	}
	if devStatus.Ingress != nil {
		t.Fatalf("egress-only claim must not publish IngressStatus, got %+v", devStatus.Ingress)
	}
}

func TestReportResourceClaimIngressDiscoveryAndRevocation(t *testing.T) {
	ctx := t.Context()
	st, _ := store.New(nil)
	tm, _ := tunnel.NewManager(shortTempDir(t), nil, tunnel.WithAuditWriter(io.Discard))
	defer tm.Close()

	shareID := types.UID("33333333-3333-3333-3333-333333333333")
	claim := makeTestClaim("pod-uid-ingress", "claim-uid-ingress", params.NetworkParameters{
		ConfinementMode: apis.ConfinementModePodNetworkIsolated,
		AdapterMode:     apis.AdapterModeExplicitProxy,
		IngressPorts: []apis.IngressPort{
			{Port: 8080},
			{Port: 9000, EndPort: 9005, Protocol: apis.IngressProtocolTCP},
		},
	})
	claim.Status.Allocation.Devices.Results[0].ShareID = &shareID

	fakeClient := fake.NewClientset(
		claim,
		&corev1.Node{
			ObjectMeta: metav1.ObjectMeta{Name: "worker-2"},
			Status: corev1.NodeStatus{
				Addresses: []corev1.NodeAddress{
					{Type: corev1.NodeInternalIP, Address: "192.168.8.10"},
				},
			},
		},
	)
	drv, err := New(Config{
		NodeName:          "worker-2",
		KubeClient:        fakeClient,
		Store:             st,
		Tunnel:            tm,
		NetNS:             &fakeNetNS{},
		IngressBridgeAddr: ":15080",
		IngressTLS:        true,
		IngressServerName: "dra-agents-net.kube-system.svc",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	drv.resolveNodeInfo(ctx)
	drv.nriConnected.Store(true)

	results, err := drv.PrepareResourceClaims(ctx, []*resourceapi.ResourceClaim{claim})
	if err != nil || results[claim.UID].Err != nil {
		t.Fatalf("PrepareResourceClaims: err=%v res=%v", err, results[claim.UID].Err)
	}
	podSandbox := &nriapi.PodSandbox{
		Id:        "sandbox-ingress-1",
		Uid:       "pod-uid-ingress",
		Name:      "web-agent",
		Namespace: "agents",
		Linux: &nriapi.LinuxPodSandbox{
			Namespaces: []*nriapi.LinuxNamespace{{Type: "network", Path: "/proc/self/ns/net"}},
		},
	}
	if err := drv.RunPodSandbox(ctx, podSandbox); err != nil {
		t.Fatalf("RunPodSandbox: %v", err)
	}
	drv.statusWG.Wait()

	// CreateContainer must advertise AGENT_INGRESS_PORT per agents.net ingress.md §1.
	adj, _, err := drv.CreateContainer(ctx, podSandbox, &nriapi.Container{Name: "agent"})
	if err != nil {
		t.Fatalf("CreateContainer: %v", err)
	}
	if gotPort := envMap(adj.Env)["AGENT_INGRESS_PORT"]; gotPort != "8080" {
		t.Fatalf("AGENT_INGRESS_PORT = %q, want 8080", gotPort)
	}

	// ResourceClaim.status.devices[0].data must publish typed IngressStatus with routable nodeIP:port.
	updated, err := fakeClient.ResourceV1().ResourceClaims(claim.Namespace).Get(ctx, claim.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get ResourceClaim: %v", err)
	}
	if len(updated.Status.Devices) != 1 || updated.Status.Devices[0].Data == nil {
		t.Fatalf("expected 1 AllocatedDeviceStatus with Data, got %+v", updated.Status.Devices)
	}
	if updated.Status.Devices[0].Conditions[0].Status != metav1.ConditionTrue {
		t.Fatalf("expected Ready=True, got %+v", updated.Status.Devices[0].Conditions)
	}
	var devStatus apis.DeviceStatus
	if err := json.Unmarshal(updated.Status.Devices[0].Data.Raw, &devStatus); err != nil {
		t.Fatalf("unmarshal DeviceStatus: %v", err)
	}
	if devStatus.Ingress == nil {
		t.Fatalf("expected non-nil IngressStatus, got %+v", devStatus)
	}
	if devStatus.Ingress.Endpoint != "192.168.8.10:15080" {
		t.Fatalf("ingress.endpoint = %q, want 192.168.8.10:15080", devStatus.Ingress.Endpoint)
	}
	if devStatus.Ingress.Protocol != apis.IngressTunnelProtocolHTTPConnect {
		t.Fatalf("ingress.protocol = %q, want %q", devStatus.Ingress.Protocol, apis.IngressTunnelProtocolHTTPConnect)
	}
	if devStatus.Ingress.Target != "pod-uid-ingress" {
		t.Fatalf("ingress.target = %q, want pod-uid-ingress", devStatus.Ingress.Target)
	}
	if !devStatus.Ingress.TLS || devStatus.Ingress.ServerName != "dra-agents-net.kube-system.svc" {
		t.Fatalf("unexpected TLS metadata: %+v", devStatus.Ingress)
	}
	if len(devStatus.Ingress.Ports) != 2 ||
		devStatus.Ingress.Ports[0].Port != 8080 || devStatus.Ingress.Ports[0].Protocol != apis.IngressProtocolTCP ||
		devStatus.Ingress.Ports[1].Port != 9000 || devStatus.Ingress.Ports[1].EndPort != 9005 {
		t.Fatalf("unexpected ingress ports: %+v", devStatus.Ingress.Ports)
	}
	if formatted := formatIngressPorts(devStatus.Ingress.Ports); formatted != "8080,9000-9005" {
		t.Fatalf("formatIngressPorts = %q, want 8080,9000-9005", formatted)
	}

	// StopPodSandbox must revoke IngressStatus and mark Ready=False.
	if err := drv.StopPodSandbox(ctx, podSandbox); err != nil {
		t.Fatalf("StopPodSandbox: %v", err)
	}
	drv.statusWG.Wait()

	revoked, err := fakeClient.ResourceV1().ResourceClaims(claim.Namespace).Get(ctx, claim.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get revoked ResourceClaim: %v", err)
	}
	if revoked.Status.Devices[0].Conditions[0].Status != metav1.ConditionFalse || revoked.Status.Devices[0].Conditions[0].Reason != "AgentsNetRevoked" {
		t.Fatalf("expected Ready=False AgentsNetRevoked, got %+v", revoked.Status.Devices[0].Conditions)
	}
	var revokedStatus apis.DeviceStatus
	if err := json.Unmarshal(revoked.Status.Devices[0].Data.Raw, &revokedStatus); err != nil {
		t.Fatalf("unmarshal revoked DeviceStatus: %v", err)
	}
	if revokedStatus.Ingress != nil {
		t.Fatalf("expected nil IngressStatus after StopPodSandbox, got %+v", revokedStatus.Ingress)
	}
}

func TestPrepareRunCreateStopRemoveCATrustAndPodSync(t *testing.T) {
	ctx := t.Context()
	tmp := shortTempDir(t)
	sysCAPath := filepath.Join(tmp, "sys-ca.pem")
	customCAPath := filepath.Join(tmp, "custom-ca.pem")
	writeTestCAPEM(t, sysCAPath, "sys-root")
	writeTestCAPEM(t, customCAPath, "corp-proxy-ca")

	st, _ := store.New(nil)
	tm, err := tunnel.NewManager(filepath.Join(tmp, "s"), auth.NewResolver(auth.ResolverConfig{KubeletRootDir: tmp}), tunnel.WithAuditWriter(io.Discard))
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	defer tm.Close()

	netns := &fakeNetNS{}
	drv, err := New(Config{
		NodeName:       "worker-1",
		Store:          st,
		Tunnel:         tm,
		CAMaterializer: catrust.NewMaterializer(nil, sysCAPath),
		NetNS:          netns,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	drv.nriConnected.Store(true)

	podUID := types.UID("pod-uid-abc")
	claimUID := types.UID("claim-uid-abc")
	claim := makeTestClaim(podUID, claimUID, params.NetworkParameters{
		ConfinementMode: apis.ConfinementModePodNetworkIsolated,
		AdapterMode:     apis.AdapterModeTunSidecar,
		CATrust: &apis.CATrustConfig{
			Mode:       apis.CATrustModeInjectEnv,
			BundleMode: apis.CABundleModeAppendSystemRoots,
			Sources: []apis.CASource{
				{Type: apis.CASourceTypeHostPath, HostPath: customCAPath},
			},
		},
		IngressPorts: []apis.IngressPort{{Port: 8080}},
		PolicyEnforcementPoint: &apis.PolicyEnforcementPointConfig{
			URL: "unix:///run/pep/egress.sock",
		},
		Custom: map[string]string{"tenant": "team-a"},
	})

	// 1. DRA PrepareResourceClaims returns zero CDI devices, opens egress.sock, and materializes Pod CAs.
	prepRes, err := drv.PrepareResourceClaims(ctx, []*resourceapi.ResourceClaim{claim})
	if err != nil {
		t.Fatalf("PrepareResourceClaims: %v", err)
	}
	if res := prepRes[claimUID]; res.Err != nil || len(res.Devices) != 0 {
		t.Fatalf("PrepareResult = %+v, want Err=nil and 0 CDI devices", res)
	}

	// 2. NRI RunPodSandbox verifies loopback-only netns before any container starts.
	pod := &nriapi.PodSandbox{
		Uid:       string(podUID),
		Name:      "sb-1",
		Namespace: "agents",
		Linux: &nriapi.LinuxPodSandbox{
			Namespaces: []*nriapi.LinuxNamespace{{Type: "network", Path: "/var/run/netns/sb-1"}},
		},
	}
	if err := drv.RunPodSandbox(ctx, pod); err != nil {
		t.Fatalf("RunPodSandbox: %v", err)
	}
	if len(netns.verifiedPaths) != 1 || netns.verifiedPaths[0] != "/var/run/netns/sb-1" {
		t.Fatalf("expected VerifyLoopbackOnly called once, got %v", netns.verifiedPaths)
	}

	// 3. NRI CreateContainer injects /dev/net/tun + egress/ingress sockets ONLY on tun2connect.
	adjSidecar, _, err := drv.CreateContainer(ctx, pod, &nriapi.Container{Name: Tun2ConnectContainerName})
	if err != nil || adjSidecar == nil {
		t.Fatalf("CreateContainer sidecar: adj=%v err=%v", adjSidecar, err)
	}
	if len(adjSidecar.Linux.Devices) != 1 || adjSidecar.Linux.Devices[0].Path != "/dev/net/tun" {
		t.Fatalf("expected /dev/net/tun on sidecar, got %+v", adjSidecar.Linux.Devices)
	}
	// Sidecar mounts: egress, ingress, merged CA, extra CA = 4.
	if len(adjSidecar.Mounts) != 4 {
		t.Fatalf("expected 4 mounts on sidecar, got %d", len(adjSidecar.Mounts))
	}

	// Workload container gets CA mounts + agents.net/language CA env vars only — zero /dev/net/tun, zero egress.sock!
	adjAgent, _, err := drv.CreateContainer(ctx, pod, &nriapi.Container{Name: "agent"})
	if err != nil || adjAgent == nil {
		t.Fatalf("CreateContainer agent: adj=%v err=%v", adjAgent, err)
	}
	if adjAgent.Linux != nil && len(adjAgent.Linux.Devices) > 0 {
		t.Fatalf("agent container must NOT receive /dev/net/tun, got %+v", adjAgent.Linux.Devices)
	}
	if len(adjAgent.Mounts) != 2 || adjAgent.Mounts[0].Destination != catrust.ContainerCABundlePath || adjAgent.Mounts[1].Destination != catrust.ContainerExtraCAPath {
		t.Fatalf("agent container mounts = %+v, want merged + extra CA bundles only", adjAgent.Mounts)
	}
	agentEnv := envMap(adjAgent.Env)
	if agentEnv["AGENT_CA_CERT"] != catrust.ContainerCABundlePath || agentEnv["NODE_EXTRA_CA_CERTS"] != catrust.ContainerExtraCAPath || agentEnv["REQUESTS_CA_BUNDLE"] != catrust.ContainerCABundlePath {
		t.Fatalf("missing expected CA trust env vars: %+v", agentEnv)
	}

	// 4. SyncPod captures attested ServiceAccount metadata from the Pod informer.
	drv.SyncPod(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "sb-1",
			Namespace: "agents",
			UID:       podUID,
		},
		Spec: corev1.PodSpec{ServiceAccountName: "agent-sa"},
	})
	updatedCfg, ok := st.Get(podUID)
	if !ok || updatedCfg.ServiceAccount != "agent-sa" {
		t.Fatalf("SyncPod did not update identity: %+v", updatedCfg)
	}

	// 5. StopPodSandbox + RemovePodSandbox + UnprepareResourceClaims clean up cleanly.
	if err := drv.StopPodSandbox(ctx, pod); err != nil {
		t.Fatalf("StopPodSandbox: %v", err)
	}
	if err := drv.RemovePodSandbox(ctx, pod); err != nil {
		t.Fatalf("RemovePodSandbox: %v", err)
	}
	unprep, err := drv.UnprepareResourceClaims(ctx, []kubeletplugin.NamespacedObject{
		{NamespacedName: types.NamespacedName{Namespace: "agents", Name: "claim-1"}, UID: claimUID},
	})
	if err != nil || unprep[claimUID] != nil {
		t.Fatalf("UnprepareResourceClaims: err=%v res=%+v", err, unprep)
	}
}

func TestExplicitProxySocketAtAndMagicLanguageEnvVars(t *testing.T) {
	ctx := t.Context()
	st, _ := store.New(nil)
	tm, err := tunnel.NewManager(shortTempDir(t), nil, tunnel.WithAuditWriter(io.Discard))
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	defer tm.Close()

	netns := &fakeNetNS{}
	drv, err := New(Config{NodeName: "worker-1", Store: st, Tunnel: tm, NetNS: netns})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	drv.nriConnected.Store(true)

	podUID := types.UID("pod-compat")
	claimUID := types.UID("claim-compat")
	claim := makeTestClaim(podUID, claimUID, params.NetworkParameters{
		ConfinementMode: apis.ConfinementModeNetworkPolicyDenyAll,
		AdapterMode:     apis.AdapterModeExplicitProxy,
		Proxy: &apis.ExplicitProxyConfig{
			Port:    new(int32(18080)),
			NoProxy: []string{".internal.corp"},
		},
	})
	prepRes, err := drv.PrepareResourceClaims(ctx, []*resourceapi.ResourceClaim{claim})
	if err != nil || prepRes[claimUID].Err != nil {
		t.Fatalf("PrepareResourceClaims: err=%v res=%+v", err, prepRes[claimUID])
	}

	// HostNetwork pod (no network namespace path) must be rejected.
	if err := drv.RunPodSandbox(ctx, &nriapi.PodSandbox{Uid: string(podUID), Name: "sb", Namespace: "agents"}); err == nil {
		t.Fatalf("expected error for hostNetwork pod")
	}

	pod := &nriapi.PodSandbox{
		Uid:       string(podUID),
		Name:      "sb",
		Namespace: "agents",
		Linux:     &nriapi.LinuxPodSandbox{Namespaces: []*nriapi.LinuxNamespace{{Type: "network", Path: "/var/run/netns/compat"}}},
	}
	if err := drv.RunPodSandbox(ctx, pod); err != nil {
		t.Fatalf("RunPodSandbox compat: %v", err)
	}
	if len(netns.flushedPaths) != 1 || netns.flushedPaths[0] != "/var/run/netns/compat" {
		t.Fatalf("expected FlushNonLoopbackRoutes called once, got %v", netns.flushedPaths)
	}
	if len(netns.blockedPaths) != 1 || netns.blockedPaths[0] != "/var/run/netns/compat" {
		t.Fatalf("expected BlockNonLoopbackNICs called once by default (DropAll), got %v", netns.blockedPaths)
	}
	if len(netns.listenedAddrs) != 1 || netns.listenedAddrs[0] != "/var/run/netns/compat@127.0.0.1:18080" {
		t.Fatalf("expected socketat ListenAt on 127.0.0.1:18080, got %v", netns.listenedAddrs)
	}

	// Verify nicBlockMode=Disabled (DeviceClass opt-out) skips both FlushNonLoopbackRoutes
	// and BlockNonLoopbackNICs so CNI NetworkPolicy and kubelet probes keep working.
	podUIDOptOut := types.UID("pod-nic-disabled")
	claimUIDOptOut := types.UID("claim-nic-disabled")
	claimOptOut := makeTestClaim(podUIDOptOut, claimUIDOptOut, params.NetworkParameters{
		ConfinementMode: apis.ConfinementModeNetworkPolicyDenyAll,
		NICBlockMode:    apis.NICBlockModeDisabled,
		AdapterMode:     apis.AdapterModeExplicitProxy,
	})
	if res, err := drv.PrepareResourceClaims(ctx, []*resourceapi.ResourceClaim{claimOptOut}); err != nil || res[claimUIDOptOut].Err != nil {
		t.Fatalf("PrepareResourceClaims opt-out: err=%v res=%+v", err, res[claimUIDOptOut])
	}
	if err := drv.RunPodSandbox(ctx, &nriapi.PodSandbox{
		Uid:       string(podUIDOptOut),
		Name:      "sb-optout",
		Namespace: "agents",
		Linux:     &nriapi.LinuxPodSandbox{Namespaces: []*nriapi.LinuxNamespace{{Type: "network", Path: "/var/run/netns/optout"}}},
	}); err != nil {
		t.Fatalf("RunPodSandbox opt-out: %v", err)
	}
	if len(netns.flushedPaths) != 1 || len(netns.blockedPaths) != 1 {
		t.Fatalf("expected FlushNonLoopbackRoutes and BlockNonLoopbackNICs skipped when nicBlockMode=Disabled, got flushed=%v blocked=%v", netns.flushedPaths, netns.blockedPaths)
	}

	// Verify BlockNonLoopbackNICs failure fails closed under default DropAll.
	netns.blockErr = errors.New("tc clsact unavailable")
	podUIDFail := types.UID("pod-nic-fail")
	claimUIDFail := types.UID("claim-nic-fail")
	claimFail := makeTestClaim(podUIDFail, claimUIDFail, params.NetworkParameters{
		ConfinementMode: apis.ConfinementModeNetworkPolicyDenyAll,
		AdapterMode:     apis.AdapterModeExplicitProxy,
	})
	if res, err := drv.PrepareResourceClaims(ctx, []*resourceapi.ResourceClaim{claimFail}); err != nil || res[claimUIDFail].Err != nil {
		t.Fatalf("PrepareResourceClaims fail: err=%v res=%+v", err, res[claimUIDFail])
	}
	if err := drv.RunPodSandbox(ctx, &nriapi.PodSandbox{
		Uid:       string(podUIDFail),
		Name:      "sb-tc-fail",
		Namespace: "agents",
		Linux:     &nriapi.LinuxPodSandbox{Namespaces: []*nriapi.LinuxNamespace{{Type: "network", Path: "/var/run/netns/tcfail"}}},
	}); err == nil {
		t.Fatalf("expected RunPodSandbox to fail closed when BlockNonLoopbackNICs fails")
	}
	netns.blockErr = nil

	// Verify ExplicitProxy injects all language magic proxy env vars pointing at http://127.0.0.1:18080
	// and appends cleanly to existing JAVA_TOOL_OPTIONS.
	adj, _, err := drv.CreateContainer(ctx, pod, &nriapi.Container{
		Name: "agent",
		Env:  []string{"JAVA_TOOL_OPTIONS=-Xmx256m"},
	})
	if err != nil || adj == nil {
		t.Fatalf("CreateContainer ExplicitProxy: adj=%+v err=%v", adj, err)
	}
	envs := envMap(adj.Env)
	if envs["HTTP_PROXY"] != "http://127.0.0.1:18080" || envs["http_proxy"] != "http://127.0.0.1:18080" {
		t.Fatalf("unexpected HTTP_PROXY/http_proxy: %+v", envs)
	}
	if envs["NODE_USE_ENV_PROXY"] != "1" || envs["GRPC_PROXY_EXP"] != "http://127.0.0.1:18080" {
		t.Fatalf("missing Node/gRPC proxy env vars: %+v", envs)
	}
	if !strings.HasPrefix(envs["JAVA_TOOL_OPTIONS"], "-Xmx256m -Dhttp.proxyHost=127.0.0.1 -Dhttp.proxyPort=18080") {
		t.Fatalf("unexpected JAVA_TOOL_OPTIONS: %q", envs["JAVA_TOOL_OPTIONS"])
	}

	// Verify loopback check failure aborts RunPodSandbox.
	netns.verifyErr = errors.New("non-loopback eth0 present")
	podUID2 := types.UID("pod-bad-netns")
	claimUID2 := types.UID("claim-bad-netns")
	claim2 := makeTestClaim(podUID2, claimUID2, params.NetworkParameters{
		ConfinementMode: apis.ConfinementModePodNetworkIsolated,
	})
	prepRes2, err := drv.PrepareResourceClaims(ctx, []*resourceapi.ResourceClaim{claim2})
	if err != nil || prepRes2[claimUID2].Err != nil {
		t.Fatalf("PrepareResourceClaims 2: err=%v res=%+v", err, prepRes2[claimUID2])
	}
	if err := drv.RunPodSandbox(ctx, &nriapi.PodSandbox{
		Uid:       string(podUID2),
		Name:      "sb2",
		Namespace: "agents",
		Linux:     &nriapi.LinuxPodSandbox{Namespaces: []*nriapi.LinuxNamespace{{Type: "network", Path: "/var/run/netns/bad"}}},
	}); err == nil {
		t.Fatalf("expected RunPodSandbox to fail when non-loopback interface exists under PodNetworkIsolated")
	}
}

func TestPodSandboxRecreationStaleGCAndIdempotentPrepare(t *testing.T) {
	ctx := t.Context()
	tmp := shortTempDir(t)
	st, _ := store.New(nil)
	tm, err := tunnel.NewManager(filepath.Join(tmp, "s"), nil, tunnel.WithAuditWriter(io.Discard))
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	defer tm.Close()

	netns := &fakeNetNS{}
	drv, err := New(Config{NodeName: "worker-1", Store: st, Tunnel: tm, NetNS: netns})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	drv.nriConnected.Store(true)

	// 1. Empty ReservedFor must fail closed.
	emptyClaim := makeTestClaim("pod-empty", "claim-empty", params.NetworkParameters{})
	emptyClaim.Status.ReservedFor = nil
	resEmpty, err := drv.PrepareResourceClaims(ctx, []*resourceapi.ResourceClaim{emptyClaim})
	if err != nil || resEmpty[emptyClaim.UID].Err == nil {
		t.Fatalf("expected PrepareResourceClaims to reject empty ReservedFor, got err=%v res=%+v", err, resEmpty)
	}

	// 2. Prepare -> RunPodSandbox(sb-1) -> Stop(sb-1) -> Remove(sb-1) -> RunPodSandbox(sb-2).
	podUID := types.UID("pod-recreate-1")
	claimUID := types.UID("claim-recreate-1")
	claim := makeTestClaim(podUID, claimUID, params.NetworkParameters{
		ConfinementMode: apis.ConfinementModePodNetworkIsolated,
		AdapterMode:     apis.AdapterModeExplicitProxy,
	})
	if res, err := drv.PrepareResourceClaims(ctx, []*resourceapi.ResourceClaim{claim}); err != nil || res[claimUID].Err != nil {
		t.Fatalf("PrepareResourceClaims: err=%v res=%+v", err, res)
	}

	sb1 := &nriapi.PodSandbox{
		Id: "sb-id-1", Uid: string(podUID), Name: "sb", Namespace: "agents",
		Linux: &nriapi.LinuxPodSandbox{Namespaces: []*nriapi.LinuxNamespace{{Type: "network", Path: "/var/run/netns/sb1"}}},
	}
	if err := drv.RunPodSandbox(ctx, sb1); err != nil {
		t.Fatalf("RunPodSandbox(sb1): %v", err)
	}
	if err := drv.StopPodSandbox(ctx, sb1); err != nil {
		t.Fatalf("StopPodSandbox(sb1): %v", err)
	}
	if err := drv.RemovePodSandbox(ctx, sb1); err != nil {
		t.Fatalf("RemovePodSandbox(sb1): %v", err)
	}
	// DRA-owned store entry must survive RemovePodSandbox so kubelet retry stays confined.
	if _, ok := st.Get(podUID); !ok {
		t.Fatal("RemovePodSandbox erroneously deleted DRA-owned store entry")
	}

	sb2 := &nriapi.PodSandbox{
		Id: "sb-id-2", Uid: string(podUID), Name: "sb", Namespace: "agents",
		Linux: &nriapi.LinuxPodSandbox{Namespaces: []*nriapi.LinuxNamespace{{Type: "network", Path: "/var/run/netns/sb2"}}},
	}
	if err := drv.RunPodSandbox(ctx, sb2); err != nil {
		t.Fatalf("RunPodSandbox(sb2) after retry: %v", err)
	}
	if !tm.HasExtraListener(podUID) {
		t.Fatal("expected re-armed socketat listener on recreated sandbox sb2")
	}

	// Stale StopPodSandbox/RemovePodSandbox for sb1 must NOT disrupt live sb2.
	if err := drv.StopPodSandbox(ctx, sb1); err != nil {
		t.Fatalf("stale StopPodSandbox(sb1): %v", err)
	}
	if err := drv.RemovePodSandbox(ctx, sb1); err != nil {
		t.Fatalf("stale RemovePodSandbox(sb1): %v", err)
	}
	if !tm.HasExtraListener(podUID) {
		t.Fatal("stale sb1 teardown disrupted live replacement sandbox sb2")
	}
	cfg, ok := st.Get(podUID)
	if !ok || cfg.SandboxID != "sb-id-2" || cfg.NetNS != "/var/run/netns/sb2" {
		t.Fatalf("live sb2 state corrupted by stale sb1 GC: %+v", cfg)
	}

	// 3. Idempotent re-invocation of PrepareResourceClaims preserves live NetNS, SandboxID, and ServiceAccount.
	_ = st.UpdateIdentity(podUID, "sb", "agents", "my-sa")
	if res, err := drv.PrepareResourceClaims(ctx, []*resourceapi.ResourceClaim{claim}); err != nil || res[claimUID].Err != nil {
		t.Fatalf("idempotent PrepareResourceClaims: err=%v res=%+v", err, res)
	}
	cfgAfter, ok := st.Get(podUID)
	if !ok || cfgAfter.NetNS != "/var/run/netns/sb2" || cfgAfter.SandboxID != "sb-id-2" || cfgAfter.ServiceAccount != "my-sa" {
		t.Fatalf("idempotent PrepareResourceClaims wiped live state: %+v", cfgAfter)
	}
}

func TestHostTunDefaultZeroSidecarLifecycle(t *testing.T) {
	ctx := t.Context()
	tmp := shortTempDir(t)
	st, _ := store.New(nil)
	tm, err := tunnel.NewManager(filepath.Join(tmp, "s"), nil, tunnel.WithAuditWriter(io.Discard))
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	defer tm.Close()

	netns := &fakeNetNS{}
	drv, err := New(Config{NodeName: "worker-1", Store: st, Tunnel: tm, NetNS: netns})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	drv.nriConnected.Store(true)

	// Empty AdapterMode must default to HostTun.
	podUID := types.UID("pod-hosttun-1")
	claimUID := types.UID("claim-hosttun-1")
	claim := makeTestClaim(podUID, claimUID, params.NetworkParameters{
		ConfinementMode: apis.ConfinementModeNetworkPolicyDenyAll,
		IngressPorts:    []apis.IngressPort{{Port: 8080}},
	})
	prepRes, err := drv.PrepareResourceClaims(ctx, []*resourceapi.ResourceClaim{claim})
	if err != nil || prepRes[claimUID].Err != nil {
		t.Fatalf("PrepareResourceClaims: err=%v res=%+v", err, prepRes[claimUID])
	}
	cfg, ok := st.Get(podUID)
	if !ok {
		t.Fatal("missing PodConfig in store")
	}
	if cfg.Parameters.EffectiveAdapterMode() != apis.AdapterModeHostTun {
		t.Fatalf("EffectiveAdapterMode = %q, want HostTun", cfg.Parameters.EffectiveAdapterMode())
	}
	if cfg.SocketPaths.ResolvConfPath == "" {
		t.Fatal("expected ResolvConfPath written for HostTun")
	}
	resolvBytes, err := os.ReadFile(cfg.SocketPaths.ResolvConfPath)
	if err != nil {
		t.Fatalf("read HostTun resolv.conf: %v", err)
	}
	if got := string(resolvBytes); got != "nameserver 198.19.255.253\n" {
		t.Fatalf("resolv.conf = %q, want %q", got, "nameserver 198.19.255.253\n")
	}

	pod := &nriapi.PodSandbox{
		Id:        "sb-hosttun-1",
		Uid:       string(podUID),
		Name:      "agent",
		Namespace: "agents",
		Linux:     &nriapi.LinuxPodSandbox{Namespaces: []*nriapi.LinuxNamespace{{Type: "network", Path: "/var/run/netns/ht1"}}},
	}
	if err := drv.RunPodSandbox(ctx, pod); err != nil {
		t.Fatalf("RunPodSandbox: %v", err)
	}
	if len(netns.hostTunPaths) != 1 || netns.hostTunPaths[0] != "/var/run/netns/ht1" || netns.hostTunPreserveNIC[0] {
		t.Fatalf("unexpected HostTun start: paths=%v preserveNIC=%v", netns.hostTunPaths, netns.hostTunPreserveNIC)
	}
	if len(netns.listenedAddrs) != 0 {
		t.Fatalf("HostTun must not bind ExplicitProxy loopback port, got %v", netns.listenedAddrs)
	}

	// CreateContainer replaces /etc/resolv.conf without mounting egress.sock or injecting HTTP_PROXY or /dev/net/tun.
	adj, _, err := drv.CreateContainer(ctx, pod, &nriapi.Container{Name: "agent"})
	if err != nil || adj == nil {
		t.Fatalf("CreateContainer: adj=%+v err=%v", adj, err)
	}
	if adj.Linux != nil && len(adj.Linux.Devices) > 0 {
		t.Fatalf("HostTun must not expose /dev/net/tun to container: %+v", adj.Linux.Devices)
	}
	var sawRemoveResolv, sawAddResolv bool
	for _, m := range adj.Mounts {
		if m.Destination == containerEgressMountDir {
			t.Fatalf("HostTun must not mount egress.sock into container: %+v", adj.Mounts)
		}
		if strings.HasSuffix(m.Destination, containerResolvConfPath) && m.Source == "" {
			sawRemoveResolv = true
		}
		if m.Destination == containerResolvConfPath && m.Source == cfg.SocketPaths.ResolvConfPath {
			sawAddResolv = true
		}
	}
	if !sawRemoveResolv || !sawAddResolv {
		t.Fatalf("expected RemoveMount + AddMount for /etc/resolv.conf, got %+v", adj.Mounts)
	}
	envs := envMap(adj.Env)
	if envs["HTTP_PROXY"] != "" || envs["HTTPS_PROXY"] != "" {
		t.Fatalf("HostTun must not inject HTTP_PROXY/HTTPS_PROXY: %+v", envs)
	}
	if envs["AGENT_INGRESS_PORT"] != "8080" {
		t.Fatalf("AGENT_INGRESS_PORT = %q, want 8080", envs["AGENT_INGRESS_PORT"])
	}

	// nicBlockMode=Disabled under NetworkPolicyDenyAll enables preserveNICReturn.
	podUID2 := types.UID("pod-hosttun-disabled")
	claimUID2 := types.UID("claim-hosttun-disabled")
	claim2 := makeTestClaim(podUID2, claimUID2, params.NetworkParameters{
		ConfinementMode: apis.ConfinementModeNetworkPolicyDenyAll,
		NICBlockMode:    apis.NICBlockModeDisabled,
		AdapterMode:     apis.AdapterModeHostTun,
	})
	if res, err := drv.PrepareResourceClaims(ctx, []*resourceapi.ResourceClaim{claim2}); err != nil || res[claimUID2].Err != nil {
		t.Fatalf("PrepareResourceClaims 2: err=%v res=%+v", err, res)
	}
	pod2 := &nriapi.PodSandbox{
		Id: "sb-hosttun-2", Uid: string(podUID2), Name: "agent2", Namespace: "agents",
		Linux: &nriapi.LinuxPodSandbox{Namespaces: []*nriapi.LinuxNamespace{{Type: "network", Path: "/var/run/netns/ht2"}}},
	}
	if err := drv.RunPodSandbox(ctx, pod2); err != nil {
		t.Fatalf("RunPodSandbox 2: %v", err)
	}
	if len(netns.hostTunPreserveNIC) != 2 || !netns.hostTunPreserveNIC[1] {
		t.Fatalf("expected preserveNICReturn=true for nicBlockMode=Disabled, got %v", netns.hostTunPreserveNIC)
	}

	// StopPodSandbox closes handle without deleting persistent tun0; RemovePodSandbox cleans up tun0.
	if err := drv.StopPodSandbox(ctx, pod); err != nil {
		t.Fatalf("StopPodSandbox: %v", err)
	}
	if netns.hostTunClosed != 1 || len(netns.hostTunCleaned) != 0 {
		t.Fatalf("after StopPodSandbox: closed=%d cleaned=%v, want 1 / []", netns.hostTunClosed, netns.hostTunCleaned)
	}
	// Re-start and test RemovePodSandbox cleanup.
	if err := drv.RunPodSandbox(ctx, pod); err != nil {
		t.Fatalf("RunPodSandbox restart: %v", err)
	}
	if err := drv.RemovePodSandbox(ctx, pod); err != nil {
		t.Fatalf("RemovePodSandbox: %v", err)
	}
	if netns.hostTunClosed != 2 || len(netns.hostTunCleaned) != 1 || netns.hostTunCleaned[0] != "/var/run/netns/ht1" {
		t.Fatalf("after RemovePodSandbox: closed=%d cleaned=%v", netns.hostTunClosed, netns.hostTunCleaned)
	}
}
