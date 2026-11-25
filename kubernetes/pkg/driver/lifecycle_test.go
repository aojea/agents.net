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
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/containerd/nri/pkg/adaptation"
	nriapi "github.com/containerd/nri/pkg/api"
	"github.com/containerd/nri/pkg/stub"
	"github.com/prometheus/client_golang/prometheus/testutil"
	resourceapi "k8s.io/api/resource/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/record"
	"k8s.io/dynamic-resource-allocation/kubeletplugin"
	"k8s.io/dynamic-resource-allocation/resourceslice"
	registerapi "k8s.io/kubelet/pkg/apis/pluginregistration/v1"
	testingclock "k8s.io/utils/clock/testing"

	"github.com/aojea/agents.net/kubernetes/pkg/apis"
	"github.com/aojea/agents.net/kubernetes/pkg/catrust"
	"github.com/aojea/agents.net/kubernetes/pkg/metrics"
	"github.com/aojea/agents.net/kubernetes/pkg/params"
	"github.com/aojea/agents.net/kubernetes/pkg/store"
	"github.com/aojea/agents.net/kubernetes/pkg/tunnel"
)

type fakePluginHelper struct {
	stopCalled         atomic.Bool
	registrationStatus *registerapi.RegistrationStatus
	lastPublished      atomic.Pointer[resourceslice.DriverResources]
}

func (f *fakePluginHelper) PublishResources(_ context.Context, res resourceslice.DriverResources) error {
	f.lastPublished.Store(&res)
	return nil
}

func (f *fakePluginHelper) Stop() {
	f.stopCalled.Store(true)
}

func (f *fakePluginHelper) RegistrationStatus() *registerapi.RegistrationStatus {
	return f.registrationStatus
}

// fakeNRIStub is a fake stub.Stub for lifecycle tests. Each successful Start is
// one session that simulates the runtime's mandatory Synchronize handshake and
// stays open until disconnect or Stop.
type fakeNRIStub struct {
	stub.Stub

	mu         sync.Mutex
	drv        *Driver
	startFn    func(context.Context) error
	done       chan struct{}
	stopCalled atomic.Bool
}

func (f *fakeNRIStub) Start(ctx context.Context) error {
	if f.startFn != nil {
		if err := f.startFn(ctx); err != nil {
			return err
		}
	}
	f.mu.Lock()
	f.done = make(chan struct{})
	drv := f.drv
	f.mu.Unlock()
	if drv != nil {
		_, _ = drv.Synchronize(ctx, nil, nil)
	}
	return nil
}

func (f *fakeNRIStub) Wait() {
	f.mu.Lock()
	done := f.done
	f.mu.Unlock()
	if done != nil {
		<-done
	}
}

func (f *fakeNRIStub) Stop() {
	f.stopCalled.Store(true)
	f.disconnect()
}

func (f *fakeNRIStub) disconnect() {
	f.mu.Lock()
	done := f.done
	f.done = nil
	f.mu.Unlock()
	if done != nil {
		close(done)
	}
}

func TestPrepareResourceClaimsGatedWhenNRIDisconnected(t *testing.T) {
	ctx := t.Context()
	st, _ := store.New(nil)
	tm, err := tunnel.NewManager(shortTempDir(t), nil, tunnel.WithAuditWriter(io.Discard))
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	defer tm.Close()

	drv, err := New(Config{NodeName: "worker-1", Store: st, Tunnel: tm, NetNS: &fakeNetNS{}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Empty claim batches still succeed when NRI is disconnected.
	if res, err := drv.PrepareResourceClaims(ctx, nil); err != nil || res != nil {
		t.Fatalf("PrepareResourceClaims(nil) = (%v, %v), want (nil, nil)", res, err)
	}

	claim := makeTestClaim("pod-uid-gate", "claim-uid-gate", params.NetworkParameters{
		ConfinementMode: apis.ConfinementModePodNetworkIsolated,
		AdapterMode:     apis.AdapterModeExplicitProxy,
	})

	before := testutil.ToFloat64(metrics.DRAPluginRequestsTotal.WithLabelValues(methodPrepareResourceClaims, metrics.StatusFailed))
	if _, err := drv.PrepareResourceClaims(ctx, []*resourceapi.ResourceClaim{claim}); err == nil || !strings.Contains(err.Error(), "not connected") {
		t.Fatalf("PrepareResourceClaims while NRI disconnected: err = %v, want not connected error", err)
	}
	after := testutil.ToFloat64(metrics.DRAPluginRequestsTotal.WithLabelValues(methodPrepareResourceClaims, metrics.StatusFailed))
	if after-before != 1 {
		t.Errorf("DRA failed metric delta = %v, want 1", after-before)
	}

	// Once NRI connects, PrepareResourceClaims succeeds normally.
	drv.nriConnected.Store(true)
	res, err := drv.PrepareResourceClaims(ctx, []*resourceapi.ResourceClaim{claim})
	if err != nil || res[claim.UID].Err != nil {
		t.Fatalf("PrepareResourceClaims while NRI connected = (%+v, %v), want success", res, err)
	}
}

// TestStartConnectsNRIBeforeDRA verifies that Start does not create the DRA
// registration socket until NRI has connected to the container runtime.
func TestStartConnectsNRIBeforeDRA(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Use /tmp so Unix socket paths stay under Linux's 108-byte sun_path limit.
	rootDir, err := os.MkdirTemp("/tmp", "agentsnet-start-*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(rootDir) })
	registryDir := filepath.Join(rootDir, "plugins_registry")
	if err := os.MkdirAll(registryDir, 0o750); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	registrationSockets := func() int {
		entries, err := os.ReadDir(registryDir)
		if err != nil {
			t.Fatalf("ReadDir: %v", err)
		}
		return len(entries)
	}

	connect := make(chan struct{})
	fakeNRI := &fakeNRIStub{startFn: func(ctx context.Context) error {
		select {
		case <-connect:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}}

	st, _ := store.New(nil)
	tm, _ := tunnel.NewManager(shortTempDir(t), nil, tunnel.WithAuditWriter(io.Discard))
	defer tm.Close()
	drv, err := New(Config{
		NodeName:       "node-1",
		KubeClient:     fake.NewClientset(),
		Store:          st,
		Tunnel:         tm,
		NetNS:          &fakeNetNS{},
		KubeletRootDir: rootDir,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	fakeNRI.drv = drv
	drv.nriPlugin = fakeNRI
	drv.clock = testingclock.NewFakeClock(time.Now())

	startErr := make(chan error, 1)
	go func() { startErr <- drv.Start(ctx) }()

	time.Sleep(200 * time.Millisecond)
	if n := registrationSockets(); n != 0 {
		t.Fatalf("DRA plugin started before NRI connected: found %d registration sockets", n)
	}

	close(connect)
	deadline := time.Now().Add(5 * time.Second)
	for registrationSockets() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if registrationSockets() == 0 {
		t.Fatal("DRA plugin did not start after NRI connected")
	}

	// No real kubelet is present to complete registration, so cancel here.
	cancel()
	if err := <-startErr; err == nil {
		t.Error("Start() = nil without kubelet registration, want error")
	}
	fakeNRI.Stop()
}

func TestRunNRIReconnectBackoffAndReset(t *testing.T) {
	ctx := t.Context()

	fakeClock := testingclock.NewFakeClock(time.Now())
	attemptCh := make(chan int, 20)

	// Outage 1: 3 failed reconnects, 4th succeeds (streak resets).
	// Outage 2: 3 failed reconnects, 4th succeeds (6 total failures > maxNRIAttempts=5).
	// Outage 3: maxNRIAttempts consecutive failures -> runNRI returns error.
	outcomes := []error{
		nil,
		errors.New("outage-1-err-1"),
		errors.New("outage-1-err-2"),
		errors.New("outage-1-err-3"),
		nil,
		errors.New("outage-2-err-1"),
		errors.New("outage-2-err-2"),
		errors.New("outage-2-err-3"),
		nil,
		errors.New("outage-3-err-1"),
		errors.New("outage-3-err-2"),
		errors.New("outage-3-err-3"),
		errors.New("outage-3-err-4"),
		errors.New("outage-3-err-5"),
	}

	var idx atomic.Int32
	fakeNRI := &fakeNRIStub{}
	fakeNRI.startFn = func(context.Context) error {
		n := int(idx.Add(1)) - 1
		attemptCh <- n
		if n >= len(outcomes) {
			return errors.New("unexpected extra attempt")
		}
		return outcomes[n]
	}

	st, _ := store.New(nil)
	tm, _ := tunnel.NewManager(shortTempDir(t), nil, tunnel.WithAuditWriter(io.Discard))
	defer tm.Close()
	drv, err := New(Config{NodeName: "node-1", Store: st, Tunnel: tm, NetNS: &fakeNetNS{}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	fakeNRI.drv = drv
	drv.nriPlugin = fakeNRI
	drv.clock = fakeClock

	runErrCh := make(chan error, 1)
	go func() { runErrCh <- drv.runNRI(ctx) }()

	waitAttempt := func(want int) {
		t.Helper()
		select {
		case got := <-attemptCh:
			if got != want {
				t.Fatalf("attempt index = %d, want %d", got, want)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for attempt %d", want)
		}
	}
	waitWaiter := func() {
		t.Helper()
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			if fakeClock.HasWaiters() {
				return
			}
			time.Sleep(time.Millisecond)
		}
		t.Fatal("timed out waiting for backoff timer")
	}
	waitConnState := func(want bool) {
		t.Helper()
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			if drv.nriConnected.Load() == want {
				return
			}
			time.Sleep(time.Millisecond)
		}
		t.Fatalf("timed out waiting for nriConnected=%v", want)
	}
	reconnect := func(backoff time.Duration, attempt int) {
		t.Helper()
		waitWaiter()
		fakeClock.Step(backoff - time.Millisecond)
		select {
		case got := <-attemptCh:
			t.Fatalf("attempt %d fired before %v backoff elapsed", got, backoff)
		case <-time.After(5 * time.Millisecond):
		}
		fakeClock.Step(time.Millisecond)
		waitAttempt(attempt)
	}

	// Initial session connects immediately.
	waitAttempt(0)
	waitConnState(true)

	// Outage 1: 1s, 2s, 4s, 8s -> recovery.
	fakeNRI.disconnect()
	waitConnState(false)
	reconnect(1*time.Second, 1)
	reconnect(2*time.Second, 2)
	reconnect(4*time.Second, 3)
	reconnect(8*time.Second, 4)
	waitConnState(true)

	// Outage 2: streak and backoff reset -> starts at 1s again, survives > 5 total failures.
	fakeNRI.disconnect()
	waitConnState(false)
	reconnect(1*time.Second, 5)
	reconnect(2*time.Second, 6)
	reconnect(4*time.Second, 7)
	reconnect(8*time.Second, 8)
	waitConnState(true)

	// Outage 3: 5 consecutive failures return error.
	fakeNRI.disconnect()
	waitConnState(false)
	for i, d := range []time.Duration{1 * time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second} {
		reconnect(d, 9+i)
	}

	select {
	case err := <-runErrCh:
		if err == nil {
			t.Fatal("runNRI returned nil after maxNRIAttempts consecutive failures, want error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for runNRI to exit after maxNRIAttempts consecutive failures")
	}
}

func TestStopWaitsForPreparedPodsGracePeriod(t *testing.T) {
	now := time.Now()
	fakeClock := testingclock.NewFakeClock(now)

	st, _ := store.New(nil)
	// Pod 1 prepared with zero NRI activity yet; Pod 2 had NRI activity at now.
	_ = st.Upsert(store.PodConfig{PodUID: "pod-1", ClaimUID: "claim-1"})
	_ = st.Upsert(store.PodConfig{PodUID: "pod-2", ClaimUID: "claim-2", LastNRIActivity: now})

	tm, _ := tunnel.NewManager(shortTempDir(t), nil, tunnel.WithAuditWriter(io.Discard))
	defer tm.Close()
	fakeDRA := &fakePluginHelper{registrationStatus: &registerapi.RegistrationStatus{PluginRegistered: true}}
	fakeNRI := &fakeNRIStub{}

	drv, err := New(Config{NodeName: "node-1", Store: st, Tunnel: tm, NetNS: &fakeNetNS{}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	fakeNRI.drv = drv
	drv.draPlugin = fakeDRA
	drv.nriPlugin = fakeNRI
	drv.clock = fakeClock
	drv.draRegistered.Store(true)

	var cancelCalled atomic.Bool
	done := make(chan struct{})
	go func() {
		drv.Stop(func() { cancelCalled.Store(true) })
		close(done)
	}()

	// DRA stops immediately while Stop waits on the grace period ticker.
	deadline := time.Now().Add(2 * time.Second)
	for !fakeClock.HasWaiters() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !fakeDRA.stopCalled.Load() || drv.CheckDRA() == nil {
		t.Fatal("DRA plugin must stop immediately at start of Stop()")
	}
	if fakeNRI.stopCalled.Load() {
		t.Fatal("NRI plugin stopped before grace period elapsed")
	}

	// Step 5s (still within 10s grace period): Stop must still wait.
	fakeClock.Step(5 * time.Second)
	select {
	case <-done:
		t.Fatal("Stop finished after 5s, before 10s grace period")
	case <-time.After(20 * time.Millisecond):
	}

	// Step another 5s (10s total): both pods satisfy grace period -> Stop completes.
	fakeClock.Step(5 * time.Second)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop did not finish after grace period elapsed")
	}

	if !cancelCalled.Load() {
		t.Error("ctxCancel was not called")
	}
	if !fakeNRI.stopCalled.Load() {
		t.Error("nriPlugin.Stop was not called")
	}
}

// unixSocketProxy forwards a stable Unix socket path to a swappable backend
// runtime socket and can drop all live connections to simulate containerd restart.
type unixSocketProxy struct {
	ln     net.Listener
	mu     sync.Mutex
	target string
	conns  map[net.Conn]struct{}
	closed bool
}

func newUnixSocketProxy(t *testing.T, listenPath string) *unixSocketProxy {
	t.Helper()
	ln, err := net.Listen("unix", listenPath)
	if err != nil {
		t.Fatalf("listen %s: %v", listenPath, err)
	}
	p := &unixSocketProxy{
		ln:    ln,
		conns: make(map[net.Conn]struct{}),
	}
	go p.acceptLoop()
	t.Cleanup(p.close)
	return p
}

func (p *unixSocketProxy) setTarget(target string) {
	p.mu.Lock()
	p.target = target
	p.mu.Unlock()
}

func (p *unixSocketProxy) dropConnections() {
	p.mu.Lock()
	conns := make([]net.Conn, 0, len(p.conns))
	for c := range p.conns {
		conns = append(conns, c)
	}
	p.mu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
}

func (p *unixSocketProxy) close() {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.closed = true
	p.mu.Unlock()
	_ = p.ln.Close()
	p.dropConnections()
}

func (p *unixSocketProxy) track(c net.Conn) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		_ = c.Close()
		return
	}
	p.conns[c] = struct{}{}
	p.mu.Unlock()
}

func (p *unixSocketProxy) untrack(c net.Conn) {
	p.mu.Lock()
	delete(p.conns, c)
	p.mu.Unlock()
	_ = c.Close()
}

func (p *unixSocketProxy) acceptLoop() {
	for {
		clientConn, err := p.ln.Accept()
		if err != nil {
			return
		}
		p.mu.Lock()
		target := p.target
		p.mu.Unlock()
		if target == "" {
			_ = clientConn.Close()
			continue
		}
		backendConn, err := net.Dial("unix", target)
		if err != nil {
			_ = clientConn.Close()
			continue
		}
		p.track(clientConn)
		p.track(backendConn)
		go func() {
			_, _ = io.Copy(backendConn, clientConn)
			p.untrack(clientConn)
			p.untrack(backendConn)
		}()
		go func() {
			_, _ = io.Copy(clientConn, backendConn)
			p.untrack(clientConn)
			p.untrack(backendConn)
		}()
	}
}

func startTestNRIRuntime(t *testing.T, sockPath, emptyDir string, syncPods []*nriapi.PodSandbox, syncCtrs []*nriapi.Container) *adaptation.Adaptation {
	t.Helper()
	syncFn := func(ctx context.Context, cb adaptation.SyncCB) error {
		_, err := cb(ctx, syncPods, syncCtrs)
		return err
	}
	updateFn := func(context.Context, []*nriapi.ContainerUpdate) ([]*nriapi.ContainerUpdate, error) {
		return nil, nil
	}
	rt, err := adaptation.New("containerd", "2.0.0", syncFn, updateFn,
		adaptation.WithSocketPath(sockPath),
		adaptation.WithPluginPath(emptyDir),
		adaptation.WithPluginConfigPath(emptyDir),
	)
	if err != nil {
		t.Fatalf("adaptation.New(%s): %v", sockPath, err)
	}
	if err := rt.Start(); err != nil {
		t.Fatalf("rt.Start(%s): %v", sockPath, err)
	}
	rt.BlockPluginSync().Unblock()
	t.Cleanup(rt.Stop)
	return rt
}

func TestEndToEndNRISessionAndRuntimeRestart(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sockDir, err := os.MkdirTemp("/tmp", "agentsnet-nri-*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sockDir) })
	emptyDir := filepath.Join(sockDir, "empty")
	if err := os.MkdirAll(emptyDir, 0o750); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	clientSock := filepath.Join(sockDir, "nri.sock")
	rt1Sock := filepath.Join(sockDir, "rt1.sock")
	rt2Sock := filepath.Join(sockDir, "rt2.sock")

	rt1 := startTestNRIRuntime(t, rt1Sock, emptyDir, nil, nil)
	proxy := newUnixSocketProxy(t, clientSock)
	proxy.setTarget(rt1Sock)

	fakeClock := testingclock.NewFakeClock(time.Now())
	st, _ := store.New(nil)
	tm, _ := tunnel.NewManager(shortTempDir(t), nil, tunnel.WithAuditWriter(io.Discard))
	defer tm.Close()

	drv, err := New(Config{
		NodeName:      "node-1",
		KubeClient:    fake.NewClientset(),
		Store:         st,
		Tunnel:        tm,
		NetNS:         &fakeNetNS{},
		EventRecorder: record.NewFakeRecorder(100),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	drv.draPlugin = &fakePluginHelper{registrationStatus: &registerapi.RegistrationStatus{PluginRegistered: true}}
	drv.clock = fakeClock

	waitFor := func(desc string, cond func() bool) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if cond() {
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
		t.Fatalf("timed out waiting for %s", desc)
	}

	nriStub, err := stub.New(drv,
		stub.WithPluginName(drv.driverName),
		stub.WithPluginIdx("00"),
		stub.WithSocketPath(clientSock),
		stub.WithFailurePolicy(&nriapi.FailurePolicy{FailRequest: true, KeepConnected: true}),
	)
	if err != nil {
		t.Fatalf("stub.New: %v", err)
	}
	drv.nriPlugin = nriStub

	runErr := make(chan error, 1)
	go func() { runErr <- drv.runNRI(ctx) }()
	waitFor("NRI connection to runtime 1", func() bool { return drv.CheckNRI() == nil })

	// 1. Prepare claim-1 and exercise RunPodSandbox/CreateContainer on runtime 1.
	claim1 := makeTestClaim("pod-1-uid", "claim-1-uid", params.NetworkParameters{
		ConfinementMode: apis.ConfinementModePodNetworkIsolated,
		AdapterMode:     apis.AdapterModeExplicitProxy,
	})
	res, err := drv.PrepareResourceClaims(ctx, []*resourceapi.ResourceClaim{claim1})
	if err != nil || res[claim1.UID].Err != nil {
		t.Fatalf("PrepareResourceClaims(claim1) = (%+v, %v), want success", res, err)
	}
	pod1 := &nriapi.PodSandbox{
		Id:        "pod-1-sb",
		Uid:       "pod-1-uid",
		Name:      "pod-1",
		Namespace: "agents",
		Linux: &nriapi.LinuxPodSandbox{
			Namespaces: []*nriapi.LinuxNamespace{{Type: "network", Path: "/var/run/netns/pod1"}},
		},
	}
	if err := rt1.RunPodSandbox(ctx, &nriapi.RunPodSandboxRequest{Pod: pod1}); err != nil {
		t.Fatalf("rt1.RunPodSandbox(pod-1): %v", err)
	}
	if _, err := rt1.CreateContainer(ctx, &nriapi.CreateContainerRequest{
		Pod:       pod1,
		Container: &nriapi.Container{Id: "ctr-1", Name: "agent"},
	}); err != nil {
		t.Fatalf("rt1.CreateContainer(pod-1): %v", err)
	}

	// 2. Simulate containerd restart: drop connections and stop runtime 1.
	proxy.setTarget("")
	proxy.dropConnections()
	rt1.Stop()

	waitFor("NRI disconnect and reconnect timer", func() bool {
		return !drv.nriConnected.Load() && fakeClock.HasWaiters()
	})
	if err := drv.CheckNRI(); err == nil {
		t.Fatal("CheckNRI() during outage = nil, want error")
	}

	// While NRI is down, PrepareResourceClaims rejects new claims.
	claim2 := makeTestClaim("pod-2-uid", "claim-2-uid", params.NetworkParameters{
		ConfinementMode: apis.ConfinementModePodNetworkIsolated,
		AdapterMode:     apis.AdapterModeExplicitProxy,
	})
	if _, err := drv.PrepareResourceClaims(ctx, []*resourceapi.ResourceClaim{claim2}); err == nil || !strings.Contains(err.Error(), "not connected") {
		t.Fatalf("PrepareResourceClaims while disconnected = %v, want not connected error", err)
	}

	// 3. Start runtime 2 with pod-1 live (with /run/agents.net mount) and reconnect.
	pod1Reloaded := &nriapi.PodSandbox{
		Id:        "pod-1-sb",
		Uid:       "pod-1-uid",
		Name:      "pod-1",
		Namespace: "agents",
		Linux: &nriapi.LinuxPodSandbox{
			Namespaces: []*nriapi.LinuxNamespace{{Type: "network", Path: "/var/run/netns/pod1-reloaded"}},
		},
	}
	ctr1Reloaded := &nriapi.Container{
		Id:           "ctr-1",
		PodSandboxId: "pod-1-sb",
		Name:         "agent",
		State:        nriapi.ContainerState_CONTAINER_RUNNING,
		Mounts:       []*nriapi.Mount{{Destination: containerEgressMountDir}},
	}
	rt2 := startTestNRIRuntime(t, rt2Sock, emptyDir, []*nriapi.PodSandbox{pod1Reloaded}, []*nriapi.Container{ctr1Reloaded})
	proxy.setTarget(rt2Sock)
	fakeClock.Step(nriInitialBackoff)

	waitFor("NRI connection to runtime 2", func() bool { return drv.CheckNRI() == nil })
	waitFor("Synchronize updated pod-1 netns", func() bool {
		cfg, ok := st.Get("pod-1-uid")
		return ok && cfg.NetNS == "/var/run/netns/pod1-reloaded"
	})

	// New claims and hooks succeed on runtime 2 after reconnect.
	res, err = drv.PrepareResourceClaims(ctx, []*resourceapi.ResourceClaim{claim2})
	if err != nil || res[claim2.UID].Err != nil {
		t.Fatalf("PrepareResourceClaims(claim2) after reconnect = (%+v, %v)", res, err)
	}
	pod2 := &nriapi.PodSandbox{
		Id:        "pod-2-sb",
		Uid:       "pod-2-uid",
		Name:      "pod-2",
		Namespace: "agents",
		Linux: &nriapi.LinuxPodSandbox{
			Namespaces: []*nriapi.LinuxNamespace{{Type: "network", Path: "/var/run/netns/pod2"}},
		},
	}
	if err := rt2.RunPodSandbox(ctx, &nriapi.RunPodSandboxRequest{Pod: pod2}); err != nil {
		t.Fatalf("rt2.RunPodSandbox(pod-2): %v", err)
	}
	if _, err := rt2.CreateContainer(ctx, &nriapi.CreateContainerRequest{
		Pod:       pod2,
		Container: &nriapi.Container{Id: "ctr-2", Name: "agent"},
	}); err != nil {
		t.Fatalf("rt2.CreateContainer(pod-2): %v", err)
	}

	// Clean up prepared claims so Stop() finishes immediately without waiting for grace period.
	if _, err := drv.UnprepareResourceClaims(ctx, []kubeletplugin.NamespacedObject{
		{NamespacedName: types.NamespacedName{Namespace: "agents", Name: "claim-1"}, UID: claim1.UID},
		{NamespacedName: types.NamespacedName{Namespace: "agents", Name: "claim-2"}, UID: claim2.UID},
	}); err != nil {
		t.Fatalf("UnprepareResourceClaims: %v", err)
	}

	drv.Stop(cancel)
	if err := <-runErr; err != nil {
		t.Errorf("runNRI() after Stop() = %v, want nil", err)
	}
	if err := drv.CheckNRI(); err == nil {
		t.Error("CheckNRI() after Stop() = nil, want error")
	}
}

func TestSynchronizeReportsMissingPlumbingUnit(t *testing.T) {
	ctx := t.Context()
	st, _ := store.New(nil)
	tm, _ := tunnel.NewManager(shortTempDir(t), nil, tunnel.WithAuditWriter(io.Discard))
	defer tm.Close()

	recorder := record.NewFakeRecorder(10)
	netns := &fakeNetNS{hasRoutes: true}
	drv, err := New(Config{
		NodeName:      "worker-1",
		Store:         st,
		Tunnel:        tm,
		NetNS:         netns,
		EventRecorder: recorder,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	const podUID = types.UID("pod-missing-unit")
	if err := st.Upsert(store.PodConfig{
		PodUID:       podUID,
		PodName:      "sb-unplumbed",
		PodNamespace: "agents",
		Parameters: params.NetworkParameters{
			ConfinementMode: apis.ConfinementModeNetworkPolicyDenyAll,
			AdapterMode:     apis.AdapterModeExplicitProxy,
			CATrust:         &apis.CATrustConfig{Mode: apis.CATrustModeInjectEnv},
		},
		CABundle: catrust.MaterializedBundle{MergedHostPath: "/tmp/ca.pem"},
	}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	pod := &nriapi.PodSandbox{
		Id:        "sb-1",
		Uid:       string(podUID),
		Name:      "sb-unplumbed",
		Namespace: "agents",
		Linux: &nriapi.LinuxPodSandbox{
			Namespaces: []*nriapi.LinuxNamespace{{Type: "network", Path: "/var/run/netns/sb"}},
		},
	}

	runSync := func(state nriapi.ContainerState, mounts []*nriapi.Mount) ([]string, float64) {
		t.Helper()
		before := testutil.ToFloat64(metrics.PodsMissingPlumbingTotal)
		ctrs := []*nriapi.Container{{
			Id:           "ctr-1",
			PodSandboxId: pod.Id,
			Name:         "agent",
			State:        state,
			Mounts:       mounts,
		}}
		if _, err := drv.Synchronize(ctx, []*nriapi.PodSandbox{pod}, ctrs); err != nil {
			t.Fatalf("Synchronize: %v", err)
		}
		var events []string
		for len(recorder.Events) > 0 {
			events = append(events, <-recorder.Events)
		}
		return events, testutil.ToFloat64(metrics.PodsMissingPlumbingTotal) - before
	}

	// 1. Non-running container (creation/teardown) must NOT be reported.
	if evs, delta := runSync(nriapi.ContainerState_CONTAINER_CREATED, nil); len(evs) != 0 || delta != 0 {
		t.Fatalf("CREATED state: events=%v delta=%v, want none", evs, delta)
	}

	// 2. Running container missing mounts + unflushed routes -> Warning event + metric.
	evs, delta := runSync(nriapi.ContainerState_CONTAINER_RUNNING, nil)
	if len(evs) != 1 || delta != 1 {
		t.Fatalf("missing plumbing: events=%v delta=%v, want 1 event and delta 1", evs, delta)
	}
	for _, want := range []string{"Warning " + eventReasonPlumbingMissing, "ca-bundle-mount", "egress-socket-mount", "non-loopback-routes-unflushed"} {
		if !strings.Contains(evs[0], want) {
			t.Errorf("event = %q, missing %q", evs[0], want)
		}
	}

	// 3. Once routes are flushed and mounts are present -> clean (no event, no metric increase).
	netns.hasRoutes = false
	mounts := []*nriapi.Mount{
		{Destination: containerEgressMountDir},
		{Destination: catrust.ContainerCABundlePath},
	}
	if evs, delta := runSync(nriapi.ContainerState_CONTAINER_RUNNING, mounts); len(evs) != 0 || delta != 0 {
		t.Fatalf("healthy pod: events=%v delta=%v, want none", evs, delta)
	}
}

func TestSynchronizePreservesUnstartedPreparedPodAndReapsVanishedPod(t *testing.T) {
	ctx := t.Context()
	st, _ := store.New(nil)
	tm, _ := tunnel.NewManager(shortTempDir(t), nil, tunnel.WithAuditWriter(io.Discard))
	defer tm.Close()

	drv, err := New(Config{NodeName: "node-1", Store: st, Tunnel: tm, NetNS: &fakeNetNS{}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Pod A was prepared via DRA just before a runtime restart and has not reached RunPodSandbox yet (NetNS == "").
	if err := st.Upsert(store.PodConfig{
		PodUID:   "pod-unstarted",
		ClaimUID: "claim-unstarted",
		PodName:  "unstarted",
		Parameters: params.NetworkParameters{
			ConfinementMode: apis.ConfinementModePodNetworkIsolated,
			AdapterMode:     apis.AdapterModeExplicitProxy,
		},
	}); err != nil {
		t.Fatalf("Put unstarted: %v", err)
	}

	// Pod B previously ran (NetNS != "") and vanished while NRI was disconnected.
	if err := st.Upsert(store.PodConfig{
		PodUID:   "pod-vanished",
		ClaimUID: "claim-vanished",
		PodName:  "vanished",
		NetNS:    "/var/run/netns/old",
		Parameters: params.NetworkParameters{
			ConfinementMode: apis.ConfinementModePodNetworkIsolated,
			AdapterMode:     apis.AdapterModeExplicitProxy,
		},
	}); err != nil {
		t.Fatalf("Put vanished: %v", err)
	}

	if _, err := drv.Synchronize(ctx, nil, nil); err != nil {
		t.Fatalf("Synchronize: %v", err)
	}
	if !drv.nriConnected.Load() {
		t.Fatal("expected nriConnected=true after Synchronize completes")
	}
	if _, ok := st.Get("pod-unstarted"); !ok {
		t.Fatal("Synchronize erroneously reaped prepared Pod whose RunPodSandbox has not run yet")
	}
	if _, ok := st.Get("pod-vanished"); ok {
		t.Fatal("Synchronize failed to reap vanished Pod that had previously run")
	}
}

func TestBoltDBColdRestartSynchronizeRestoresSocketsAndSocketAt(t *testing.T) {
	ctx := t.Context()
	tmp := shortTempDir(t)
	dbPath := filepath.Join(tmp, "state.db")
	sockRoot := filepath.Join(tmp, "pods")

	// 1. Instance 1 prepares a Pod, runs RunPodSandbox, and exits (simulating DaemonSet restart).
	b1, err := store.OpenBolt(dbPath)
	if err != nil {
		t.Fatalf("OpenBolt 1: %v", err)
	}
	st1, err := store.New(b1)
	if err != nil {
		t.Fatalf("store.New 1: %v", err)
	}
	tm1, err := tunnel.NewManager(sockRoot, nil, tunnel.WithAuditWriter(io.Discard))
	if err != nil {
		t.Fatalf("NewManager 1: %v", err)
	}
	drv1, err := New(Config{NodeName: "node-1", Store: st1, Tunnel: tm1, NetNS: &fakeNetNS{}})
	if err != nil {
		t.Fatalf("New 1: %v", err)
	}
	drv1.nriConnected.Store(true)

	podUID := types.UID("pod-cold-restart")
	claimUID := types.UID("claim-cold-restart")
	claim := makeTestClaim(podUID, claimUID, params.NetworkParameters{
		ConfinementMode: apis.ConfinementModePodNetworkIsolated,
		AdapterMode:     apis.AdapterModeExplicitProxy,
	})
	if res, err := drv1.PrepareResourceClaims(ctx, []*resourceapi.ResourceClaim{claim}); err != nil || res[claimUID].Err != nil {
		t.Fatalf("PrepareResourceClaims: err=%v res=%+v", err, res)
	}
	pod := &nriapi.PodSandbox{
		Id:        "sb-cold-1",
		Uid:       string(podUID),
		Name:      "sb-cold",
		Namespace: "agents",
		Linux:     &nriapi.LinuxPodSandbox{Namespaces: []*nriapi.LinuxNamespace{{Type: "network", Path: "/var/run/netns/cold"}}},
	}
	if err := drv1.RunPodSandbox(ctx, pod); err != nil {
		t.Fatalf("RunPodSandbox: %v", err)
	}
	tm1.Close()
	_ = st1.Close()

	// 2. Instance 2 hydrates from BoltDB and runs Synchronize: egress.sock + socketat listener restored!
	b2, err := store.OpenBolt(dbPath)
	if err != nil {
		t.Fatalf("OpenBolt 2: %v", err)
	}
	defer func() { _ = b2.Close() }()
	st2, err := store.New(b2)
	if err != nil {
		t.Fatalf("store.New 2: %v", err)
	}
	tm2, err := tunnel.NewManager(sockRoot, nil, tunnel.WithAuditWriter(io.Discard))
	if err != nil {
		t.Fatalf("NewManager 2: %v", err)
	}
	defer tm2.Close()
	netns2 := &fakeNetNS{}
	drv2, err := New(Config{NodeName: "node-1", Store: st2, Tunnel: tm2, NetNS: netns2})
	if err != nil {
		t.Fatalf("New 2: %v", err)
	}

	if _, err := drv2.Synchronize(ctx, []*nriapi.PodSandbox{pod}, nil); err != nil {
		t.Fatalf("Synchronize after cold restart: %v", err)
	}
	if !tm2.HasExtraListener(podUID) {
		t.Fatal("expected socketat loopback listener restored after cold restart")
	}
	if len(netns2.listenedAddrs) != 1 || netns2.listenedAddrs[0] != "/var/run/netns/cold@127.0.0.1:15001" {
		t.Fatalf("unexpected restored socketat listen addrs: %v", netns2.listenedAddrs)
	}
}
