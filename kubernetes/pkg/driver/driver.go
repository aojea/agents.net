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

// Package driver implements the per-node dra-agents-net Kubernetes Network Driver
// (KND) following the Kubernetes Network Driver Model (Ojea, IEEE LCN 2025,
// DOI: 10.1109/LCN65610.2025.11146291 / arXiv:2506.23628) and DRANET's slow-path
// DRA / fast-path NRI split without writing CDI JSON specification files to disk.
package driver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	nriapi "github.com/containerd/nri/pkg/api"
	"github.com/containerd/nri/pkg/stub"
	corev1 "k8s.io/api/core/v1"
	resourceapi "k8s.io/api/resource/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	v1core "k8s.io/client-go/kubernetes/typed/core/v1"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/retry"
	"k8s.io/dynamic-resource-allocation/kubeletplugin"
	"k8s.io/dynamic-resource-allocation/resourceslice"
	"k8s.io/klog/v2"
	registerapi "k8s.io/kubelet/pkg/apis/pluginregistration/v1"
	"k8s.io/utils/clock"

	"github.com/aojea/agents.net/kubernetes/pkg/apis"
	"github.com/aojea/agents.net/kubernetes/pkg/auth"
	"github.com/aojea/agents.net/kubernetes/pkg/catrust"
	"github.com/aojea/agents.net/kubernetes/pkg/metrics"
	"github.com/aojea/agents.net/kubernetes/pkg/params"
	"github.com/aojea/agents.net/kubernetes/pkg/proxyenv"
	"github.com/aojea/agents.net/kubernetes/pkg/store"
	"github.com/aojea/agents.net/kubernetes/pkg/tunnel"
)

const (
	// DefaultDeviceName is the DNS label of the single shared DRAConsumableCapacity
	// device published per node by dra-agents-net (Beta, enabled by default since K8s 1.36).
	DefaultDeviceName = "agents-net"

	// CapacitySandboxes is the consumable capacity key exposed on the per-node
	// agents-net device (default request policy consumes 1 unit per Sandbox claim).
	CapacitySandboxes resourceapi.QualifiedName = "sandboxes"

	// DefaultMaxSandboxes is the fallback per-node consumable sandbox capacity when
	// node status.allocatable.pods cannot be read and --max-sandboxes is unset.
	DefaultMaxSandboxes int64 = 110

	// Tun2ConnectContainerName is the name of the single per-Pod tun2connect native sidecar.
	Tun2ConnectContainerName = apis.Tun2ConnectSidecarName

	containerEgressMountDir  = "/run/agents.net"
	containerIngressMountDir = "/run/agents.net/ingress"

	// maxNRIAttempts caps consecutive NRI connection failures before exiting.
	// The containerd/nri v0.12.5 stub cannot reconnect after a failed registration.
	maxNRIAttempts    = 5
	nriInitialBackoff = time.Second
	nriMaxBackoff     = 16 * time.Second

	stopGracePeriod     = 10 * time.Second
	stopPollInterval    = 5 * time.Second
	stopFallbackTimeout = 5 * time.Minute

	methodPrepareResourceClaims   = "PrepareResourceClaims"
	methodUnprepareResourceClaims = "UnprepareResourceClaims"
	methodSynchronize             = "Synchronize"
	methodRunPodSandbox           = "RunPodSandbox"
	methodCreateContainer         = "CreateContainer"
	methodStopPodSandbox          = "StopPodSandbox"
	methodRemovePodSandbox        = "RemovePodSandbox"

	eventReasonPlumbingMissing = "AgentsNetPlumbingMissing"
	eventReasonPrepareFailed   = "AgentsNetPrepareFailed"
)

// NetNSManager abstracts Pod network namespace inspection, route flushing,
// tc clsact NIC blocking, and goroutine-safe cross-netns listener binding (socketat).
type NetNSManager interface {
	VerifyLoopbackOnly(netnsPath string, allowTunTap bool) error
	FlushNonLoopbackRoutes(netnsPath string) error
	HasNonLoopbackRoutes(netnsPath string) (bool, error)
	BlockNonLoopbackNICs(netnsPath string, allowTunTap bool) error
	VerifyNonLoopbackNICsBlocked(netnsPath string, allowTunTap bool) (bool, error)
	ListenAt(netnsPath, network, address string) (net.Listener, error)
}

// IngressRevoker revokes and re-allows host ingress connections across a Pod's lifecycle.
type IngressRevoker interface {
	Revoke(podUID types.UID)
	Allow(podUID types.UID)
}

// pluginHelper is the internal contract we need from *kubeletplugin.Helper,
// allowing unit tests to inject a lightweight fake.
type pluginHelper interface {
	PublishResources(context.Context, resourceslice.DriverResources) error
	Stop()
	RegistrationStatus() *registerapi.RegistrationStatus
}

// Config configures the per-node Driver.
type Config struct {
	DriverName           string
	NodeName             string
	NodeIP               string
	KubeClient           kubernetes.Interface
	Store                *store.PodConfigStore
	Tunnel               *tunnel.Manager
	Ingress              IngressRevoker
	CAMaterializer       *catrust.Materializer
	NetNS                NetNSManager
	EventRecorder        record.EventRecorder
	MaxSandboxes         int64
	KubeletRootDir       string
	NRISocketPath        string
	NRIPluginIdx         string
	IngressBridgeAddr    string
	IngressAdvertiseAddr string
	IngressTLS           bool
	IngressServerName    string
	OnNRIFatal           func(error)
}

// Driver combines a DRA kubeletplugin.DRAPlugin (slow path), an NRI runtime
// plugin (fast path, zero CDI files), socketat Pod-loopback listeners for ExplicitProxy,
// and a node-scoped core/v1 Pod informer for ServiceAccount and warm-pool claim sync.
type Driver struct {
	driverName           string
	nodeName             string
	nodeIP               string
	kubeClient           kubernetes.Interface
	store                *store.PodConfigStore
	tunnel               *tunnel.Manager
	ingress              IngressRevoker
	caMat                *catrust.Materializer
	netns                NetNSManager
	maxSandboxes         int64
	kubeletRootDir       string
	nriSocketPath        string
	nriPluginIdx         string
	ingressAddr          string
	ingressAdvertiseAddr string
	ingressTLS           bool
	ingressServerName    string

	draPlugin        pluginHelper
	nriMu            sync.Mutex
	nriPlugin        stub.Stub
	nriStubFactory   func(sessionID uint64) (stub.Stub, error)
	nriSessionID     uint64
	nriSyncSucceeded bool
	nriWG            sync.WaitGroup
	podListerMu      sync.RWMutex
	podLister        corev1listers.PodLister
	clock            clock.WithTicker
	eventBroadcaster record.EventBroadcaster
	eventRecorder    record.EventRecorder
	onNRIFatal       func(error)

	// draRegistered is true from kubelet registration until Stop.
	draRegistered atomic.Bool
	// nriConnected is true while the current NRI session has completed Synchronize
	// and has not disconnected.
	nriConnected atomic.Bool

	unhealthy atomic.Bool
	statusWG  sync.WaitGroup
}

var _ kubeletplugin.DRAPlugin = &Driver{}

// New creates a Driver without starting network, NRI, or kubelet listeners.
// Callers may wire CheckDRA and CheckNRI into /healthz before calling Start.
func New(cfg Config) (*Driver, error) {
	if cfg.NodeName == "" {
		return nil, errors.New("node name is required")
	}
	if cfg.Store == nil {
		return nil, errors.New("store is required")
	}
	if cfg.Tunnel == nil {
		return nil, errors.New("tunnel manager is required")
	}
	driverName := cfg.DriverName
	if driverName == "" {
		driverName = apis.DriverName
	}
	kubeletRoot := cfg.KubeletRootDir
	if kubeletRoot == "" {
		kubeletRoot = auth.DefaultKubeletRootDir
	}
	nriIdx := cfg.NRIPluginIdx
	if nriIdx == "" {
		nriIdx = "00"
	}
	maxSandboxes := max(cfg.MaxSandboxes, 0)
	netnsMgr := cfg.NetNS
	if netnsMgr == nil {
		netnsMgr = NewLinuxNetNSManager()
	}
	caMat := cfg.CAMaterializer
	if caMat == nil {
		caMat = catrust.NewMaterializer(cfg.KubeClient, "")
	}

	var broadcaster record.EventBroadcaster
	recorder := cfg.EventRecorder
	if recorder == nil && cfg.KubeClient != nil {
		broadcaster = record.NewBroadcaster()
		broadcaster.StartStructuredLogging(0)
		broadcaster.StartRecordingToSink(&v1core.EventSinkImpl{Interface: cfg.KubeClient.CoreV1().Events("")})
		recorder = broadcaster.NewRecorder(scheme.Scheme, corev1.EventSource{Component: driverName, Host: cfg.NodeName})
	}

	onNRIFatal := cfg.OnNRIFatal
	if onNRIFatal == nil {
		onNRIFatal = func(err error) {
			klog.Fatalf("%v", err)
		}
	}

	return &Driver{
		driverName:           driverName,
		nodeName:             cfg.NodeName,
		nodeIP:               cfg.NodeIP,
		kubeClient:           cfg.KubeClient,
		store:                cfg.Store,
		tunnel:               cfg.Tunnel,
		ingress:              cfg.Ingress,
		caMat:                caMat,
		netns:                netnsMgr,
		maxSandboxes:         maxSandboxes,
		kubeletRootDir:       kubeletRoot,
		nriSocketPath:        cfg.NRISocketPath,
		nriPluginIdx:         nriIdx,
		ingressAddr:          cfg.IngressBridgeAddr,
		ingressAdvertiseAddr: cfg.IngressAdvertiseAddr,
		ingressTLS:           cfg.IngressTLS,
		ingressServerName:    cfg.IngressServerName,
		clock:                clock.RealClock{},
		eventBroadcaster:     broadcaster,
		eventRecorder:        recorder,
		onNRIFatal:           onNRIFatal,
	}, nil
}

func (d *Driver) newNRIStub(sessionID uint64) (stub.Stub, error) {
	nriOpts := []stub.Option{
		stub.WithPluginName(d.driverName),
		stub.WithPluginIdx(d.nriPluginIdx),
		// Fail the pod/container request if the plugin times out or loses its
		// connection, and keep the plugin connected on timeout so containerd
		// never silently starts an unconfined sandbox without agents.net plumbing.
		stub.WithFailurePolicy(&nriapi.FailurePolicy{
			FailRequest:   true,
			KeepConnected: true,
		}),
		stub.WithOnClose(func() {
			d.nriMu.Lock()
			if d.nriSessionID == sessionID {
				d.nriConnected.Store(false)
			}
			d.nriMu.Unlock()
			metrics.NRIPluginDisconnectsTotal.Inc()
			klog.InfoS("NRI plugin connection closed", "driver", d.driverName, "sessionID", sessionID)
		}),
	}
	if d.nriSocketPath != "" {
		nriOpts = append(nriOpts, stub.WithSocketPath(d.nriSocketPath))
	}
	return stub.New(d, nriOpts...)
}

// Start connects the NRI plugin FIRST, then starts and registers the DRA kubelet
// plugin, publishes the node's GA resource.k8s.io/v1 ResourceSlice, and starts the
// node-scoped Pod identity informer.
//
// Connecting NRI before DRA starts avoids a startup race: once DRA registers,
// kubelet can create sandboxes for already-prepared claims without calling
// NodePrepareResources again, so the container runtime must already have the
// NRI plugin connected.
func (d *Driver) Start(ctx context.Context) error {
	d.resolveNodeInfo(ctx)

	d.nriMu.Lock()
	if d.nriPlugin == nil && d.nriStubFactory == nil {
		d.nriStubFactory = d.newNRIStub
	}
	d.nriMu.Unlock()

	d.nriWG.Go(func() {
		if err := d.runNRI(ctx); err != nil && d.onNRIFatal != nil {
			d.onNRIFatal(err)
		}
	})

	// Wait for NRI to connect before starting the DRA kubelet plugin.
	if err := wait.PollUntilContextTimeout(ctx, 100*time.Millisecond, 30*time.Second, true, func(context.Context) (bool, error) {
		return d.nriConnected.Load(), nil
	}); err != nil {
		return fmt.Errorf("NRI plugin is not connected: %w", err)
	}

	pluginDir := filepath.Join(d.kubeletRootDir, "plugins", d.driverName)
	if err := os.MkdirAll(pluginDir, 0o750); err != nil {
		return fmt.Errorf("create DRA plugin dir %q: %w", pluginDir, err)
	}

	if d.draPlugin == nil {
		draHelper, err := kubeletplugin.Start(
			ctx,
			d,
			kubeletplugin.KubeClient(d.kubeClient),
			kubeletplugin.NodeName(d.nodeName),
			kubeletplugin.DriverName(d.driverName),
			kubeletplugin.RegistrarDirectoryPath(filepath.Join(d.kubeletRootDir, "plugins_registry")),
			kubeletplugin.PluginDataDirectoryPath(pluginDir),
			kubeletplugin.HealthService(false),
		)
		if err != nil {
			return fmt.Errorf("start DRA kubeletplugin: %w", err)
		}
		d.draPlugin = draHelper
	}

	if err := wait.PollUntilContextTimeout(ctx, time.Second, 30*time.Second, true, func(context.Context) (bool, error) {
		status := d.draPlugin.RegistrationStatus()
		if status == nil {
			return false, nil
		}
		return status.PluginRegistered, nil
	}); err != nil {
		d.draPlugin.Stop()
		return fmt.Errorf("wait for DRA kubelet registration: %w", err)
	}
	d.draRegistered.Store(true)

	if err := d.PublishResourceSlice(ctx); err != nil {
		d.draRegistered.Store(false)
		d.draPlugin.Stop()
		return fmt.Errorf("publish initial ResourceSlice: %w", err)
	}

	regSock := filepath.Join(d.kubeletRootDir, "plugins_registry", d.driverName+"-reg.sock")
	klog.InfoS("dra-agents-net DRA+NRI driver started",
		"driver", d.driverName,
		"node", d.nodeName,
		"maxSandboxes", d.maxSandboxes,
		"registrationSocket", regSock,
	)

	if d.kubeClient != nil {
		d.startNodePodInformer(ctx)
	}

	return nil
}

// runNRI keeps the NRI plugin connected to the container runtime until ctx is
// done. It constructs a fresh stub.Stub on every attempt (working around
// containerd/nri's non-reusable stub state after failed registration), waits
// with exponential backoff (1s..16s), and resets the failure streak only after
// Synchronize succeeds. After maxNRIAttempts consecutive failures it returns an
// error so the caller exits cleanly and kubelet restarts the Pod.
func (d *Driver) runNRI(ctx context.Context) error {
	failures := 0
	backoff := nriInitialBackoff
	for {
		d.nriMu.Lock()
		d.nriSessionID++
		sid := d.nriSessionID
		d.nriSyncSucceeded = false
		d.nriConnected.Store(false)
		factory := d.nriStubFactory
		nriStub := d.nriPlugin
		d.nriMu.Unlock()

		var err error
		if factory != nil {
			nriStub, err = factory(sid)
			if err == nil {
				d.nriMu.Lock()
				d.nriPlugin = nriStub
				d.nriMu.Unlock()
			}
		}
		if err == nil {
			err = nriStub.Start(ctx)
		}
		if err == nil {
			nriStub.Wait()
			d.nriMu.Lock()
			d.nriConnected.Store(false)
			synced := d.nriSyncSucceeded
			if factory != nil && d.nriPlugin == nriStub {
				d.nriPlugin = nil
			}
			d.nriMu.Unlock()
			if synced {
				failures, backoff = 0, nriInitialBackoff
			} else {
				failures++
				err = errors.New("NRI session closed before Synchronize completed")
				klog.ErrorS(err, "NRI plugin session closed early", "driver", d.driverName, "consecutiveFailures", failures)
			}
		} else {
			d.nriMu.Lock()
			d.nriConnected.Store(false)
			if factory != nil && d.nriPlugin == nriStub {
				d.nriPlugin = nil
			}
			d.nriMu.Unlock()
			failures++
			klog.ErrorS(err, "NRI plugin connection failed", "driver", d.driverName, "consecutiveFailures", failures)
		}
		if ctx.Err() != nil {
			return nil
		}
		if failures >= maxNRIAttempts {
			return fmt.Errorf("NRI plugin failed %d consecutive times to connect: %w", maxNRIAttempts, err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-d.clock.After(backoff):
		}
		backoff = min(backoff*2, nriMaxBackoff)
		metrics.NRIPluginReconnectAttemptsTotal.Inc()
		klog.InfoS("restarting NRI plugin", "driver", d.driverName, "consecutiveFailures", failures, "maxAttempts", maxNRIAttempts)
	}
}

// CheckDRA returns an error if the DRA plugin is not registered with kubelet.
func (d *Driver) CheckDRA() error {
	if !d.draRegistered.Load() {
		return errors.New("DRA plugin is not registered with kubelet")
	}
	return nil
}

// CheckNRI returns an error if the NRI plugin has no connection to the container runtime.
func (d *Driver) CheckNRI() error {
	if !d.nriConnected.Load() {
		return errors.New("NRI plugin is not connected to the container runtime")
	}
	return nil
}

// Stop coordinates graceful shutdown to prevent prepared Pods from starting
// without their agents.net plumbing during DaemonSet restarts or upgrades:
//  1. Stop the DRA plugin so kubelet cannot prepare new claims.
//  2. Wait until every prepared Pod has passed stopGracePeriod since its last
//     NRI hook (or stopFallbackTimeout elapses) so in-flight sandboxes and
//     containers finish RunPodSandbox / CreateContainer while NRI is connected.
//  3. Wait for in-flight status writes, cancel ctxCancel, and stop NRI.
func (d *Driver) Stop(ctxCancel context.CancelFunc) {
	klog.InfoS("stopping dra-agents-net driver", "driver", d.driverName)

	// Step 1: Halt DRA so no new ResourceClaims are prepared.
	d.draRegistered.Store(false)
	if d.draPlugin != nil {
		d.draPlugin.Stop()
	}

	// Step 2: Drain prepared Pods currently initializing through NRI.
	ticker := d.clock.NewTicker(stopPollInterval)
	defer ticker.Stop()

	defaultPreviousActivity := d.clock.Now()
	for {
		if d.clock.Since(defaultPreviousActivity) >= stopFallbackTimeout {
			klog.InfoS("shutdown fallback timeout reached; stopping NRI despite pending pods", "timeout", stopFallbackTimeout)
			break
		}

		activities := d.store.GetPodNRIActivities()
		if len(activities) == 0 {
			break
		}

		waitingForGrace := 0
		for _, previousActivity := range activities {
			if previousActivity.IsZero() {
				previousActivity = defaultPreviousActivity
			}
			if d.clock.Since(previousActivity) < stopGracePeriod {
				waitingForGrace++
			}
		}
		if waitingForGrace == 0 {
			break
		}

		klog.InfoS("waiting for prepared pods to finish NRI initialization before shutdown",
			"preparedPods", len(activities), "inGracePeriod", waitingForGrace)
		<-ticker.C()
	}

	// Step 3: Wait for status writes, cancel context, stop NRI, and flush events.
	d.statusWG.Wait()
	if ctxCancel != nil {
		ctxCancel()
	}
	d.nriMu.Lock()
	nriPlugin := d.nriPlugin
	d.nriConnected.Store(false)
	d.nriMu.Unlock()
	if nriPlugin != nil {
		nriPlugin.Stop()
	}
	d.nriWG.Wait()
	if d.eventBroadcaster != nil {
		d.eventBroadcaster.Shutdown()
	}
	klog.InfoS("dra-agents-net driver stopped", "driver", d.driverName)
}

func (d *Driver) startNodePodInformer(ctx context.Context) {
	fieldSel := fields.OneTermEqualSelector("spec.nodeName", d.nodeName).String()
	factory := informers.NewSharedInformerFactoryWithOptions(
		d.kubeClient,
		30*time.Second,
		informers.WithTweakListOptions(func(opts *metav1.ListOptions) {
			opts.FieldSelector = fieldSel
		}),
	)
	podsInformer := factory.Core().V1().Pods()
	podInf := podsInformer.Informer()
	_, _ = podInf.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj any) {
			if pod, ok := obj.(*corev1.Pod); ok {
				d.SyncPod(pod)
			}
		},
		UpdateFunc: func(_, newObj any) {
			if pod, ok := newObj.(*corev1.Pod); ok {
				d.SyncPod(pod)
			}
		},
	})
	d.podListerMu.Lock()
	d.podLister = podsInformer.Lister()
	d.podListerMu.Unlock()

	factory.Start(ctx.Done())
	cache.WaitForCacheSync(ctx.Done(), podInf.HasSynced)
}

func (d *Driver) lookupPod(namespace, name string) *corev1.Pod {
	d.podListerMu.RLock()
	lister := d.podLister
	d.podListerMu.RUnlock()
	if lister == nil || namespace == "" || name == "" {
		return nil
	}
	pod, err := lister.Pods(namespace).Get(name)
	if err != nil {
		return nil
	}
	return pod
}

// SyncPod updates attested Pod metadata (name, namespace, ServiceAccount) for a
// tracked Pod on this node from the node-scoped Pod informer.
func (d *Driver) SyncPod(pod *corev1.Pod) {
	if pod == nil {
		return
	}
	cfg, ok := d.store.Get(pod.UID)
	if !ok {
		return
	}
	metaChanged := cfg.PodName != pod.Name ||
		cfg.PodNamespace != pod.Namespace ||
		cfg.ServiceAccount != pod.Spec.ServiceAccountName

	if !metaChanged {
		return
	}
	if err := d.store.UpdateIdentity(pod.UID, pod.Name, pod.Namespace, pod.Spec.ServiceAccountName); err != nil {
		klog.ErrorS(err, "failed to checkpoint updated Pod identity", "podUID", pod.UID)
	}
	d.tunnel.UpdateIdentity(pod.UID, d.buildWorkloadIdentity(pod.UID, cfg.SandboxID, pod.Name, pod.Namespace, pod.Spec.ServiceAccountName, cfg.Parameters.Custom), false)
}

// resolveNodeInfo discovers the node's consumable sandbox capacity and routable IP
// address from the Node object when not explicitly configured via flags/env.
func (d *Driver) resolveNodeInfo(ctx context.Context) {
	needSlots := d.maxSandboxes <= 0
	needIP := d.nodeIP == ""
	if !needSlots && !needIP {
		return
	}
	if d.kubeClient != nil {
		getCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		node, err := d.kubeClient.CoreV1().Nodes().Get(getCtx, d.nodeName, metav1.GetOptions{})
		if err != nil {
			klog.V(2).InfoS("failed to read node metadata; falling back to defaults",
				"node", d.nodeName, "defaultMaxSandboxes", DefaultMaxSandboxes, "err", err)
		} else {
			if needSlots {
				if podsQty := node.Status.Allocatable.Pods(); podsQty != nil && podsQty.Value() > 0 {
					d.maxSandboxes = podsQty.Value()
				}
			}
			if needIP {
				d.nodeIP = selectNodeIP(node.Status.Addresses)
			}
		}
	}
	if d.maxSandboxes <= 0 {
		d.maxSandboxes = DefaultMaxSandboxes
	}
}

func selectNodeIP(addrs []corev1.NodeAddress) string {
	var external string
	for _, a := range addrs {
		if a.Address == "" {
			continue
		}
		switch a.Type {
		case corev1.NodeInternalIP:
			return a.Address
		case corev1.NodeExternalIP:
			if external == "" {
				external = a.Address
			}
		}
	}
	return external
}

// resolveIngressEndpoint returns the dialable host:port published in
// ResourceClaim.status.devices[].data.ingress.endpoint, or empty if ingress
// is disabled or no routable node address is known.
func (d *Driver) resolveIngressEndpoint() string {
	if d.ingressAdvertiseAddr != "" {
		return d.ingressAdvertiseAddr
	}
	if d.ingressAddr == "" {
		return ""
	}
	host, port, err := net.SplitHostPort(d.ingressAddr)
	if err != nil || port == "" {
		return ""
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		if d.nodeIP == "" {
			return ""
		}
		return net.JoinHostPort(d.nodeIP, port)
	}
	return d.ingressAddr
}

// BuildResourceSlice builds a single resource.k8s.io/v1 ResourceSlice per node containing
// one shared DRAConsumableCapacity device (allowMultipleAllocations: true) whose sandboxes
// capacity tracks node allocatable pods (or --max-sandboxes). Setting requestPolicy.default
// to 1 lets standard ResourceClaims without explicit capacity requests consume 1 unit each.
func (d *Driver) BuildResourceSlice() resourceslice.DriverResources {
	if d.unhealthy.Load() {
		return resourceslice.DriverResources{
			Pools: map[string]resourceslice.Pool{
				d.nodeName: {},
			},
		}
	}

	total := d.maxSandboxes
	if total <= 0 {
		total = DefaultMaxSandboxes
	}

	one := resource.MustParse("1")
	return resourceslice.DriverResources{
		Pools: map[string]resourceslice.Pool{
			d.nodeName: {
				Slices: []resourceslice.Slice{
					{
						Devices: []resourceapi.Device{
							{
								Name:                     DefaultDeviceName,
								AllowMultipleAllocations: new(true),
								Capacity: map[resourceapi.QualifiedName]resourceapi.DeviceCapacity{
									CapacitySandboxes: {
										Value: *resource.NewQuantity(total, resource.DecimalSI),
										RequestPolicy: &resourceapi.CapacityRequestPolicy{
											Default:     &one,
											ValidValues: []resource.Quantity{one},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

// PublishResourceSlice publishes the node's ResourceSlice(s) via kubeletplugin
// and updates publication observability gauges.
func (d *Driver) PublishResourceSlice(ctx context.Context) error {
	resources := d.BuildResourceSlice()
	if d.draPlugin == nil {
		return nil
	}
	if err := d.draPlugin.PublishResources(ctx, resources); err != nil {
		return err
	}
	var count int
	for _, pool := range resources.Pools {
		for _, sl := range pool.Slices {
			count += len(sl.Devices)
		}
	}
	metrics.PublishedDevicesTotal.Set(float64(count))
	metrics.LastPublishedTimeSeconds.Set(float64(d.clock.Now().Unix()))
	return nil
}

// SetHealthy toggles whether this node advertises available dra-agents-net slots.
// When unhealthy, slices are withdrawn so new Pods do not schedule here without
// requiring the DRADeviceTaints feature gate; existing Pods continue running.
func (d *Driver) SetHealthy(ctx context.Context, healthy bool) error {
	prev := !d.unhealthy.Load()
	d.unhealthy.Store(!healthy)
	if prev == healthy {
		return nil
	}
	return d.PublishResourceSlice(ctx)
}

// PrepareResourceClaims runs on the DRA slow path BEFORE CRI RunPodSandbox.
// It refuses non-empty batches while the NRI plugin is disconnected so kubelet
// cannot proceed to create an unconfined Pod sandbox.
func (d *Driver) PrepareResourceClaims(ctx context.Context, claims []*resourceapi.ResourceClaim) (map[types.UID]kubeletplugin.PrepareResult, error) {
	if len(claims) == 0 {
		return nil, nil
	}
	start := time.Now()
	defer func() {
		metrics.DRAPluginRequestsLatencySeconds.WithLabelValues(methodPrepareResourceClaims).Observe(time.Since(start).Seconds())
	}()

	if !d.nriConnected.Load() {
		metrics.DRAPluginRequestsTotal.WithLabelValues(methodPrepareResourceClaims, metrics.StatusFailed).Inc()
		return nil, fmt.Errorf("NRI plugin %s is not connected to container runtime", d.driverName)
	}

	results := make(map[types.UID]kubeletplugin.PrepareResult, len(claims))
	for _, claim := range claims {
		res, status := d.prepareResourceClaim(ctx, claim)
		metrics.DRAPluginRequestsTotal.WithLabelValues(methodPrepareResourceClaims, status).Inc()
		if res.Err != nil && d.eventRecorder != nil {
			d.eventRecorder.Eventf(claim, corev1.EventTypeWarning, eventReasonPrepareFailed,
				"failed to prepare agents.net claim %s/%s: %v", claim.Namespace, claim.Name, res.Err)
		}
		results[claim.UID] = res
	}
	return results, nil
}

func (d *Driver) prepareResourceClaim(ctx context.Context, claim *resourceapi.ResourceClaim) (kubeletplugin.PrepareResult, string) {
	if claim.Status.Allocation == nil {
		return kubeletplugin.PrepareResult{Err: fmt.Errorf("claim %s/%s has no allocation", claim.Namespace, claim.Name)}, metrics.StatusFailed
	}
	if len(claim.Status.ReservedFor) == 0 {
		return kubeletplugin.PrepareResult{
			Err: fmt.Errorf("claim %s/%s has empty status.reservedFor; refusing to prepare without Pod identity", claim.Namespace, claim.Name),
		}, metrics.StatusFailed
	}
	if len(claim.Status.ReservedFor) > 1 {
		return kubeletplugin.PrepareResult{
			Err: fmt.Errorf("dra-agents-net supports one pod per claim, got %d", len(claim.Status.ReservedFor)),
		}, metrics.StatusFailed
	}
	reserved := claim.Status.ReservedFor[0]
	if reserved.Resource != "pods" || reserved.APIGroup != "" {
		return kubeletplugin.PrepareResult{
			Err: fmt.Errorf("dra-agents-net supports Pods only, got %s/%s", reserved.APIGroup, reserved.Resource),
		}, metrics.StatusFailed
	}
	podUID := reserved.UID
	if err := auth.ValidatePodUID(podUID); err != nil {
		return kubeletplugin.PrepareResult{Err: fmt.Errorf("invalid Pod UID in claim %s/%s: %w", claim.Namespace, claim.Name, err)}, metrics.StatusFailed
	}

	var matchedResult *resourceapi.DeviceRequestAllocationResult
	for i := range claim.Status.Allocation.Devices.Results {
		res := &claim.Status.Allocation.Devices.Results[i]
		if res.Driver == d.driverName {
			matchedResult = res
			break
		}
	}
	if matchedResult == nil {
		return kubeletplugin.PrepareResult{}, metrics.StatusNoop
	}

	netParams, err := params.DecodeForRequest(claim.Status.Allocation.Devices.Config, d.driverName, matchedResult.Request)
	if err != nil {
		return kubeletplugin.PrepareResult{Err: fmt.Errorf("decode dra-agents-net parameters for claim %s/%s: %w", claim.Namespace, claim.Name, err)}, metrics.StatusFailed
	}

	existing, existed := d.store.Get(podUID)
	serviceAccount := existing.ServiceAccount
	if podObj := d.lookupPod(claim.Namespace, reserved.Name); podObj != nil && podObj.UID == podUID {
		if podObj.Spec.ServiceAccountName != "" {
			serviceAccount = podObj.Spec.ServiceAccountName
		}
	}

	identity := d.buildWorkloadIdentity(podUID, existing.SandboxID, reserved.Name, claim.Namespace, serviceAccount, netParams.Custom)
	paths, err := d.tunnel.EnsureListener(ctx, podUID, tunnel.ListenerConfig{
		Identity:               identity,
		PolicyEnforcementPoint: netParams.PolicyEnforcementPoint,
		PodCertVolumeName:      netParams.PodCertVolumeName,
		HasIngress:             len(netParams.IngressPorts) > 0,
		MaxConnections:         int(*netParams.MaxConnections),
		IdleTimeoutSeconds:     int(*netParams.IdleTimeoutSeconds),
	})
	if err != nil {
		return kubeletplugin.PrepareResult{Err: fmt.Errorf("start agents.net listener for pod %s: %w", podUID, err)}, metrics.StatusFailed
	}

	caBundle, err := d.caMat.Materialize(ctx, netParams.CATrust, claim.Namespace, filepath.Join(paths.PodRootDir, "ca"))
	if err != nil {
		if !existed {
			_ = d.tunnel.Remove(podUID)
		}
		return kubeletplugin.PrepareResult{Err: fmt.Errorf("materialize Pod CA trust bundle for pod %s: %w", podUID, err)}, metrics.StatusFailed
	}

	shareID := ""
	if matchedResult.ShareID != nil {
		shareID = string(*matchedResult.ShareID)
	}
	podCfg := store.PodConfig{
		PodUID:          podUID,
		PodName:         reserved.Name,
		PodNamespace:    claim.Namespace,
		ServiceAccount:  serviceAccount,
		ClaimUID:        claim.UID,
		ClaimNamespace:  claim.Namespace,
		ClaimName:       claim.Name,
		DeviceName:      matchedResult.Device,
		PoolName:        matchedResult.Pool,
		ShareID:         shareID,
		SandboxID:       existing.SandboxID,
		NetNS:           existing.NetNS,
		Parameters:      netParams,
		SocketPaths:     paths,
		CABundle:        caBundle,
		LastNRIActivity: existing.LastNRIActivity,
	}
	if err := d.store.Upsert(podCfg); err != nil {
		if !existed {
			_ = d.tunnel.Remove(podUID)
		}
		return kubeletplugin.PrepareResult{Err: fmt.Errorf("checkpoint pod config for %s: %w", podUID, err)}, metrics.StatusFailed
	}

	// Return empty CDI devices: NRI CreateContainer injects mounts, CA bundles, and env in memory.
	return kubeletplugin.PrepareResult{}, metrics.StatusSuccess
}

// UnprepareResourceClaims tears down tunnel listeners, host socket/CA dirs, and checkpointed state.
func (d *Driver) UnprepareResourceClaims(_ context.Context, claims []kubeletplugin.NamespacedObject) (map[types.UID]error, error) {
	if len(claims) == 0 {
		return nil, nil
	}
	start := time.Now()
	defer func() {
		metrics.DRAPluginRequestsLatencySeconds.WithLabelValues(methodUnprepareResourceClaims).Observe(time.Since(start).Seconds())
	}()

	results := make(map[types.UID]error, len(claims))
	for _, claim := range claims {
		podCfg, ok := d.store.GetByClaimUID(claim.UID)
		if !ok {
			metrics.DRAPluginRequestsTotal.WithLabelValues(methodUnprepareResourceClaims, metrics.StatusNoop).Inc()
			results[claim.UID] = nil
			continue
		}
		var errs []error
		if d.ingress != nil {
			d.ingress.Revoke(podCfg.PodUID)
		}
		if err := d.tunnel.Remove(podCfg.PodUID); err != nil {
			errs = append(errs, err)
		}
		if err := d.store.Delete(podCfg.PodUID); err != nil {
			errs = append(errs, err)
		} else if d.ingress != nil {
			// Now that podCfg is removed from the store (subsequent requests return 404),
			// clear the revoked marker so the ingress server's revoked map stays bounded.
			d.ingress.Allow(podCfg.PodUID)
		}
		err := errors.Join(errs...)
		if err != nil {
			metrics.DRAPluginRequestsTotal.WithLabelValues(methodUnprepareResourceClaims, metrics.StatusFailed).Inc()
		} else {
			metrics.DRAPluginRequestsTotal.WithLabelValues(methodUnprepareResourceClaims, metrics.StatusSuccess).Inc()
		}
		results[claim.UID] = err
	}
	return results, nil
}

// HandleError logs DRA background errors per kubeletplugin contract.
func (d *Driver) HandleError(ctx context.Context, err error, msg string) {
	if droppedErr, ok := errors.AsType[*resourceslice.DroppedFieldsError](err); ok {
		klog.ErrorS(droppedErr, "kube-apiserver dropped DRAConsumableCapacity fields from ResourceSlice; verify Kubernetes >= 1.36 or enable DRAConsumableCapacity feature gate",
			"driver", d.driverName, "node", d.nodeName)
	}
	runtime.HandleErrorWithContext(ctx, err, msg)
}

// WatchHealthStatus declines kubelet health RPCs when HealthService(false) is used.
func (d *Driver) WatchHealthStatus(_ context.Context, _ chan<- kubeletplugin.DeviceHealthReport) error {
	return kubeletplugin.ErrHealthNotSupported
}

// Synchronize runs on NRI startup and after every NRI reconnection. It inspects
// live running prepared Pods for missing agents.net plumbing or confinement
// (reporting any pod created while NRI was disconnected), restores per-Pod UDS
// and socketat loopback listeners, and reaps orphaned checkpoints.
func (d *Driver) Synchronize(ctx context.Context, pods []*nriapi.PodSandbox, containers []*nriapi.Container) ([]*nriapi.ContainerUpdate, error) {
	start := time.Now()
	defer func() {
		recordNRIMetric(methodSynchronize, metrics.StatusSuccess, start)
	}()

	// A sandbox with a running container is past RunPodSandbox and CreateContainer
	// and is not in teardown, so its agents.net plumbing and isolation must be present.
	runningBySandbox := make(map[string][]*nriapi.Container)
	for _, ctr := range containers {
		if ctr.GetState() == nriapi.ContainerState_CONTAINER_RUNNING {
			runningBySandbox[ctr.GetPodSandboxId()] = append(runningBySandbox[ctr.GetPodSandboxId()], ctr)
		}
	}

	livePods := make(map[types.UID]*nriapi.PodSandbox, len(pods))
	for _, pod := range pods {
		livePods[types.UID(pod.GetUid())] = pod
		if running := runningBySandbox[pod.GetId()]; len(running) > 0 {
			d.reportMissingPlumbing(pod, running)
		}
	}

	for _, uid := range d.store.ListPodUIDs() {
		cfg, ok := d.store.Get(uid)
		if !ok {
			continue
		}
		pod, isLive := livePods[uid]
		if !isLive {
			// Only reap entries whose sandbox previously ran (NetNS != "").
			// A freshly prepared Pod (NetNS == "") may not have reached RunPodSandbox yet.
			if cfg.NetNS == "" {
				continue
			}
			if d.ingress != nil {
				d.ingress.Revoke(uid)
			}
			_ = d.tunnel.Remove(uid)
			if err := d.store.Delete(uid); err == nil && d.ingress != nil {
				d.ingress.Allow(uid)
			}
			continue
		}
		ns := getNetworkNamespace(pod)
		if ns != "" {
			// Pass zero time so Synchronize records SandboxID & NetNS without refreshing LastNRIActivity.
			_ = d.store.UpdateSandbox(uid, pod.GetId(), ns, time.Time{})
		}

		maxConns := int(params.DefaultMaxConnections)
		if cfg.Parameters.MaxConnections != nil {
			maxConns = int(*cfg.Parameters.MaxConnections)
		}
		idleSecs := int(params.DefaultIdleTimeoutSeconds)
		if cfg.Parameters.IdleTimeoutSeconds != nil {
			idleSecs = int(*cfg.Parameters.IdleTimeoutSeconds)
		}

		identity := d.buildWorkloadIdentity(
			uid,
			pod.GetId(),
			cfg.PodName,
			cfg.PodNamespace,
			cfg.ServiceAccount,
			cfg.Parameters.Custom,
		)
		if _, err := d.tunnel.EnsureListener(ctx, uid, tunnel.ListenerConfig{
			Identity:               identity,
			PolicyEnforcementPoint: cfg.Parameters.PolicyEnforcementPoint,
			PodCertVolumeName:      cfg.Parameters.PodCertVolumeName,
			HasIngress:             len(cfg.Parameters.IngressPorts) > 0,
			MaxConnections:         maxConns,
			IdleTimeoutSeconds:     idleSecs,
		}); err != nil {
			klog.ErrorS(err, "failed to restore agents.net listener during Synchronize", "podUID", uid)
			continue
		}

		if cfg.Parameters.EffectiveAdapterMode() == apis.AdapterModeExplicitProxy && ns != "" && !d.tunnel.HasExtraListener(uid) {
			addr := fmt.Sprintf("127.0.0.1:%d", cfg.Parameters.EffectiveProxyPort())
			ln, err := d.netns.ListenAt(ns, "tcp", addr)
			if err != nil {
				klog.ErrorS(err, "failed to restore socketat loopback proxy listener during Synchronize", "podUID", uid, "addr", addr)
			} else if err := d.tunnel.AttachListener(uid, ln); err != nil {
				klog.ErrorS(err, "failed to attach restored loopback listener", "podUID", uid)
			}
		}
	}

	// Mark NRI ready only after Synchronize has reconciled live Pods and
	// restored listeners so DRA registration and PrepareResourceClaims cannot
	// race ahead of the runtime's initial NRI synchronization.
	d.nriMu.Lock()
	d.nriSyncSucceeded = true
	d.nriConnected.Store(true)
	d.nriMu.Unlock()

	return nil, nil
}

// reportMissingPlumbing detects running prepared Pods whose sandbox or
// containers were created while dra-agents-net was not connected to the
// container runtime (for example after SIGKILL, panic, or runtime restart).
// Because kubelet does not call NodePrepareResources again for an already
// prepared claim, dra-agents-net cannot retroactively attach missing container
// mounts; instead it surfaces the gap via a Pod Warning event, an error log,
// and dra_agents_net_pods_missing_plumbing_total.
func (d *Driver) reportMissingPlumbing(pod *nriapi.PodSandbox, runningCtrs []*nriapi.Container) {
	cfg, ok := d.store.Get(types.UID(pod.GetUid()))
	if !ok {
		return
	}

	var missing []string

	// 1. Verify live network namespace isolation.
	ns := getNetworkNamespace(pod)
	if ns == "" {
		missing = append(missing, "pod-netns")
	} else {
		mode := cfg.Parameters.ConfinementMode
		if mode == "" {
			mode = apis.ConfinementModePodNetworkIsolated
		}
		switch mode {
		case apis.ConfinementModePodNetworkIsolated:
			allowTunTap := cfg.Parameters.EffectiveAdapterMode() == apis.AdapterModeTunSidecar
			if err := d.netns.VerifyLoopbackOnly(ns, allowTunTap); err != nil {
				missing = append(missing, "loopback-only-netns")
			}
		case apis.ConfinementModeNetworkPolicyDenyAll:
			if cfg.Parameters.EffectiveNICBlockMode() == apis.NICBlockModeDropAll {
				hasRoutes, err := d.netns.HasNonLoopbackRoutes(ns)
				if err != nil {
					klog.ErrorS(err, "failed to inspect Pod routes during Synchronize",
						"pod", klog.KRef(pod.GetNamespace(), pod.GetName()), "podUID", pod.GetUid())
				} else if hasRoutes {
					missing = append(missing, "non-loopback-routes-unflushed")
				}
				allowTunTap := cfg.Parameters.EffectiveAdapterMode() == apis.AdapterModeTunSidecar
				blocked, err := d.netns.VerifyNonLoopbackNICsBlocked(ns, allowTunTap)
				if err != nil {
					klog.ErrorS(err, "failed to inspect Pod tc NIC drop filters during Synchronize",
						"pod", klog.KRef(pod.GetNamespace(), pod.GetName()), "podUID", pod.GetUid())
				} else if !blocked {
					missing = append(missing, "non-loopback-nics-unblocked")
				}
			}
		}
	}

	// 2. Verify required NRI container mounts on running containers.
	adapterMode := cfg.Parameters.AdapterMode
	if adapterMode == "" {
		adapterMode = apis.AdapterModeExplicitProxy
	}
	switch adapterMode {
	case apis.AdapterModeExplicitProxy:
		for _, ctr := range runningCtrs {
			if !containerHasMount(ctr, containerEgressMountDir) {
				missing = append(missing, "egress-socket-mount")
				break
			}
		}
	case apis.AdapterModeTunSidecar:
		for _, ctr := range runningCtrs {
			if ctr.GetName() != Tun2ConnectContainerName {
				continue
			}
			if !containerHasMount(ctr, containerEgressMountDir) {
				missing = append(missing, "tun2connect-egress-mount")
			}
			if len(cfg.Parameters.IngressPorts) > 0 && !containerHasMount(ctr, containerIngressMountDir) {
				missing = append(missing, "tun2connect-ingress-mount")
			}
		}
	}

	if cfg.CABundle.MergedHostPath != "" && cfg.Parameters.CATrust != nil && cfg.Parameters.CATrust.Mode != apis.CATrustModeNone {
		for _, ctr := range runningCtrs {
			if !containerHasMount(ctr, catrust.ContainerCABundlePath) {
				missing = append(missing, "ca-bundle-mount")
				break
			}
		}
	}

	if len(missing) == 0 {
		return
	}
	slices.Sort(missing)
	metrics.PodsMissingPlumbingTotal.Inc()
	klog.ErrorS(nil, "Pod runs without required agents.net plumbing or isolation",
		"pod", klog.KRef(pod.GetNamespace(), pod.GetName()),
		"podUID", pod.GetUid(),
		"missing", missing,
	)
	if d.eventRecorder != nil {
		d.eventRecorder.Eventf(podObjectRef(pod), corev1.EventTypeWarning, eventReasonPlumbingMissing,
			"pod %s/%s runs without required agents.net plumbing or isolation (%s): its sandbox was created while dra-agents-net was not connected to the container runtime. Delete the pod to recreate it with agents.net isolation.",
			pod.GetNamespace(), pod.GetName(), strings.Join(missing, ", "))
	}
}

func containerHasMount(ctr *nriapi.Container, destination string) bool {
	for _, m := range ctr.GetMounts() {
		if m.GetDestination() == destination {
			return true
		}
	}
	return false
}

func podObjectRef(pod *nriapi.PodSandbox) *corev1.ObjectReference {
	return &corev1.ObjectReference{
		Kind:       "Pod",
		APIVersion: "v1",
		Namespace:  pod.GetNamespace(),
		Name:       pod.GetName(),
		UID:        types.UID(pod.GetUid()),
	}
}

// RunPodSandbox runs synchronously once per Pod BEFORE any container is created or started.
// Under PodNetworkIsolated it verifies the Pod netns has only loopback; under NetworkPolicyDenyAll
// it flushes routes on non-loopback interfaces (eth0) so tun0 owns 0.0.0.0/0 and ::/0 cleanly.
// Under ExplicitProxy it also binds 127.0.0.1:<port> inside the Pod netns via socketat so every
// language HTTP client can reach the agents.net boundary over loopback without a sidecar.
func (d *Driver) RunPodSandbox(_ context.Context, pod *nriapi.PodSandbox) error {
	start := time.Now()
	status := metrics.StatusNoop
	defer func() {
		recordNRIMetric(methodRunPodSandbox, status, start)
	}()

	podUID := types.UID(pod.GetUid())
	cfg, ok := d.store.Get(podUID)
	if !ok {
		return nil
	}

	ns := getNetworkNamespace(pod)
	if ns == "" {
		status = metrics.StatusFailed
		return fmt.Errorf("dra-agents-net forbids hostNetwork pods (%s/%s)", pod.GetNamespace(), pod.GetName())
	}

	mode := cfg.Parameters.ConfinementMode
	if mode == "" {
		mode = apis.ConfinementModePodNetworkIsolated
	}

	switch mode {
	case apis.ConfinementModePodNetworkIsolated:
		if err := d.netns.VerifyLoopbackOnly(ns, false); err != nil {
			status = metrics.StatusFailed
			return fmt.Errorf("PodNetworkIsolated check failed for pod %s/%s: %w", pod.GetNamespace(), pod.GetName(), err)
		}
	case apis.ConfinementModeNetworkPolicyDenyAll:
		// Under nicBlockMode=Disabled, defer eth0 isolation to CNI NetworkPolicy
		// so host-to-Pod kubelet probes and CNI drop visibility keep working.
		if cfg.Parameters.EffectiveNICBlockMode() == apis.NICBlockModeDropAll {
			if err := d.netns.FlushNonLoopbackRoutes(ns); err != nil {
				status = metrics.StatusFailed
				return fmt.Errorf("NetworkPolicyDenyAll route flush failed for pod %s/%s: %w", pod.GetNamespace(), pod.GetName(), err)
			}
			allowTunTap := cfg.Parameters.EffectiveAdapterMode() == apis.AdapterModeTunSidecar
			if err := d.netns.BlockNonLoopbackNICs(ns, allowTunTap); err != nil {
				status = metrics.StatusFailed
				return fmt.Errorf("NetworkPolicyDenyAll tc NIC blocking failed for pod %s/%s: %w", pod.GetNamespace(), pod.GetName(), err)
			}
		}
	default:
		status = metrics.StatusFailed
		return fmt.Errorf("unsupported confinementMode %q for pod %s/%s", mode, pod.GetNamespace(), pod.GetName())
	}

	// Re-arm the tunnel and ingress state in case kubelet is recreating the PodSandbox
	// after an earlier failed or stopped sandbox instance sharing the same DRA claim.
	d.tunnel.Rearm(podUID)
	if d.ingress != nil {
		d.ingress.Allow(podUID)
	}

	if cfg.Parameters.EffectiveAdapterMode() == apis.AdapterModeExplicitProxy {
		addr := fmt.Sprintf("127.0.0.1:%d", cfg.Parameters.EffectiveProxyPort())
		ln, err := d.netns.ListenAt(ns, "tcp", addr)
		if err != nil {
			status = metrics.StatusFailed
			return fmt.Errorf("bind ExplicitProxy loopback listener %s in pod %s/%s via socketat: %w", addr, pod.GetNamespace(), pod.GetName(), err)
		}
		if err := d.tunnel.AttachListener(podUID, ln); err != nil {
			status = metrics.StatusFailed
			return fmt.Errorf("attach ExplicitProxy loopback listener for pod %s/%s: %w", pod.GetNamespace(), pod.GetName(), err)
		}
	}

	if err := d.store.UpdateSandbox(podUID, pod.GetId(), ns, d.clock.Now().UTC()); err != nil {
		status = metrics.StatusFailed
		return fmt.Errorf("record pod netns: %w", err)
	}
	cfg.SandboxID = pod.GetId()
	cfg.NetNS = ns

	_ = d.store.UpdateIdentity(podUID, pod.GetName(), pod.GetNamespace(), cfg.ServiceAccount)
	d.tunnel.UpdateIdentity(podUID, d.buildWorkloadIdentity(podUID, cfg.SandboxID, pod.GetName(), pod.GetNamespace(), cfg.ServiceAccount, cfg.Parameters.Custom), false)

	d.reportResourceClaimDeviceStatusAsync(cfg, true)
	status = metrics.StatusSuccess
	return nil
}

// CreateContainer runs per container in the Pod and injects mounts, /dev/net/tun, Pod CA
// certificates, and language-specific proxy/CA environment variables in memory via
// ContainerAdjustment with zero CDI files.
func (d *Driver) CreateContainer(_ context.Context, pod *nriapi.PodSandbox, ctr *nriapi.Container) (*nriapi.ContainerAdjustment, []*nriapi.ContainerUpdate, error) {
	start := time.Now()
	status := metrics.StatusNoop
	defer func() {
		recordNRIMetric(methodCreateContainer, status, start)
	}()

	podUID := types.UID(pod.GetUid())
	cfg, ok := d.store.Get(podUID)
	if !ok {
		return nil, nil, nil
	}
	d.store.TouchNRIActivity(podUID, d.clock.Now().UTC())

	adj := &nriapi.ContainerAdjustment{}
	changed := false
	desiredEnv := make(map[string]string)
	var javaToolOpts string

	adapterMode := cfg.Parameters.AdapterMode
	if adapterMode == "" {
		adapterMode = apis.AdapterModeExplicitProxy
	}

	switch adapterMode {
	case apis.AdapterModeTunSidecar:
		if ctr.GetName() == Tun2ConnectContainerName {
			changed = true
			adj.AddMount(&nriapi.Mount{
				Destination: containerEgressMountDir,
				Source:      cfg.SocketPaths.EgressDir,
				Type:        "bind",
				Options:     []string{"rbind", "ro"},
			})
			desiredEnv["AGENTS_NET_EGRESS_SOCKET"] = filepath.Join(containerEgressMountDir, tunnel.EgressSocketName)
			if len(cfg.Parameters.IngressPorts) > 0 {
				adj.AddMount(&nriapi.Mount{
					Destination: containerIngressMountDir,
					Source:      cfg.SocketPaths.IngressDir,
					Type:        "bind",
					Options:     []string{"rbind", "rw"},
				})
				desiredEnv["AGENTS_NET_INGRESS_SOCKET"] = filepath.Join(containerIngressMountDir, tunnel.IngressSocketName)
				desiredEnv["AGENTS_NET_INGRESS_PORTS"] = formatIngressPorts(cfg.Parameters.IngressPorts)
			}
			if cfg.Parameters.ConfinementMode == apis.ConfinementModeNetworkPolicyDenyAll {
				desiredEnv["AGENTS_NET_COMPAT_ISOLATED"] = "1"
			}
			adj.AddDevice(&nriapi.LinuxDevice{
				Path:  "/dev/net/tun",
				Type:  "c",
				Major: 10,
				Minor: 200,
			})
		}

	case apis.AdapterModeExplicitProxy:
		changed = true
		adj.AddMount(&nriapi.Mount{
			Destination: containerEgressMountDir,
			Source:      cfg.SocketPaths.EgressDir,
			Type:        "bind",
			Options:     []string{"rbind", "ro"},
		})
		egressSock := filepath.Join(containerEgressMountDir, tunnel.EgressSocketName)
		var extraNoProxy []string
		if cfg.Parameters.Proxy != nil {
			extraNoProxy = cfg.Parameters.Proxy.NoProxy
		}
		pVars, jOpts := proxyenv.ExplicitProxyEnv(egressSock, cfg.Parameters.EffectiveProxyPort(), extraNoProxy)
		maps.Copy(desiredEnv, pVars)
		javaToolOpts = jOpts
	}

	// Advertise the primary pinned ingress port to workload containers per agents.net ingress.md §1.
	if len(cfg.Parameters.IngressPorts) > 0 && ctr.GetName() != Tun2ConnectContainerName {
		desiredEnv["AGENT_INGRESS_PORT"] = strconv.FormatInt(int64(cfg.Parameters.IngressPorts[0].Port), 10)
	}

	// Inject materialized Pod CA bundles into EVERY container in the Pod per agents.net Section 2.3.B.
	if cfg.CABundle.MergedHostPath != "" && cfg.Parameters.CATrust != nil && cfg.Parameters.CATrust.Mode != apis.CATrustModeNone {
		changed = true
		adj.AddMount(&nriapi.Mount{
			Destination: catrust.ContainerCABundlePath,
			Source:      cfg.CABundle.MergedHostPath,
			Type:        "bind",
			Options:     []string{"rbind", "ro"},
		})
		if cfg.CABundle.ExtraHostPath != "" {
			adj.AddMount(&nriapi.Mount{
				Destination: catrust.ContainerExtraCAPath,
				Source:      cfg.CABundle.ExtraHostPath,
				Type:        "bind",
				Options:     []string{"rbind", "ro"},
			})
		}
		caMode := cfg.Parameters.CATrust.Mode
		if caMode == "" || caMode == apis.CATrustModeInjectEnv {
			maps.Copy(desiredEnv, catrust.EnvVars(catrust.ContainerCABundlePath, catrust.ContainerExtraCAPath))
		}
	}

	hasJavaOpts := false
	for _, kv := range ctr.GetEnv() {
		if strings.HasPrefix(kv, "JAVA_TOOL_OPTIONS=") {
			hasJavaOpts = true
			break
		}
	}
	for _, entry := range proxyenv.MergeNonClobbering(ctr.GetEnv(), desiredEnv, javaToolOpts) {
		changed = true
		if entry.Key == "JAVA_TOOL_OPTIONS" && hasJavaOpts {
			adj.RemoveEnv("JAVA_TOOL_OPTIONS")
		}
		adj.AddEnv(entry.Key, entry.Value)
	}

	status = metrics.StatusSuccess
	if !changed {
		return nil, nil, nil
	}
	return adj, nil, nil
}

// StopPodSandbox immediately revokes the current sandbox's listeners and closes all active tunnels.
// Stale events for a superseded PodSandbox ID are ignored so delayed runtime GC never disrupts a
// newly created replacement sandbox sharing the same Pod UID.
func (d *Driver) StopPodSandbox(_ context.Context, pod *nriapi.PodSandbox) error {
	start := time.Now()
	status := metrics.StatusNoop
	defer func() {
		recordNRIMetric(methodStopPodSandbox, status, start)
	}()

	podUID := types.UID(pod.GetUid())
	cfg, ok := d.store.Get(podUID)
	if !ok {
		return nil
	}
	if cfg.SandboxID != "" && pod.GetId() != "" && pod.GetId() != cfg.SandboxID {
		return nil
	}
	if d.ingress != nil {
		d.ingress.Revoke(podUID)
	}
	d.tunnel.Revoke(podUID)
	d.reportResourceClaimDeviceStatusAsync(cfg, false)
	status = metrics.StatusSuccess
	return nil
}

// RemovePodSandbox detaches sandbox-scoped resources (socketat loopback listeners and NetNS)
// for the matching PodSandbox ID while keeping DRA-owned state (store checkpoint, egress.sock,
// and CA bundles) intact until UnprepareResourceClaims runs. Preserving DRA-owned state ensures
// kubelet PodSandbox retries retain full confinement and plumbing.
func (d *Driver) RemovePodSandbox(_ context.Context, pod *nriapi.PodSandbox) error {
	start := time.Now()
	status := metrics.StatusNoop
	defer func() {
		recordNRIMetric(methodRemovePodSandbox, status, start)
	}()

	podUID := types.UID(pod.GetUid())
	cfg, ok := d.store.Get(podUID)
	if !ok {
		return nil
	}
	if cfg.SandboxID != "" && pod.GetId() != "" && pod.GetId() != cfg.SandboxID {
		return nil
	}
	if d.ingress != nil {
		d.ingress.Revoke(podUID)
	}
	d.tunnel.Revoke(podUID)
	d.tunnel.DetachExtraListeners(podUID)
	if err := d.store.UpdateSandbox(podUID, "", "", time.Time{}); err != nil {
		status = metrics.StatusFailed
		return err
	}
	status = metrics.StatusSuccess
	return nil
}

func recordNRIMetric(method, status string, start time.Time) {
	metrics.NRIPluginRequestsTotal.WithLabelValues(method, status).Inc()
	metrics.NRIPluginRequestsLatencySeconds.WithLabelValues(method, status).Observe(time.Since(start).Seconds())
}

func (d *Driver) buildWorkloadIdentity(
	podUID types.UID,
	sandboxID, podName, namespace, sa string,
	custom map[string]string,
) auth.WorkloadIdentity {
	return auth.WorkloadIdentity{
		Namespace:      namespace,
		PodName:        podName,
		PodUID:         podUID,
		SandboxID:      sandboxID,
		ServiceAccount: sa,
		NodeName:       d.nodeName,
		Custom:         custom,
	}
}

func (d *Driver) reportResourceClaimDeviceStatusAsync(cfg store.PodConfig, ready bool) {
	if d.kubeClient == nil || cfg.ClaimNamespace == "" || cfg.ClaimName == "" {
		return
	}
	d.statusWG.Go(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		cond := metav1.Condition{
			Type:               "Ready",
			Status:             metav1.ConditionTrue,
			Reason:             "AgentsNetPrepared",
			Message:            "agents.net listener prepared for Pod",
			LastTransitionTime: metav1.Now(),
		}
		if !ready {
			cond.Status = metav1.ConditionFalse
			cond.Reason = "AgentsNetRevoked"
			cond.Message = "agents.net listener revoked after PodSandbox stop"
		}

		devStatus := apis.DeviceStatus{
			APIVersion: apis.DeviceStatusAPIVersion,
			Kind:       apis.DeviceStatusKind,
			NodeName:   d.nodeName,
			PodUID:     string(cfg.PodUID),
			SandboxID:  cfg.SandboxID,
		}
		if ready && len(cfg.Parameters.IngressPorts) > 0 {
			if endpoint := d.resolveIngressEndpoint(); endpoint != "" {
				ports := make([]apis.IngressPort, len(cfg.Parameters.IngressPorts))
				for i, p := range cfg.Parameters.IngressPorts {
					proto := p.Protocol
					if proto == "" {
						proto = apis.IngressProtocolTCP
					}
					ports[i] = apis.IngressPort{Port: p.Port, EndPort: p.EndPort, Protocol: proto}
				}
				devStatus.Ingress = &apis.IngressStatus{
					Endpoint:   endpoint,
					Protocol:   apis.IngressTunnelProtocolHTTPConnect,
					Target:     string(cfg.PodUID),
					TLS:        d.ingressTLS,
					ServerName: d.ingressServerName,
					Ports:      ports,
				}
			}
		}
		dataBytes, err := json.Marshal(devStatus)
		if err != nil {
			klog.ErrorS(err, "marshal ResourceClaim.status.devices data", "claim", cfg.ClaimNamespace+"/"+cfg.ClaimName)
			return
		}

		entry := resourceapi.AllocatedDeviceStatus{
			Driver:     d.driverName,
			Pool:       cfg.PoolName,
			Device:     cfg.DeviceName,
			Conditions: []metav1.Condition{cond},
			Data:       &k8sruntime.RawExtension{Raw: dataBytes},
		}
		if cfg.ShareID != "" {
			shareID := cfg.ShareID
			entry.ShareID = &shareID
		}

		err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
			// Prevent a delayed revoke for a retired PodSandbox from overwriting a newer generation.
			if !ready && cfg.SandboxID != "" {
				if cur, ok := d.store.Get(cfg.PodUID); ok && cur.SandboxID != "" && cur.SandboxID != cfg.SandboxID {
					return nil
				}
			}

			claim, err := d.kubeClient.ResourceV1().ResourceClaims(cfg.ClaimNamespace).Get(ctx, cfg.ClaimName, metav1.GetOptions{})
			if err != nil {
				return err
			}
			updated := claim.DeepCopy()
			replaced := false
			for i := range updated.Status.Devices {
				existing := &updated.Status.Devices[i]
				if existing.Driver == entry.Driver && existing.Pool == entry.Pool && existing.Device == entry.Device && sameShareID(existing.ShareID, entry.ShareID) {
					updated.Status.Devices[i] = entry
					replaced = true
					break
				}
			}
			if !replaced {
				updated.Status.Devices = append(updated.Status.Devices, entry)
			}
			_, err = d.kubeClient.ResourceV1().ResourceClaims(cfg.ClaimNamespace).UpdateStatus(ctx, updated, metav1.UpdateOptions{})
			return err
		})
		if err != nil {
			klog.ErrorS(err, "failed to update ResourceClaim.status.devices", "claim", cfg.ClaimNamespace+"/"+cfg.ClaimName)
		}
	})
}

func sameShareID(a, b *string) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return *a == *b
}

func getNetworkNamespace(pod *nriapi.PodSandbox) string {
	if pod == nil || pod.Linux == nil {
		return ""
	}
	for _, ns := range pod.Linux.Namespaces {
		if ns.Type == "network" {
			return ns.Path
		}
	}
	return ""
}

func formatIngressPorts(ports []apis.IngressPort) string {
	parts := make([]string, 0, len(ports))
	for _, p := range ports {
		if p.EndPort > p.Port {
			parts = append(parts, fmt.Sprintf("%d-%d", p.Port, p.EndPort))
		} else {
			parts = append(parts, strconv.FormatInt(int64(p.Port), 10))
		}
	}
	return strings.Join(parts, ",")
}
