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

// Command dra-agents-net runs the per-node agents.net Kubernetes Network Driver
// (KND) DaemonSet, following the Kubernetes Network Driver Model (Ojea, IEEE LCN
// 2025, DOI: 10.1109/LCN65610.2025.11146291 / arXiv:2506.23628): standard GA DRA
// slow-path preparation + NRI fast-path runtime hooks + socketat loopback
// listeners + authenticated upstream CONNECT / RFC 9298 connect-udp forwarding.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog/v2"

	"github.com/aojea/agents.net/kubernetes/pkg/apis"
	"github.com/aojea/agents.net/kubernetes/pkg/auth"
	"github.com/aojea/agents.net/kubernetes/pkg/catrust"
	"github.com/aojea/agents.net/kubernetes/pkg/driver"
	"github.com/aojea/agents.net/kubernetes/pkg/ingress"
	"github.com/aojea/agents.net/kubernetes/pkg/store"
	"github.com/aojea/agents.net/kubernetes/pkg/tunnel"
)

func main() {
	var (
		kubeconfig           string
		nodeName             string
		nodeIP               string
		driverName           string
		socketRoot           string
		checkpointPath       string
		kubeletRoot          string
		nriSocket            string
		nriPluginIdx         string
		nodeTokenPath        string
		spiffeSocket         string
		spireDelegatedSock   string
		systemRootsPath      string
		metricsAddr          string
		ingressAddr          string
		ingressAdvertiseAddr string
		ingressTLSCert       string
		ingressTLSKey        string
		ingressClientCA      string
		ingressServerName    string
		maxSandboxes         int64
	)

	klog.InitFlags(nil)
	flag.StringVar(&kubeconfig, "kubeconfig", "", "Path to kubeconfig (defaults to in-cluster config)")
	flag.StringVar(&nodeName, "node-name", os.Getenv("NODE_NAME"), "Kubernetes node name")
	flag.StringVar(&nodeIP, "node-ip", os.Getenv("NODE_IP"), "Kubernetes node IP used to advertise the ingress bridge endpoint (defaults to Node InternalIP)")
	flag.StringVar(&driverName, "driver-name", apis.DriverName, "DRA driver and NRI plugin name")
	flag.StringVar(&socketRoot, "socket-root", "/run/dra-agents-net/pods", "Host directory for per-Pod agents.net Unix sockets and CA bundles")
	flag.StringVar(&checkpointPath, "checkpoint-path", "/run/dra-agents-net/state.db", "BoltDB tmpfs checkpoint path")
	flag.StringVar(&kubeletRoot, "kubelet-root-dir", auth.DefaultKubeletRootDir, "Host kubelet root directory")
	flag.StringVar(&nriSocket, "nri-socket", "", "Optional containerd/CRI-O NRI socket path")
	flag.StringVar(&nriPluginIdx, "nri-plugin-idx", "00", "NRI plugin index")
	flag.StringVar(&nodeTokenPath, "node-token-path", auth.DefaultNodeTokenPath, "Projected ServiceAccount token path for ServiceAccountToken Node mode")
	flag.StringVar(&spiffeSocket, "spiffe-socket", auth.DefaultSPIFFEWorkloadSocket, "SPIFFE Workload API Unix socket path")
	flag.StringVar(&spireDelegatedSock, "spire-delegated-socket", auth.DefaultSPIREDelegatedSocket, "SPIRE Delegated Identity Unix socket path")
	flag.StringVar(&systemRootsPath, "system-roots-path", "", "Optional host system CA bundle path for AppendSystemRoots mode (auto-detected if empty)")
	flag.StringVar(&metricsAddr, "metrics-addr", ":9102", "Address for Prometheus /metrics and /healthz")
	flag.StringVar(&ingressAddr, "ingress-addr", "", "Optional host listen address for the HTTP CONNECT ingress bridge (e.g. :15080)")
	flag.StringVar(&ingressAdvertiseAddr, "ingress-advertise-addr", "", "Optional explicit host:port advertised in ResourceClaim.status.devices[].data.ingress.endpoint")
	flag.StringVar(&ingressTLSCert, "ingress-tls-cert", "", "Optional PEM server certificate path for TLS on --ingress-addr")
	flag.StringVar(&ingressTLSKey, "ingress-tls-key", "", "Optional PEM server key path for TLS on --ingress-addr")
	flag.StringVar(&ingressClientCA, "ingress-client-ca", "", "Optional PEM client CA bundle path to enforce mTLS on --ingress-addr")
	flag.StringVar(&ingressServerName, "ingress-server-name", "", "Optional TLS server name advertised in ResourceClaim.status.devices[].data.ingress.serverName")
	flag.Int64Var(&maxSandboxes, "max-sandboxes", 0, "Per-node DRA slot count (0 auto-detects from node status.allocatable.pods, fallback 110)")
	flag.Parse()

	if nodeName == "" {
		klog.Fatalf("--node-name or NODE_NAME environment variable is required")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Registered before all resource defers so os.Exit runs LAST after graceful shutdown.
	exitCode := 0
	defer func() {
		if exitCode != 0 {
			os.Exit(exitCode)
		}
	}()

	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, syscall.SIGINT, syscall.SIGTERM)

	restCfg, err := loadRestConfig(kubeconfig)
	if err != nil {
		klog.Fatalf("load kubernetes config: %v", err)
	}
	kubeClient, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		klog.Fatalf("create kubernetes client: %v", err)
	}

	boltBackend, err := store.OpenBolt(checkpointPath)
	if err != nil {
		klog.Fatalf("open checkpoint store %q: %v", checkpointPath, err)
	}
	podStore, err := store.New(boltBackend)
	if err != nil {
		klog.Fatalf("hydrate pod store: %v", err)
	}
	defer func() { _ = podStore.Close() }()

	authResolver := auth.NewResolver(auth.ResolverConfig{
		KubeletRootDir:              kubeletRoot,
		DefaultNodeTokenPath:        nodeTokenPath,
		DefaultSPIFFEWorkloadSocket: spiffeSocket,
		DefaultSPIREDelegatedSocket: spireDelegatedSock,
		KubeClient:                  kubeClient,
	})
	defer func() { _ = authResolver.Close() }()

	tunnelMgr, err := tunnel.NewManager(socketRoot, authResolver)
	if err != nil {
		klog.Fatalf("create agents.net tunnel manager: %v", err)
	}
	defer tunnelMgr.Close()

	var (
		fatalMu  sync.Mutex
		fatalErr error
	)
	triggerFatal := func(err error) {
		fatalMu.Lock()
		if fatalErr == nil {
			fatalErr = err
		}
		fatalMu.Unlock()
		cancel()
	}

	var (
		ingressSrv        *ingress.Server
		ingressTLSEnabled bool
	)
	if ingressAddr != "" {
		ingressTLS, err := buildIngressTLSConfig(ingressTLSCert, ingressTLSKey, ingressClientCA)
		if err != nil {
			klog.Fatalf("configure ingress TLS: %v", err)
		}
		ingressTLSEnabled = ingressTLS != nil
		if !ingressTLSEnabled {
			klog.InfoS("WARNING: dra-agents-net ingress bridge running without TLS/mTLS; configure --ingress-tls-cert, --ingress-tls-key, and --ingress-client-ca in production", "addr", ingressAddr)
		}
		ingressSrv, err = ingress.NewServer(ingress.Config{
			ListenAddr: ingressAddr,
			Store:      podStore,
			TLSConfig:  ingressTLS,
		})
		if err != nil {
			klog.Fatalf("create ingress bridge: %v", err)
		}
	}

	drv, err := driver.New(driver.Config{
		DriverName:           driverName,
		NodeName:             nodeName,
		NodeIP:               nodeIP,
		KubeClient:           kubeClient,
		Store:                podStore,
		Tunnel:               tunnelMgr,
		Ingress:              ingressSrv,
		CAMaterializer:       catrust.NewMaterializer(kubeClient, systemRootsPath),
		MaxSandboxes:         maxSandboxes,
		KubeletRootDir:       kubeletRoot,
		NRISocketPath:        nriSocket,
		NRIPluginIdx:         nriPluginIdx,
		IngressBridgeAddr:    ingressAddr,
		IngressAdvertiseAddr: ingressAdvertiseAddr,
		IngressTLS:           ingressTLSEnabled,
		IngressServerName:    ingressServerName,
		OnNRIFatal:           triggerFatal,
	})
	if err != nil {
		klog.Fatalf("create DRA+NRI driver: %v", err)
	}

	mux := http.NewServeMux()
	registerHealthz(mux,
		healthChecker{name: "dra", check: drv.CheckDRA},
		healthChecker{name: "nri", check: drv.CheckNRI},
	)
	mux.Handle("/metrics", promhttp.Handler())

	// Bind before starting the driver so a port still held by a previous
	// DaemonSet Pod stops this process before it accepts any DRA claim.
	metricsSrv, err := startMetricsServer(metricsAddr, mux, func(err error) {
		triggerFatal(fmt.Errorf("metrics/healthz server on %s stopped: %w", metricsAddr, err))
	})
	if err != nil {
		klog.Fatalf("start metrics/healthz server on %s: %v", metricsAddr, err)
	}
	klog.InfoS("serving metrics and healthz", "addr", metricsAddr)
	defer func() {
		shutCtx, shutCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutCancel()
		_ = metricsSrv.Shutdown(shutCtx)
	}()

	if err := drv.Start(ctx); err != nil {
		klog.Fatalf("start DRA+NRI driver: %v", err)
	}
	// Deferred AFTER metricsSrv/tunnelMgr/podStore defers so LIFO order drains
	// prepared Pods through NRI while store, tunnelMgr, and /healthz stay alive.
	defer drv.Stop(cancel)

	if ingressSrv != nil {
		if _, err := ingressSrv.Start(); err != nil {
			klog.Fatalf("start ingress bridge: %v", err)
		}
		defer func() { _ = ingressSrv.Close() }()
	}

	select {
	case sig := <-signalCh:
		klog.InfoS("received shutdown signal; initiating graceful shutdown", "signal", sig.String())
	case <-ctx.Done():
		fatalMu.Lock()
		err := fatalErr
		fatalMu.Unlock()
		if err != nil {
			klog.ErrorS(err, "fatal component error; initiating graceful shutdown")
			exitCode = 1
		} else {
			klog.InfoS("context cancelled; initiating graceful shutdown")
		}
	}
}

// startMetricsServer binds addr synchronously and serves handler in the background.
// Bind failures return immediately; unexpected Serve failures call onServeError.
func startMetricsServer(addr string, handler http.Handler, onServeError func(error)) (*http.Server, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen on %s: %w", addr, err)
	}
	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			onServeError(err)
		}
	}()
	return srv, nil
}

func loadRestConfig(kubeconfig string) (*rest.Config, error) {
	if kubeconfig != "" {
		return clientcmd.BuildConfigFromFlags("", kubeconfig)
	}
	if cfg, err := rest.InClusterConfig(); err == nil {
		return cfg, nil
	}
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	return clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, &clientcmd.ConfigOverrides{}).ClientConfig()
}

type tlsFileStamp struct {
	mtime time.Time
	size  int64
	ino   uint64
}

func statTLSFile(path string) (tlsFileStamp, error) {
	info, err := os.Stat(path)
	if err != nil {
		return tlsFileStamp{}, err
	}
	st := tlsFileStamp{mtime: info.ModTime(), size: info.Size()}
	if sys, ok := info.Sys().(*syscall.Stat_t); ok && sys != nil {
		st.ino = sys.Ino
	}
	return st, nil
}

type rotatingIngressTLS struct {
	certFile     string
	keyFile      string
	clientCAFile string

	mu        sync.Mutex
	cert      *tls.Certificate
	certStamp tlsFileStamp
	keyStamp  tlsFileStamp
	caPool    *x509.CertPool
	caStamp   tlsFileStamp
}

func (r *rotatingIngressTLS) getCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.loadCertLocked()
}

func (r *rotatingIngressTLS) loadCertLocked() (*tls.Certificate, error) {
	cStamp, err := statTLSFile(r.certFile)
	if err != nil {
		return nil, fmt.Errorf("stat ingress TLS cert %q: %w", r.certFile, err)
	}
	kStamp, err := statTLSFile(r.keyFile)
	if err != nil {
		return nil, fmt.Errorf("stat ingress TLS key %q: %w", r.keyFile, err)
	}
	if r.cert != nil && cStamp == r.certStamp && kStamp == r.keyStamp {
		return r.cert, nil
	}
	pair, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		return nil, fmt.Errorf("load ingress TLS keypair: %w", err)
	}
	r.cert = &pair
	r.certStamp = cStamp
	r.keyStamp = kStamp
	return r.cert, nil
}

func (r *rotatingIngressTLS) loadClientCALocked() (*x509.CertPool, error) {
	if r.clientCAFile == "" {
		return nil, nil
	}
	st, err := statTLSFile(r.clientCAFile)
	if err != nil {
		return nil, fmt.Errorf("stat ingress client CA %q: %w", r.clientCAFile, err)
	}
	if r.caPool != nil && st == r.caStamp {
		return r.caPool, nil
	}
	caBytes, err := os.ReadFile(r.clientCAFile)
	if err != nil {
		return nil, fmt.Errorf("read ingress client CA %q: %w", r.clientCAFile, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caBytes) {
		return nil, fmt.Errorf("no valid CA certificates in %q", r.clientCAFile)
	}
	r.caPool = pool
	r.caStamp = st
	return r.caPool, nil
}

func (r *rotatingIngressTLS) getConfigForClient(_ *tls.ClientHelloInfo) (*tls.Config, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cert, err := r.loadCertLocked()
	if err != nil {
		return nil, err
	}
	pool, err := r.loadClientCALocked()
	if err != nil {
		return nil, err
	}
	cfg := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{*cert},
	}
	if pool != nil {
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return cfg, nil
}

func buildIngressTLSConfig(certFile, keyFile, clientCAFile string) (*tls.Config, error) {
	if certFile == "" && keyFile == "" && clientCAFile == "" {
		return nil, nil
	}
	if certFile == "" || keyFile == "" {
		return nil, errors.New("both --ingress-tls-cert and --ingress-tls-key are required when TLS is enabled")
	}
	loader := &rotatingIngressTLS{
		certFile:     certFile,
		keyFile:      keyFile,
		clientCAFile: clientCAFile,
	}
	// Validate initial files eagerly at startup so broken paths fail fast.
	if _, err := loader.getConfigForClient(nil); err != nil {
		return nil, err
	}
	cfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		GetCertificate:     loader.getCertificate,
		GetConfigForClient: loader.getConfigForClient,
	}
	if clientCAFile != "" {
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return cfg, nil
}
