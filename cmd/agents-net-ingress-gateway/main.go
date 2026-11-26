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

// Command agents-net-ingress-gateway is a stateless Kubernetes ingress gateway
// for dra.agents.net. Place it behind a LoadBalancer Service, Kubernetes Ingress,
// or Gateway API HTTTPRoute to attract inbound traffic and deliver it over
// mandatory mTLS HTTP CONNECT tunnels to isolated Pods discovered via
// ResourceClaim.status.devices[].data.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	resourceapi "k8s.io/api/resource/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog/v2"

	"github.com/aojea/agents.net/pkg/apis"
	"github.com/aojea/agents.net/pkg/gateway"
)

func main() {
	var (
		kubeconfig       string
		listenAddr       string
		driverName       string
		bridgeCA         string
		bridgeClientCert string
		bridgeClientKey  string
	)

	klog.InitFlags(nil)
	flag.StringVar(&kubeconfig, "kubeconfig", "", "Path to kubeconfig (defaults to in-cluster config)")
	flag.StringVar(&listenAddr, "listen-addr", ":8080", "HTTP listen address for inbound ingress requests and /healthz")
	flag.StringVar(&driverName, "driver-name", apis.DriverName, "DRA driver name to read from ResourceClaim.status.devices")
	flag.StringVar(&bridgeCA, "bridge-ca", "", "PEM CA certificate path for verifying node ingress bridge TLS (required)")
	flag.StringVar(&bridgeClientCert, "bridge-client-cert", "", "PEM client certificate path for mandatory mTLS to node ingress bridges (required)")
	flag.StringVar(&bridgeClientKey, "bridge-client-key", "", "PEM client private key path for mandatory mTLS to node ingress bridges (required)")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	restCfg, err := loadRestConfig(kubeconfig)
	if err != nil {
		klog.Fatalf("load kubernetes config: %v", err)
	}
	kubeClient, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		klog.Fatalf("create kubernetes client: %v", err)
	}

	tlsCfg, err := buildBridgeMTLSConfig(bridgeCA, bridgeClientCert, bridgeClientKey)
	if err != nil {
		klog.Fatalf("configure mandatory bridge mTLS: %v", err)
	}

	reg := gateway.NewRegistry(driverName)
	factory := informers.NewSharedInformerFactory(kubeClient, 30*time.Second)
	claimInf := factory.Resource().V1().ResourceClaims().Informer()
	_, _ = claimInf.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj any) {
			if claim, ok := obj.(*resourceapi.ResourceClaim); ok {
				reg.SyncClaim(claim)
			}
		},
		UpdateFunc: func(_, newObj any) {
			if claim, ok := newObj.(*resourceapi.ResourceClaim); ok {
				reg.SyncClaim(claim)
			}
		},
		DeleteFunc: func(obj any) {
			if tomb, ok := obj.(cache.DeletedFinalStateUnknown); ok {
				obj = tomb.Obj
			}
			if claim, ok := obj.(*resourceapi.ResourceClaim); ok {
				reg.DeleteClaim(claim.Namespace, claim.Name)
			}
		},
	})
	factory.Start(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), claimInf.HasSynced) {
		klog.Fatalf("failed to sync ResourceClaim informer cache")
	}

	handler, err := gateway.NewHandler(gateway.Config{
		Registry:  reg,
		TLSConfig: tlsCfg,
	})
	if err != nil {
		klog.Fatalf("create gateway handler: %v", err)
	}
	defer handler.Close()

	srv := &http.Server{
		Addr:              listenAddr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		klog.InfoS("agents-net-ingress-gateway listening", "addr", listenAddr, "driver", driverName)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	case err := <-errCh:
		if err != nil {
			klog.Fatalf("gateway server failed: %v", err)
		}
	}
}

func loadRestConfig(kubeconfig string) (*rest.Config, error) {
	if kubeconfig != "" {
		return clientcmd.BuildConfigFromFlags("", kubeconfig)
	}
	return rest.InClusterConfig()
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

type rotatingBridgeTLS struct {
	caFile   string
	certFile string
	keyFile  string

	mu        sync.Mutex
	cert      *tls.Certificate
	certStamp tlsFileStamp
	keyStamp  tlsFileStamp
	caPool    *x509.CertPool
	caStamp   tlsFileStamp
}

func (r *rotatingBridgeTLS) getClientCertificate(_ *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cStamp, err := statTLSFile(r.certFile)
	if err != nil {
		return nil, fmt.Errorf("stat bridge client cert %q: %w", r.certFile, err)
	}
	kStamp, err := statTLSFile(r.keyFile)
	if err != nil {
		return nil, fmt.Errorf("stat bridge client key %q: %w", r.keyFile, err)
	}
	if r.cert != nil && cStamp == r.certStamp && kStamp == r.keyStamp {
		return r.cert, nil
	}
	pair, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		return nil, fmt.Errorf("load bridge client keypair: %w", err)
	}
	r.cert = &pair
	r.certStamp = cStamp
	r.keyStamp = kStamp
	return r.cert, nil
}

func (r *rotatingBridgeTLS) loadCAPool() (*x509.CertPool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	st, err := statTLSFile(r.caFile)
	if err != nil {
		return nil, fmt.Errorf("stat bridge CA %q: %w", r.caFile, err)
	}
	if r.caPool != nil && st == r.caStamp {
		return r.caPool, nil
	}
	pemBytes, err := os.ReadFile(r.caFile)
	if err != nil {
		return nil, fmt.Errorf("read bridge CA %q: %w", r.caFile, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("no valid CA certificates in %q", r.caFile)
	}
	r.caPool = pool
	r.caStamp = st
	return r.caPool, nil
}

func (r *rotatingBridgeTLS) verifyServerConnection(cs tls.ConnectionState) error {
	if len(cs.PeerCertificates) == 0 {
		return errors.New("ingress bridge presented no server certificate")
	}
	pool, err := r.loadCAPool()
	if err != nil {
		return err
	}
	intermediates := x509.NewCertPool()
	for _, cert := range cs.PeerCertificates[1:] {
		intermediates.AddCert(cert)
	}
	opts := x509.VerifyOptions{
		DNSName:       cs.ServerName,
		Roots:         pool,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if _, err := cs.PeerCertificates[0].Verify(opts); err != nil {
		return fmt.Errorf("verify ingress bridge certificate: %w", err)
	}
	return nil
}

func buildBridgeMTLSConfig(caPath, certPath, keyPath string) (*tls.Config, error) {
	if caPath == "" || certPath == "" || keyPath == "" {
		return nil, errors.New("--bridge-ca, --bridge-client-cert, and --bridge-client-key are all required (mTLS is mandatory)")
	}
	loader := &rotatingBridgeTLS{
		caFile:   caPath,
		certFile: certPath,
		keyFile:  keyPath,
	}
	// Validate initial files eagerly at startup so broken paths fail fast.
	if _, err := loader.loadCAPool(); err != nil {
		return nil, err
	}
	if _, err := loader.getClientCertificate(nil); err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:           tls.VersionTLS12,
		InsecureSkipVerify:   true, // Verified in VerifyConnection against hot-reloaded CA pool.
		GetClientCertificate: loader.getClientCertificate,
		VerifyConnection:     loader.verifyServerConnection,
	}, nil
}
