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
// or Gateway API HTTTPRoute to attract inbound traffic and deliver it to isolated
// Pods discovered via ResourceClaim.status.devices[].data.
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
	"syscall"
	"time"

	resourceapi "k8s.io/api/resource/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog/v2"

	"github.com/aojea/agents.net/kubernetes/pkg/apis"
	"github.com/aojea/agents.net/kubernetes/pkg/gateway"
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
	flag.StringVar(&bridgeCA, "bridge-ca", "", "Optional PEM CA certificate path for verifying node ingress bridge TLS")
	flag.StringVar(&bridgeClientCert, "bridge-client-cert", "", "Optional PEM client certificate path for mTLS to node ingress bridges")
	flag.StringVar(&bridgeClientKey, "bridge-client-key", "", "Optional PEM client private key path for mTLS to node ingress bridges")
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

	tlsCfg, err := buildBridgeTLSConfig(bridgeCA, bridgeClientCert, bridgeClientKey)
	if err != nil {
		klog.Fatalf("configure bridge TLS: %v", err)
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

func buildBridgeTLSConfig(caPath, certPath, keyPath string) (*tls.Config, error) {
	if caPath == "" && certPath == "" && keyPath == "" {
		return nil, nil
	}
	if (certPath == "") != (keyPath == "") {
		return nil, errors.New("--bridge-client-cert and --bridge-client-key must be set together")
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if caPath != "" {
		pemBytes, err := os.ReadFile(caPath)
		if err != nil {
			return nil, fmt.Errorf("read bridge CA %q: %w", caPath, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, fmt.Errorf("no valid CA certificates in %q", caPath)
		}
		cfg.RootCAs = pool
	}
	if certPath != "" {
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return nil, fmt.Errorf("load bridge client cert/key: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	return cfg, nil
}
