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

package auth

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const secretCertReloadTTL = 30 * time.Second

// secretPairLoader caches a TLS keypair from a Kubernetes Secret and refreshes it
// periodically so cert-manager Secret rotations take effect without restarting Pods.
type secretPairLoader struct {
	kubeClient kubernetes.Interface
	namespace  string
	name       string

	mu        sync.Mutex
	cert      *tls.Certificate
	fetchedAt time.Time
}

func (l *secretPairLoader) GetClientCertificate(_ *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	l.mu.Lock()
	if l.cert != nil && time.Since(l.fetchedAt) < secretCertReloadTTL {
		c := l.cert
		l.mu.Unlock()
		return c, nil
	}
	l.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	secret, err := l.kubeClient.CoreV1().Secrets(l.namespace).Get(ctx, l.name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("get mTLS Secret %s/%s: %w", l.namespace, l.name, err)
	}
	certPEM := secret.Data["tls.crt"]
	keyPEM := secret.Data["tls.key"]
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		return nil, fmt.Errorf("mTLS Secret %s/%s must contain tls.crt and tls.key", l.namespace, secret.Name)
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse mTLS Secret %s/%s keypair: %w", l.namespace, secret.Name, err)
	}

	l.mu.Lock()
	l.cert = &pair
	l.fetchedAt = time.Now()
	c := l.cert
	l.mu.Unlock()
	return c, nil
}

// rotatingPairLoader caches a TLS keypair loaded from certPath and keyPath,
// reloading automatically when either file's modification time, size, or inode changes.
type rotatingPairLoader struct {
	certPath string
	keyPath  string

	mu        sync.Mutex
	cert      *tls.Certificate
	certStamp fileStamp
	keyStamp  fileStamp
}

func (l *rotatingPairLoader) GetClientCertificate(_ *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	certInfo, err := os.Stat(l.certPath)
	if err != nil {
		return nil, fmt.Errorf("stat mTLS client cert %q: %w", l.certPath, err)
	}
	keyInfo, err := os.Stat(l.keyPath)
	if err != nil {
		return nil, fmt.Errorf("stat mTLS client key %q: %w", l.keyPath, err)
	}
	cStamp := stampFromFileInfo(certInfo)
	kStamp := stampFromFileInfo(keyInfo)

	if l.cert != nil && cStamp == l.certStamp && kStamp == l.keyStamp {
		return l.cert, nil
	}

	pair, err := tls.LoadX509KeyPair(l.certPath, l.keyPath)
	if err != nil {
		return nil, fmt.Errorf("load mTLS keypair (%q, %q): %w", l.certPath, l.keyPath, err)
	}
	l.cert = &pair
	l.certStamp = cStamp
	l.keyStamp = kStamp
	return l.cert, nil
}

func (r *Resolver) resolveMTLS(ctx context.Context, req ResolveRequest) (*ClientConfig, error) {
	mtlsSpec := req.PolicyEnforcementPoint.Auth.MTLS
	if mtlsSpec == nil {
		return nil, errors.New("mtls auth config is required when auth.type is MTLS")
	}

	tlsCfg, err := r.buildServerTLSConfig(ctx, req.PolicyEnforcementPoint.TLS, req.PodNamespace)
	if err != nil {
		return nil, err
	}

	if mtlsSpec.CertDir != "" {
		loader := &rotatingPairLoader{
			certPath: filepath.Join(mtlsSpec.CertDir, "tls.crt"),
			keyPath:  filepath.Join(mtlsSpec.CertDir, "tls.key"),
		}
		// Validate initial load eagerly so broken configurations fail fast.
		if _, err := loader.GetClientCertificate(nil); err != nil {
			return nil, err
		}
		tlsCfg.GetClientCertificate = loader.GetClientCertificate
		return &ClientConfig{
			AuthMode:  AuthModeMTLS,
			TLSConfig: tlsCfg,
		}, nil
	}

	if mtlsSpec.SecretRef != nil && mtlsSpec.SecretRef.Name != "" {
		if r.kubeClient == nil {
			return nil, errors.New("kubernetes client is required to read mtls.secretRef")
		}
		loader := &secretPairLoader{
			kubeClient: r.kubeClient,
			namespace:  req.PodNamespace,
			name:       mtlsSpec.SecretRef.Name,
		}
		// Validate eagerly so broken Secret references fail fast during PrepareResourceClaims.
		if _, err := loader.GetClientCertificate(nil); err != nil {
			return nil, err
		}
		tlsCfg.GetClientCertificate = loader.GetClientCertificate
		return &ClientConfig{
			AuthMode:  AuthModeMTLS,
			TLSConfig: tlsCfg,
		}, nil
	}

	return nil, errors.New("mtls auth requires either certDir or secretRef")
}
