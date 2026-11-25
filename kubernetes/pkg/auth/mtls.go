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
)

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
	if mtlsSpec == nil || mtlsSpec.CertDir == "" {
		return nil, errors.New("mtls.certDir is required when auth.type is MTLS")
	}

	tlsCfg, err := r.buildServerTLSConfig(ctx, req.PolicyEnforcementPoint.TLS, req.PodNamespace)
	if err != nil {
		return nil, err
	}

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
