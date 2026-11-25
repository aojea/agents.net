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
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"k8s.io/apimachinery/pkg/types"

	"github.com/aojea/agents.net/kubernetes/pkg/apis"
)

// ParseCredentialBundlePEM parses a KEP-4317 single-file PEM credential bundle
// (a PRIVATE KEY PEM block followed by one or more CERTIFICATE PEM blocks) into a
// tls.Certificate with its parsed leaf certificate populated.
func ParseCredentialBundlePEM(bundle []byte) (*tls.Certificate, error) {
	var keyPEM []byte
	var certPEM []byte
	rest := bundle
	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = remaining
		switch {
		case strings.Contains(block.Type, "PRIVATE KEY"):
			if len(keyPEM) > 0 {
				return nil, errors.New("credential bundle contains multiple private keys")
			}
			keyPEM = pem.EncodeToMemory(block)
		case block.Type == "CERTIFICATE":
			certPEM = append(certPEM, pem.EncodeToMemory(block)...)
		}
	}
	if len(keyPEM) == 0 {
		return nil, errors.New("credential bundle missing PRIVATE KEY block")
	}
	if len(certPEM) == 0 {
		return nil, errors.New("credential bundle missing CERTIFICATE blocks")
	}

	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse PodCertificate keypair: %w", err)
	}
	if len(pair.Certificate) > 0 {
		leaf, err := x509.ParseCertificate(pair.Certificate[0])
		if err != nil {
			return nil, fmt.Errorf("parse PodCertificate leaf: %w", err)
		}
		pair.Leaf = leaf
	}
	return &pair, nil
}

// PodCertificateBundlePath returns the host kubelet projected volume path for a Pod's
// KEP-4317 credential bundle file.
func PodCertificateBundlePath(kubeletRoot string, podUID types.UID, volumeName string) string {
	if volumeName == "" {
		volumeName = apis.PodCertVolumeName
	}
	return filepath.Join(
		kubeletRoot,
		"pods",
		string(podUID),
		"volumes",
		"kubernetes.io~projected",
		volumeName,
		apis.PodCertBundleFile,
	)
}

// rotatingBundleLoader reads a single-file KEP-4317 credential bundle atomically and
// reloads whenever kubelet rotates the projected volume file.
type rotatingBundleLoader struct {
	bundlePath string

	mu    sync.Mutex
	cert  *tls.Certificate
	stamp fileStamp
}

func (l *rotatingBundleLoader) GetClientCertificate(_ *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	info, err := os.Stat(l.bundlePath)
	if err != nil {
		return nil, fmt.Errorf("stat PodCertificate bundle %q: %w", l.bundlePath, err)
	}
	st := stampFromFileInfo(info)
	if l.cert != nil && st == l.stamp {
		return l.cert, nil
	}

	raw, err := os.ReadFile(l.bundlePath)
	if err != nil {
		return nil, fmt.Errorf("read PodCertificate bundle %q: %w", l.bundlePath, err)
	}
	cert, err := ParseCredentialBundlePEM(raw)
	if err != nil {
		return nil, err
	}
	l.cert = cert
	l.stamp = st
	return l.cert, nil
}

func (r *Resolver) resolvePodCertificate(ctx context.Context, req ResolveRequest) (*ClientConfig, error) {
	pcSpec := req.PolicyEnforcementPoint.Auth.PodCertificate
	if pcSpec == nil || pcSpec.SignerName == "" {
		return nil, errors.New("podCertificate.signerName is required when auth.type is PodCertificate")
	}
	bundlePath, err := safePodProjectedFilePath(r.kubeletRootDir, req.PodUID, req.PodCertVolumeName, apis.PodCertVolumeName, apis.PodCertBundleFile)
	if err != nil {
		return nil, fmt.Errorf("invalid PodCertificate volume path: %w", err)
	}

	tlsCfg, err := r.buildServerTLSConfig(ctx, req.PolicyEnforcementPoint.TLS, req.PodNamespace)
	if err != nil {
		return nil, err
	}

	// Note: during DRA PrepareResourceClaims, kubelet may not have mounted the Pod's
	// projected volume yet (that runs after PrepareResourceClaims, before containers start).
	// GetClientCertificate loads lazily on the first handshake and reloads on every rotation.
	loader := &rotatingBundleLoader{
		bundlePath: bundlePath,
	}
	tlsCfg.GetClientCertificate = loader.GetClientCertificate

	return &ClientConfig{
		AuthMode:  AuthModePodCertificate,
		TLSConfig: tlsCfg,
	}, nil
}
