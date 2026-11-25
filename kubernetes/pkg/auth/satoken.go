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
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"k8s.io/apimachinery/pkg/types"

	"github.com/aojea/agents.net/kubernetes/pkg/apis"
)

// PodSATokenPath returns the host kubelet projected volume path for a Pod's
// audience-bound ServiceAccount token (isolated to the tun2connect sidecar).
func PodSATokenPath(kubeletRoot string, podUID types.UID, volumeName string) string {
	if volumeName == "" {
		volumeName = apis.SATokenVolumeName
	}
	return filepath.Join(
		kubeletRoot,
		"pods",
		string(podUID),
		"volumes",
		"kubernetes.io~projected",
		volumeName,
		apis.SATokenFile,
	)
}

// rotatingTokenLoader caches a projected ServiceAccount JWT file and reloads
// automatically whenever kubelet rotates the token on disk.
type rotatingTokenLoader struct {
	tokenPath string

	mu    sync.Mutex
	token string
	stamp fileStamp
}

func (l *rotatingTokenLoader) BearerHeader(_ context.Context) (string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	info, err := os.Stat(l.tokenPath)
	if err != nil {
		return "", fmt.Errorf("stat ServiceAccount token %q: %w", l.tokenPath, err)
	}
	st := stampFromFileInfo(info)
	if l.token != "" && st == l.stamp {
		return "Bearer " + l.token, nil
	}

	raw, err := os.ReadFile(l.tokenPath)
	if err != nil {
		return "", fmt.Errorf("read ServiceAccount token %q: %w", l.tokenPath, err)
	}
	tok := strings.TrimSpace(string(raw))
	if tok == "" {
		return "", fmt.Errorf("ServiceAccount token file %q is empty", l.tokenPath)
	}
	if !isSafeBearerToken(tok) {
		return "", fmt.Errorf("ServiceAccount token file %q contains illegal control or whitespace characters", l.tokenPath)
	}
	l.token = tok
	l.stamp = st
	return "Bearer " + tok, nil
}

func isSafeBearerToken(tok string) bool {
	for i := range len(tok) {
		c := tok[i]
		if c <= 0x20 || c >= 0x7f {
			return false
		}
	}
	return true
}

func (r *Resolver) resolveServiceAccountToken(ctx context.Context, req ResolveRequest) (*ClientConfig, error) {
	saSpec := req.PolicyEnforcementPoint.Auth.ServiceAccountToken
	if saSpec == nil || strings.TrimSpace(saSpec.Audience) == "" {
		return nil, errors.New("serviceAccountToken.audience is required when auth.type is ServiceAccountToken")
	}

	u, err := url.Parse(strings.TrimSpace(req.PolicyEnforcementPoint.URL))
	if err != nil {
		return nil, fmt.Errorf("parse PEP URL %q: %w", req.PolicyEnforcementPoint.URL, err)
	}
	if u.Scheme != "https" && u.Scheme != "unix" {
		return nil, fmt.Errorf("ServiceAccountToken auth requires an https:// or unix:// PEP URL, got %q", u.Scheme)
	}

	tlsCfg, err := r.buildServerTLSConfig(ctx, req.PolicyEnforcementPoint.TLS, req.PodNamespace)
	if err != nil {
		return nil, err
	}

	mode := saSpec.Mode
	if mode == "" {
		mode = apis.ServiceAccountTokenModeNode
	}

	var tokenPath string
	switch mode {
	case apis.ServiceAccountTokenModeNode:
		tokenPath = r.defaultNodeTokenPath
	case apis.ServiceAccountTokenModePod:
		var perr error
		tokenPath, perr = safePodProjectedFilePath(r.kubeletRootDir, req.PodUID, req.SATokenVolumeName, apis.SATokenVolumeName, apis.SATokenFile)
		if perr != nil {
			return nil, fmt.Errorf("invalid Pod-mode ServiceAccountToken path: %w", perr)
		}
	default:
		return nil, fmt.Errorf("unsupported serviceAccountToken.mode %q", mode)
	}

	loader := &rotatingTokenLoader{tokenPath: tokenPath}
	return &ClientConfig{
		AuthMode:           AuthModeServiceAccountToken,
		TLSConfig:          tlsCfg,
		ProxyAuthorization: loader.BearerHeader,
	}, nil
}
