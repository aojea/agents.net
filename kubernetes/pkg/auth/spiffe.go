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
	"strings"

	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"

	"github.com/aojea/agents.net/kubernetes/pkg/apis"
)

const maxSPIFFESources = 16

func (r *Resolver) resolveSPIFFE(ctx context.Context, req ResolveRequest) (*ClientConfig, error) {
	spiffeSpec := req.PolicyEnforcementPoint.Auth.SPIFFE

	authorizer, err := buildSPIFFEAuthorizer(req.PolicyEnforcementPoint.TLS)
	if err != nil {
		return nil, err
	}

	sockPath := r.defaultSPIFFEWorkloadSocket
	if spiffeSpec != nil && spiffeSpec.WorkloadSocketPath != "" {
		sockPath = spiffeSpec.WorkloadSocketPath
	}
	src, err := r.getOrCreateWorkloadAPISource(ctx, sockPath)
	if err != nil {
		return nil, err
	}
	tlsCfg := tlsconfig.MTLSClientConfig(src, src, authorizer)
	if req.PolicyEnforcementPoint.TLS != nil && req.PolicyEnforcementPoint.TLS.ServerName != "" {
		tlsCfg.ServerName = req.PolicyEnforcementPoint.TLS.ServerName
	}
	return &ClientConfig{
		AuthMode:  AuthModeSPIFFE,
		TLSConfig: tlsCfg,
	}, nil
}

func buildSPIFFEAuthorizer(tlsSpec *apis.PEPTLS) (tlsconfig.Authorizer, error) {
	if tlsSpec == nil {
		return nil, errors.New("SPIFFE auth requires policyEnforcementPoint.tls.trustDomain or acceptedSPIFFEIDs")
	}
	allowedIDs, allowedDomain, err := parseSPIFFEConstraints(tlsSpec)
	if err != nil {
		return nil, err
	}
	if len(allowedIDs) > 0 && !allowedDomain.IsZero() {
		for _, id := range allowedIDs {
			if id.TrustDomain() != allowedDomain {
				return nil, fmt.Errorf("accepted SPIFFE ID %q does not belong to configured trustDomain %q", id.String(), allowedDomain.Name())
			}
		}
		return tlsconfig.AuthorizeOneOf(allowedIDs...), nil
	}
	if len(allowedIDs) > 0 {
		return tlsconfig.AuthorizeOneOf(allowedIDs...), nil
	}
	if !allowedDomain.IsZero() {
		return tlsconfig.AuthorizeMemberOf(allowedDomain), nil
	}
	return nil, errors.New("SPIFFE auth requires policyEnforcementPoint.tls.trustDomain or acceptedSPIFFEIDs")
}

func normalizeSocketURI(raw string) string {
	if strings.Contains(raw, "://") {
		return raw
	}
	return "unix://" + raw
}

func (r *Resolver) getOrCreateWorkloadAPISource(ctx context.Context, sockPath string) (*workloadapi.X509Source, error) {
	addr := normalizeSocketURI(sockPath)
	r.mu.Lock()
	if existing, ok := r.spiffeSources[addr]; ok {
		r.mu.Unlock()
		return existing, nil
	}
	if len(r.spiffeSources) >= maxSPIFFESources {
		r.mu.Unlock()
		return nil, fmt.Errorf("too many distinct SPIFFE workload sockets configured (max %d)", maxSPIFFESources)
	}
	r.mu.Unlock()

	src, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(addr)))
	if err != nil {
		return nil, fmt.Errorf("connect SPIFFE Workload API at %q: %w", addr, err)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if existing, ok := r.spiffeSources[addr]; ok {
		_ = src.Close()
		return existing, nil
	}
	if len(r.spiffeSources) >= maxSPIFFESources {
		_ = src.Close()
		return nil, fmt.Errorf("too many distinct SPIFFE workload sockets configured (max %d)", maxSPIFFESources)
	}
	r.spiffeSources[addr] = src
	return src, nil
}
