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
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/encoding/protowire"
	"k8s.io/apimachinery/pkg/types"

	"github.com/aojea/agents.net/kubernetes/pkg/apis"
)

const (
	spireDelegatedSVIDMethod   = "/spire.api.agent.delegatedidentity.v1.DelegatedIdentity/SubscribeToX509SVIDs"
	spireDelegatedBundleMethod = "/spire.api.agent.delegatedidentity.v1.DelegatedIdentity/SubscribeToX509Bundles"

	maxSPIFFESources          = 16
	spiffeReconnectMinBackoff = 250 * time.Millisecond
	spiffeReconnectMaxBackoff = 5 * time.Second
)

var errEmptyDelegatedSVIDs = errors.New("delegated identity response contained zero X.509-SVIDs")

func (r *Resolver) resolveSPIFFE(ctx context.Context, req ResolveRequest) (*ClientConfig, error) {
	spiffeSpec := req.PolicyEnforcementPoint.Auth.SPIFFE
	mode := apis.SPIFFEModeNode
	if spiffeSpec != nil && spiffeSpec.Mode != "" {
		mode = spiffeSpec.Mode
	}

	authorizer, err := buildSPIFFEAuthorizer(req.PolicyEnforcementPoint.TLS)
	if err != nil {
		return nil, err
	}

	switch mode {
	case apis.SPIFFEModeNode:
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

	case apis.SPIFFEModeDelegatedPod:
		if req.PodUID == "" {
			return nil, errors.New("podUID is required for SPIFFE DelegatedPod mode")
		}
		delegatedSock := r.defaultSPIREDelegatedSocket
		if spiffeSpec != nil && spiffeSpec.DelegatedSocketPath != "" {
			delegatedSock = spiffeSpec.DelegatedSocketPath
		}
		src, err := newDelegatedSPIFFESource(ctx, delegatedSock, req.PodUID)
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
			closeFn:   src.Close,
		}, nil

	default:
		return nil, fmt.Errorf("unsupported spiffe.mode %q", mode)
	}
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

func (r *Resolver) getOrCreateWorkloadAPISource(ctx context.Context, sockPath string) (*workloadapi.X509Source, error) {
	addr := ensureUnixPrefix(sockPath)
	r.mu.Lock()
	if src, ok := r.spiffeSources[addr]; ok {
		r.mu.Unlock()
		return src, nil
	}
	if len(r.spiffeSources) >= maxSPIFFESources {
		r.mu.Unlock()
		return nil, fmt.Errorf("maximum cached SPIFFE Workload API sources (%d) reached", maxSPIFFESources)
	}
	r.mu.Unlock()

	src, err := workloadapi.NewX509Source(
		ctx,
		workloadapi.WithClientOptions(workloadapi.WithAddr(addr)),
	)
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
		return nil, fmt.Errorf("maximum cached SPIFFE Workload API sources (%d) reached", maxSPIFFESources)
	}
	r.spiffeSources[addr] = src
	return src, nil
}

func ensureUnixPrefix(path string) string {
	if strings.HasPrefix(path, "unix://") || strings.HasPrefix(path, "unix:") {
		return path
	}
	return "unix://" + path
}

func stripUnixPrefix(path string) string {
	path = strings.TrimPrefix(path, "unix://")
	return strings.TrimPrefix(path, "unix:")
}

// rawBytesCodec passes pre-encoded protobuf payloads over gRPC without requiring
// generated spire-api-sdk stubs.
type rawBytesCodec struct{}

func (rawBytesCodec) Marshal(v any) ([]byte, error) {
	b, ok := v.([]byte)
	if !ok {
		return nil, fmt.Errorf("rawBytesCodec expects []byte, got %T", v)
	}
	return b, nil
}

func (rawBytesCodec) Unmarshal(data []byte, v any) error {
	ptr, ok := v.(*[]byte)
	if !ok {
		return fmt.Errorf("rawBytesCodec expects *[]byte, got %T", v)
	}
	*ptr = append((*ptr)[:0], data...)
	return nil
}

func (rawBytesCodec) Name() string { return "proto" }

// delegatedSPIFFESource implements both x509svid.Source and x509bundle.Source backed by
// live SPIRE Delegated Identity v1 streams scoped to selector k8s:pod-uid:<uid>.
type delegatedSPIFFESource struct {
	conn   *grpc.ClientConn
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu      sync.RWMutex
	svid    *x509svid.SVID
	bundles *x509bundle.Set
}

var (
	_ x509svid.Source   = &delegatedSPIFFESource{}
	_ x509bundle.Source = &delegatedSPIFFESource{}
)

func newDelegatedSPIFFESource(ctx context.Context, sockPath string, podUID types.UID) (*delegatedSPIFFESource, error) {
	rawPath := stripUnixPrefix(sockPath)
	conn, err := grpc.NewClient(
		"passthrough:///unix",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(dctx context.Context, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(dctx, "unix", rawPath)
		}),
		grpc.WithDefaultCallOptions(grpc.ForceCodec(rawBytesCodec{})),
	)
	if err != nil {
		return nil, fmt.Errorf("dial SPIRE Delegated Identity socket %q: %w", rawPath, err)
	}

	streamCtx, cancel := context.WithCancel(context.Background())
	s := &delegatedSPIFFESource{
		conn:    conn,
		cancel:  cancel,
		bundles: x509bundle.NewSet(),
	}

	svidReady := make(chan error, 1)
	bundleReady := make(chan error, 1)

	s.wg.Go(func() {
		s.watchSVIDs(streamCtx, podUID, svidReady)
	})
	s.wg.Go(func() {
		s.watchBundles(streamCtx, bundleReady)
	})

	initTimeout := 5 * time.Second
	if deadline, ok := ctx.Deadline(); ok {
		if rem := time.Until(deadline); rem > 0 && rem < initTimeout {
			initTimeout = rem
		}
	}
	timer := time.NewTimer(initTimeout)
	defer timer.Stop()

	for gotSVID, gotBundle := false, false; !gotSVID || !gotBundle; {
		select {
		case err := <-svidReady:
			if err != nil {
				_ = s.Close()
				return nil, fmt.Errorf("SPIRE Delegated Identity SVID stream: %w", err)
			}
			gotSVID = true
		case err := <-bundleReady:
			if err != nil {
				_ = s.Close()
				return nil, fmt.Errorf("SPIRE Delegated Identity bundle stream: %w", err)
			}
			gotBundle = true
		case <-ctx.Done():
			_ = s.Close()
			return nil, ctx.Err()
		case <-timer.C:
			_ = s.Close()
			return nil, fmt.Errorf("timed out waiting for initial SPIRE Delegated Identity SVID/bundle for pod %s", podUID)
		}
	}

	return s, nil
}

func (s *delegatedSPIFFESource) GetX509SVID() (*x509svid.SVID, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.svid == nil {
		return nil, errors.New("no delegated X.509-SVID available")
	}
	return s.svid, nil
}

func (s *delegatedSPIFFESource) GetX509BundleForTrustDomain(td spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.bundles.GetX509BundleForTrustDomain(td)
}

func (s *delegatedSPIFFESource) Close() error {
	s.cancel()
	err := s.conn.Close()
	s.wg.Wait()
	return err
}

func (s *delegatedSPIFFESource) watchSVIDs(ctx context.Context, podUID types.UID, ready chan<- error) {
	sentReady := false
	signalReady := func(err error) {
		if !sentReady {
			sentReady = true
			ready <- err
		}
	}

	desc := &grpc.StreamDesc{ServerStreams: true}
	reqPayload := encodeSubscribeX509SVIDsRequest("k8s", "pod-uid:"+string(podUID))
	backoff := spiffeReconnectMinBackoff

	for {
		stream, err := s.conn.NewStream(ctx, desc, spireDelegatedSVIDMethod)
		if err == nil {
			err = stream.SendMsg(reqPayload)
		}
		if err == nil {
			err = stream.CloseSend()
		}
		if err == nil {
			for {
				var respBytes []byte
				if rerr := stream.RecvMsg(&respBytes); rerr != nil {
					err = rerr
					break
				}
				svid, derr := decodeFirstDelegatedSVID(respBytes)
				if errors.Is(derr, errEmptyDelegatedSVIDs) {
					// SPIRE revoked all SVIDs for this selector: clear cached SVID to fail closed.
					s.mu.Lock()
					s.svid = nil
					s.mu.Unlock()
					signalReady(derr)
					continue
				}
				if derr != nil {
					signalReady(derr)
					continue
				}
				s.mu.Lock()
				s.svid = svid
				s.mu.Unlock()
				backoff = spiffeReconnectMinBackoff
				signalReady(nil)
			}
		}

		if !sentReady {
			signalReady(err)
			return
		}
		if ctx.Err() != nil {
			return
		}
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		backoff = min(backoff*2, spiffeReconnectMaxBackoff)
	}
}

func (s *delegatedSPIFFESource) watchBundles(ctx context.Context, ready chan<- error) {
	sentReady := false
	signalReady := func(err error) {
		if !sentReady {
			sentReady = true
			ready <- err
		}
	}

	desc := &grpc.StreamDesc{ServerStreams: true}
	backoff := spiffeReconnectMinBackoff

	for {
		stream, err := s.conn.NewStream(ctx, desc, spireDelegatedBundleMethod)
		if err == nil {
			err = stream.SendMsg([]byte{})
		}
		if err == nil {
			err = stream.CloseSend()
		}
		if err == nil {
			for {
				var respBytes []byte
				if rerr := stream.RecvMsg(&respBytes); rerr != nil {
					err = rerr
					break
				}
				set, derr := decodeDelegatedBundles(respBytes)
				if derr != nil {
					signalReady(derr)
					continue
				}
				s.mu.Lock()
				s.bundles = set
				s.mu.Unlock()
				backoff = spiffeReconnectMinBackoff
				signalReady(nil)
			}
		}

		if !sentReady {
			signalReady(err)
			return
		}
		if ctx.Err() != nil {
			return
		}
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		backoff = min(backoff*2, spiffeReconnectMaxBackoff)
	}
}

// Wire encoding for spire.api.agent.delegatedidentity.v1.SubscribeToX509SVIDsRequest:
//
//	message Selector { string type = 1; string value = 2; }
//	message SubscribeToX509SVIDsRequest { repeated Selector selectors = 1; }
func encodeSubscribeX509SVIDsRequest(selType, selValue string) []byte {
	var sel []byte
	sel = protowire.AppendTag(sel, 1, protowire.BytesType)
	sel = protowire.AppendString(sel, selType)
	sel = protowire.AppendTag(sel, 2, protowire.BytesType)
	sel = protowire.AppendString(sel, selValue)

	var req []byte
	req = protowire.AppendTag(req, 1, protowire.BytesType)
	req = protowire.AppendBytes(req, sel)
	return req
}

// Wire decoding for spire.api.agent.delegatedidentity.v1.SubscribeToX509SVIDsResponse:
//
//	message SubscribeToX509SVIDsResponse { repeated X509SVIDWithKey x509_svids = 1; }
//	message X509SVIDWithKey { X509SVID x509_svid = 1; bytes x509_svid_key = 2; }
//	message X509SVID { repeated bytes cert_chain = 1; }
func decodeFirstDelegatedSVID(b []byte) (*x509svid.SVID, error) {
	entries := 0
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return nil, protowire.ParseError(n)
		}
		b = b[n:]
		if num == 1 && typ == protowire.BytesType {
			entry, m := protowire.ConsumeBytes(b)
			if m < 0 {
				return nil, protowire.ParseError(m)
			}
			entries++
			svid, err := decodeX509SVIDWithKey(entry)
			if err == nil {
				return svid, nil
			}
			b = b[m:]
			continue
		}
		m := protowire.ConsumeFieldValue(num, typ, b)
		if m < 0 {
			return nil, protowire.ParseError(m)
		}
		b = b[m:]
	}
	if entries == 0 {
		return nil, errEmptyDelegatedSVIDs
	}
	return nil, errors.New("delegated identity response contained no valid X.509-SVID")
}

func decodeX509SVIDWithKey(b []byte) (*x509svid.SVID, error) {
	var certDERConcat []byte
	var keyDER []byte
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return nil, protowire.ParseError(n)
		}
		b = b[n:]
		switch {
		case num == 1 && typ == protowire.BytesType:
			svidMsg, m := protowire.ConsumeBytes(b)
			if m < 0 {
				return nil, protowire.ParseError(m)
			}
			b = b[m:]
			chain, err := decodeX509CertChain(svidMsg)
			if err != nil {
				return nil, err
			}
			certDERConcat = chain
		case num == 2 && typ == protowire.BytesType:
			keyBytes, m := protowire.ConsumeBytes(b)
			if m < 0 {
				return nil, protowire.ParseError(m)
			}
			b = b[m:]
			keyDER = append([]byte(nil), keyBytes...)
		default:
			m := protowire.ConsumeFieldValue(num, typ, b)
			if m < 0 {
				return nil, protowire.ParseError(m)
			}
			b = b[m:]
		}
	}
	if len(certDERConcat) == 0 || len(keyDER) == 0 {
		return nil, errors.New("delegated X509SVIDWithKey missing cert chain or private key")
	}
	return x509svid.ParseRaw(certDERConcat, keyDER)
}

func decodeX509CertChain(b []byte) ([]byte, error) {
	var concat []byte
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return nil, protowire.ParseError(n)
		}
		b = b[n:]
		if num == 1 && typ == protowire.BytesType {
			certDER, m := protowire.ConsumeBytes(b)
			if m < 0 {
				return nil, protowire.ParseError(m)
			}
			b = b[m:]
			concat = append(concat, certDER...)
			continue
		}
		m := protowire.ConsumeFieldValue(num, typ, b)
		if m < 0 {
			return nil, protowire.ParseError(m)
		}
		b = b[m:]
	}
	return concat, nil
}

// Wire decoding for spire.api.agent.delegatedidentity.v1.SubscribeToX509BundlesResponse:
//
//	message SubscribeToX509BundlesResponse { map<string, bytes> ca_certificates = 1; }
func decodeDelegatedBundles(b []byte) (*x509bundle.Set, error) {
	set := x509bundle.NewSet()
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return nil, protowire.ParseError(n)
		}
		b = b[n:]
		if num == 1 && typ == protowire.BytesType {
			entry, m := protowire.ConsumeBytes(b)
			if m < 0 {
				return nil, protowire.ParseError(m)
			}
			b = b[m:]
			tdName, derBytes, err := decodeBundleMapEntry(entry)
			if err != nil {
				return nil, err
			}
			td, err := spiffeid.TrustDomainFromString(tdName)
			if err != nil {
				return nil, fmt.Errorf("invalid trust domain %q in delegated bundle: %w", tdName, err)
			}
			certs, err := x509.ParseCertificates(derBytes)
			if err != nil {
				return nil, fmt.Errorf("parse delegated bundle certs for %q: %w", tdName, err)
			}
			set.Add(x509bundle.FromX509Authorities(td, certs))
			continue
		}
		m := protowire.ConsumeFieldValue(num, typ, b)
		if m < 0 {
			return nil, protowire.ParseError(m)
		}
		b = b[m:]
	}
	return set, nil
}

func decodeBundleMapEntry(b []byte) (string, []byte, error) {
	var key string
	var val []byte
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return "", nil, protowire.ParseError(n)
		}
		b = b[n:]
		switch {
		case num == 1 && typ == protowire.BytesType:
			k, m := protowire.ConsumeString(b)
			if m < 0 {
				return "", nil, protowire.ParseError(m)
			}
			b = b[m:]
			key = k
		case num == 2 && typ == protowire.BytesType:
			v, m := protowire.ConsumeBytes(b)
			if m < 0 {
				return "", nil, protowire.ParseError(m)
			}
			b = b[m:]
			val = append([]byte(nil), v...)
		default:
			m := protowire.ConsumeFieldValue(num, typ, b)
			if m < 0 {
				return "", nil, protowire.ParseError(m)
			}
			b = b[m:]
		}
	}
	return key, val, nil
}
