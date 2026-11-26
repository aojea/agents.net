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

package tunnel

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/types"

	"github.com/aojea/agents.net/pkg/apis"
	"github.com/aojea/agents.net/pkg/auth"
)

func TestDoHForwardingUnifiedAndSeparatePEP(t *testing.T) {
	ctx := t.Context()
	tmp := t.TempDir()
	caPEM, srvCertPEM, srvKeyPEM, cliCertPEM, cliKeyPEM, caPool := generateTestCerts(t)
	certDir, caPath := writeTestMTLSCertDir(t, caPEM, cliCertPEM, cliKeyPEM)
	srvCert, err := tls.X509KeyPair(srvCertPEM, srvKeyPEM)
	if err != nil {
		t.Fatalf("load server keypair: %v", err)
	}
	srvTLS := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{srvCert},
		ClientCAs:    caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		NextProtos:   []string{"h2"},
	}

	var mu sync.Mutex
	var gotUnifiedPrincipal string
	var gotUnifiedBody []byte

	// Unified HTTPS HTTP/2 mTLS PEP serving /dns-query.
	baseLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen unified pep: %v", err)
	}
	defer func() { _ = baseLn.Close() }()
	tlsLn := tls.NewListener(baseLn, srvTLS)
	protos := new(http.Protocols)
	protos.SetHTTP2(true)
	srv := &http.Server{
		Protocols: protos,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost || r.URL.Path != "/dns-query" {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			body, _ := io.ReadAll(r.Body)
			mu.Lock()
			gotUnifiedPrincipal = r.Header.Get(auth.HeaderPrincipal)
			gotUnifiedBody = append([]byte(nil), body...)
			mu.Unlock()
			w.Header().Set("Content-Type", "application/dns-message")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("unified-dns-reply"))
		}),
	}
	go func() { _ = srv.Serve(tlsLn) }()
	defer func() { _ = srv.Close() }()

	// Separate DNS PEP over unix:// socket.
	sepSock := filepath.Join(tmp, "sep-dns.sock")
	sepLn, err := net.Listen("unix", sepSock)
	if err != nil {
		t.Fatalf("listen separate dns pep: %v", err)
	}
	defer func() { _ = sepLn.Close() }()
	var gotSeparatePrincipal string
	go func() {
		for {
			c, err := sepLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer func() { _ = conn.Close() }()
				br := bufio.NewReader(conn)
				req, err := http.ReadRequest(br)
				if err != nil {
					return
				}
				_, _ = io.ReadAll(req.Body)
				mu.Lock()
				gotSeparatePrincipal = req.Header.Get(auth.HeaderPrincipal)
				mu.Unlock()
				reply := "separate-dns-reply"
				_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: "+
					"18\r\nConnection: close\r\n\r\n"+reply)
			}(c)
		}
	}()

	mgr, err := NewManager(filepath.Join(tmp, "pods"), nil, WithAuditWriter(io.Discard), WithTimeouts(3*time.Second, 3*time.Second))
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	defer mgr.Close()

	trafficPEP := &apis.PolicyEnforcementPointConfig{
		URL: "https://" + baseLn.Addr().String(),
		TLS: &apis.PEPTLS{
			ServerName: "upstream.local",
			CACertificateRefs: []apis.CASource{
				{Type: apis.CASourceTypeHostPath, HostPath: caPath},
			},
		},
		Auth: &apis.PEPAuth{
			Type: apis.PEPAuthTypeMTLS,
			MTLS: &apis.MTLSAuth{CertDir: certDir},
		},
	}

	sendDoH := func(t *testing.T, podUID types.UID, body []byte) (int, string) {
		t.Helper()
		client, server := net.Pipe()
		defer func() { _ = client.Close() }()
		if err := mgr.ServeConn(podUID, server); err != nil {
			t.Fatalf("ServeConn: %v", err)
		}
		_ = client.SetDeadline(time.Now().Add(3 * time.Second))
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, "http://boundary/dns-query", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/dns-message")
		req.Header.Set("Accept", "application/dns-message")
		req.Header.Set("Agents-Net-Principal", "forged")
		if err := req.Write(client); err != nil {
			t.Fatalf("write DoH request: %v", err)
		}
		resp, err := http.ReadResponse(bufio.NewReader(client), req)
		if err != nil {
			t.Fatalf("read DoH response: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		raw, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(raw)
	}

	// 1. Default Synthetic mode rejects POST /dns-query with 405 doh-disabled.
	const podSynth = types.UID("pod-doh-disabled")
	if _, err := mgr.EnsureListener(ctx, podSynth, ListenerConfig{
		Identity:               auth.WorkloadIdentity{Namespace: "agents", PodName: "synth", PodUID: podSynth},
		PolicyEnforcementPoint: trafficPEP,
		DNSMode:                apis.DNSModeSynthetic,
	}); err != nil {
		t.Fatalf("EnsureListener synth: %v", err)
	}
	if code, _ := sendDoH(t, podSynth, []byte("dns-q")); code != http.StatusMethodNotAllowed {
		t.Fatalf("Synthetic mode POST /dns-query status = %d, want 405", code)
	}

	// 2. Unified PEP DoH mode forwards over the Traffic PEP's mTLS HTTP/2 session with attested identity.
	const podUnified = types.UID("pod-doh-unified")
	if _, err := mgr.EnsureListener(ctx, podUnified, ListenerConfig{
		Identity:               auth.WorkloadIdentity{Namespace: "agents", PodName: "unified", PodUID: podUnified},
		PolicyEnforcementPoint: trafficPEP,
		DNSMode:                apis.DNSModeDoH,
	}); err != nil {
		t.Fatalf("EnsureListener unified: %v", err)
	}
	code, reply := sendDoH(t, podUnified, []byte("wire-query-bytes"))
	if code != http.StatusOK || reply != "unified-dns-reply" {
		t.Fatalf("Unified DoH = (%d, %q), want (200, unified-dns-reply)", code, reply)
	}
	mu.Lock()
	if gotUnifiedPrincipal != "k8s://agents/unified" || string(gotUnifiedBody) != "wire-query-bytes" {
		mu.Unlock()
		t.Fatalf("unified PEP saw principal=%q body=%q", gotUnifiedPrincipal, string(gotUnifiedBody))
	}
	mu.Unlock()

	// 3. Separate DNS PEP mode routes /dns-query to DNSEnforcementPoint instead of Traffic PEP.
	const podSep = types.UID("pod-doh-separate")
	if _, err := mgr.EnsureListener(ctx, podSep, ListenerConfig{
		Identity:               auth.WorkloadIdentity{Namespace: "agents", PodName: "separate", PodUID: podSep},
		PolicyEnforcementPoint: trafficPEP,
		DNSMode:                apis.DNSModeDoH,
		DNSEnforcementPoint:    &apis.PolicyEnforcementPointConfig{URL: "unix://" + sepSock},
	}); err != nil {
		t.Fatalf("EnsureListener separate: %v", err)
	}
	code, reply = sendDoH(t, podSep, []byte("sep-query"))
	if code != http.StatusOK || !strings.EqualFold(reply, "separate-dns-reply") {
		t.Fatalf("Separate DNS PEP DoH = (%d, %q), want (200, separate-dns-reply)", code, reply)
	}
	mu.Lock()
	if gotSeparatePrincipal != "k8s://agents/separate" {
		mu.Unlock()
		t.Fatalf("separate DNS PEP saw principal=%q, want k8s://agents/separate", gotSeparatePrincipal)
	}
	mu.Unlock()
}
