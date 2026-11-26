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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"google.golang.org/grpc"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	k8sfake "k8s.io/client-go/kubernetes/fake"

	"github.com/aojea/agents.net/pkg/apis"
)

type testPKI struct {
	caCert    *x509.Certificate
	caCertDER []byte
	caCertPEM []byte
	caKey     *ecdsa.PrivateKey
	caPool    *x509.CertPool
}

func newTestPKI(t *testing.T) *testPKI {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-root-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &testPKI{
		caCert:    cert,
		caCertDER: der,
		caCertPEM: pemBytes,
		caKey:     key,
		caPool:    pool,
	}
}

func (p *testPKI) issueLeaf(t *testing.T, cn string, dnsNames []string, uriSAN string, isServer bool) (certDER, keyPKCS8DER, certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<60))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		DNSNames:     dnsNames,
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	if isServer {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	} else {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	if uriSAN != "" {
		u, err := url.Parse(uriSAN)
		if err != nil {
			t.Fatalf("parse URI SAN %q: %v", uriSAN, err)
		}
		tmpl.URIs = []*url.URL{u}
	}
	certDER, err = x509.CreateCertificate(rand.Reader, tmpl, p.caCert, &key.PublicKey, p.caKey)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}
	keyPKCS8DER, err = x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal PKCS8 key: %v", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyPKCS8DER})
	return certDER, keyPKCS8DER, certPEM, keyPEM
}

func startMTLSServer(t *testing.T, pki *testPKI, serverURI string, requireClientCert bool) (string, <-chan *x509.Certificate) {
	t.Helper()
	_, _, srvCertPEM, srvKeyPEM := pki.issueLeaf(t, "upstream.local", []string{"upstream.local", "localhost"}, serverURI, true)
	srvPair, err := tls.X509KeyPair(srvCertPEM, srvKeyPEM)
	if err != nil {
		t.Fatalf("load server keypair: %v", err)
	}
	clientAuth := tls.NoClientCert
	if requireClientCert {
		clientAuth = tls.RequireAndVerifyClientCert
	}
	tlsCfg := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{srvPair},
		ClientCAs:    pki.caPool,
		ClientAuth:   clientAuth,
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	peerCh := make(chan *x509.Certificate, 4)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				tc := c.(*tls.Conn)
				if err := tc.Handshake(); err != nil {
					return
				}
				state := tc.ConnectionState()
				var leaf *x509.Certificate
				if len(state.PeerCertificates) > 0 {
					leaf = state.PeerCertificates[0]
				}
				peerCh <- leaf
			}(conn)
		}
	}()
	return ln.Addr().String(), peerCh
}

func TestMTLSAuthDirRotationAndConfigMapCA(t *testing.T) {
	ctx := t.Context()
	pki := newTestPKI(t)
	srvAddr, peerCh := startMTLSServer(t, pki, "", true)

	// 1. Rotating certDir mode with HostPath CA.
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(caPath, pki.caCertPEM, 0o600); err != nil {
		t.Fatalf("write ca.crt: %v", err)
	}
	_, _, c1PEM, k1PEM := pki.issueLeaf(t, "node-1-gen1", nil, "", false)
	if err := os.WriteFile(filepath.Join(dir, "tls.crt"), c1PEM, 0o600); err != nil {
		t.Fatalf("write tls.crt: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tls.key"), k1PEM, 0o600); err != nil {
		t.Fatalf("write tls.key: %v", err)
	}

	resolver := NewResolver(ResolverConfig{})
	defer func() { _ = resolver.Close() }()

	cc, err := resolver.Resolve(ctx, ResolveRequest{
		PodNamespace: "agents",
		PolicyEnforcementPoint: &apis.PolicyEnforcementPointConfig{
			URL: "https://" + srvAddr,
			TLS: &apis.PEPTLS{
				ServerName: "upstream.local",
				CACertificateRefs: []apis.CASource{
					{Type: apis.CASourceTypeHostPath, HostPath: caPath},
				},
			},
			Auth: &apis.PEPAuth{
				Type: apis.PEPAuthTypeMTLS,
				MTLS: &apis.MTLSAuth{CertDir: dir},
			},
		},
	})
	if err != nil {
		t.Fatalf("Resolve MTLS certDir: %v", err)
	}
	if cc.AuthMode != AuthModeMTLS {
		t.Fatalf("AuthMode = %q, want %q", cc.AuthMode, AuthModeMTLS)
	}

	conn, err := tls.Dial("tcp", srvAddr, cc.TLSConfig)
	if err != nil {
		t.Fatalf("mTLS dial gen1: %v", err)
	}
	_ = conn.Close()
	if peer := <-peerCh; peer == nil || peer.Subject.CommonName != "node-1-gen1" {
		t.Fatalf("server saw peer CN=%v, want node-1-gen1", peer)
	}

	// Rotate cert on disk with a bumped timestamp and verify hot reload without re-resolving.
	_, _, c2PEM, k2PEM := pki.issueLeaf(t, "node-1-gen2", nil, "", false)
	if err := os.WriteFile(filepath.Join(dir, "tls.crt"), c2PEM, 0o600); err != nil {
		t.Fatalf("rotate tls.crt: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tls.key"), k2PEM, 0o600); err != nil {
		t.Fatalf("rotate tls.key: %v", err)
	}
	future := time.Now().Add(2 * time.Second)
	_ = os.Chtimes(filepath.Join(dir, "tls.crt"), future, future)
	_ = os.Chtimes(filepath.Join(dir, "tls.key"), future, future)

	conn, err = tls.Dial("tcp", srvAddr, cc.TLSConfig)
	if err != nil {
		t.Fatalf("mTLS dial gen2: %v", err)
	}
	_ = conn.Close()
	if peer := <-peerCh; peer == nil || peer.Subject.CommonName != "node-1-gen2" {
		t.Fatalf("server saw rotated peer CN=%v, want node-1-gen2", peer)
	}

	// 2. ConfigMap CA source paired with rotating certDir.
	fakeKube := k8sfake.NewClientset(
		&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Name: "upstream-ca", Namespace: "agents"},
			Data:       map[string]string{"ca.crt": string(pki.caCertPEM)},
		},
	)
	kubeResolver := NewResolver(ResolverConfig{KubeClient: fakeKube})
	defer func() { _ = kubeResolver.Close() }()

	ccCM, err := kubeResolver.Resolve(ctx, ResolveRequest{
		PodNamespace: "agents",
		PolicyEnforcementPoint: &apis.PolicyEnforcementPointConfig{
			URL: "https://" + srvAddr,
			TLS: &apis.PEPTLS{
				ServerName: "upstream.local",
				CACertificateRefs: []apis.CASource{
					{Type: apis.CASourceTypeConfigMap, ConfigMapRef: &apis.ConfigMapKeyRef{Name: "upstream-ca"}},
				},
			},
			Auth: &apis.PEPAuth{
				Type: apis.PEPAuthTypeMTLS,
				MTLS: &apis.MTLSAuth{CertDir: dir},
			},
		},
	})
	if err != nil {
		t.Fatalf("Resolve MTLS with ConfigMap CA: %v", err)
	}
	conn, err = tls.Dial("tcp", srvAddr, ccCM.TLSConfig)
	if err != nil {
		t.Fatalf("mTLS dial ConfigMap CA: %v", err)
	}
	_ = conn.Close()
	if peer := <-peerCh; peer == nil || peer.Subject.CommonName != "node-1-gen2" {
		t.Fatalf("server saw ConfigMap CA peer CN=%v, want node-1-gen2", peer)
	}
}

func TestPodCertificateAuthKEP4317AndSPIFFEServerCheck(t *testing.T) {
	ctx := t.Context()
	pki := newTestPKI(t)
	srvSPIFFE := "spiffe://cluster.local/ns/sandbox-system/sa/portal"
	srvAddr, peerCh := startMTLSServer(t, pki, srvSPIFFE, true)

	kubeletRoot := t.TempDir()
	caPath := filepath.Join(kubeletRoot, "ca.crt")
	if err := os.WriteFile(caPath, pki.caCertPEM, 0o600); err != nil {
		t.Fatalf("write ca.crt: %v", err)
	}

	podUID := types.UID("pod-uid-4317")
	bundlePath := PodCertificateBundlePath(kubeletRoot, podUID, "")
	if err := os.MkdirAll(filepath.Dir(bundlePath), 0o700); err != nil {
		t.Fatalf("mkdir pod cert dir: %v", err)
	}

	podSPIFFE := "spiffe://cluster.local/ns/agents/sa/coding-agent"
	_, _, podCertPEM, podKeyPEM := pki.issueLeaf(t, "pod-4317", nil, podSPIFFE, false)
	bundleBytes := append(append([]byte(nil), podKeyPEM...), podCertPEM...)
	if err := os.WriteFile(bundlePath, bundleBytes, 0o600); err != nil {
		t.Fatalf("write credential-bundle.pem: %v", err)
	}

	resolver := NewResolver(ResolverConfig{KubeletRootDir: kubeletRoot})
	defer func() { _ = resolver.Close() }()

	cc, err := resolver.Resolve(ctx, ResolveRequest{
		PodNamespace: "agents",
		PodUID:       podUID,
		PolicyEnforcementPoint: &apis.PolicyEnforcementPointConfig{
			URL: "https://" + srvAddr,
			TLS: &apis.PEPTLS{
				CACertificateRefs: []apis.CASource{
					{Type: apis.CASourceTypeHostPath, HostPath: caPath},
				},
				AcceptedSPIFFEIDs: []string{srvSPIFFE},
			},
			Auth: &apis.PEPAuth{
				Type: apis.PEPAuthTypePodCertificate,
				PodCertificate: &apis.PodCertificateAuth{
					SignerName: "spiffe.io/workload-identity",
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("Resolve PodCertificate: %v", err)
	}
	if cc.AuthMode != AuthModePodCertificate {
		t.Fatalf("AuthMode = %q, want %q", cc.AuthMode, AuthModePodCertificate)
	}

	conn, err := tls.Dial("tcp", srvAddr, cc.TLSConfig)
	if err != nil {
		t.Fatalf("PodCertificate mTLS dial: %v", err)
	}
	_ = conn.Close()
	peer := <-peerCh
	if peer == nil || len(peer.URIs) != 1 || peer.URIs[0].String() != podSPIFFE {
		t.Fatalf("server saw PodCertificate SAN=%v, want %s", peer, podSPIFFE)
	}

	// Mismatched expected SPIFFE ID must fail closed during handshake.
	ccWrong, err := resolver.Resolve(ctx, ResolveRequest{
		PodNamespace: "agents",
		PodUID:       podUID,
		PolicyEnforcementPoint: &apis.PolicyEnforcementPointConfig{
			URL: "https://" + srvAddr,
			TLS: &apis.PEPTLS{
				CACertificateRefs: []apis.CASource{
					{Type: apis.CASourceTypeHostPath, HostPath: caPath},
				},
				AcceptedSPIFFEIDs: []string{"spiffe://cluster.local/ns/other/sa/wrong"},
			},
			Auth: &apis.PEPAuth{
				Type: apis.PEPAuthTypePodCertificate,
				PodCertificate: &apis.PodCertificateAuth{
					SignerName: "spiffe.io/workload-identity",
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("Resolve wrong SPIFFE ID: %v", err)
	}
	if conn, err := tls.Dial("tcp", srvAddr, ccWrong.TLSConfig); err == nil {
		_ = conn.Close()
		t.Fatalf("expected handshake failure for mismatched upstream SPIFFE ID")
	}
}

type fakeWorkloadAPIServer struct {
	workload.UnimplementedSpiffeWorkloadAPIServer
	spiffeID  string
	certDER   []byte
	keyDER    []byte
	bundleDER []byte
}

func (f *fakeWorkloadAPIServer) FetchX509SVID(_ *workload.X509SVIDRequest, stream grpc.ServerStreamingServer[workload.X509SVIDResponse]) error {
	if err := stream.Send(&workload.X509SVIDResponse{
		Svids: []*workload.X509SVID{
			{
				SpiffeId:    f.spiffeID,
				X509Svid:    f.certDER,
				X509SvidKey: f.keyDER,
				Bundle:      f.bundleDER,
			},
		},
	}); err != nil {
		return err
	}
	<-stream.Context().Done()
	return nil
}

func TestSPIFFEWorkloadAPIMTLS(t *testing.T) {
	ctx := t.Context()
	pki := newTestPKI(t)
	srvSPIFFE := "spiffe://cluster.local/ns/sandbox-system/sa/portal"
	srvAddr, peerCh := startMTLSServer(t, pki, srvSPIFFE, true)

	nodeSPIFFE := "spiffe://cluster.local/ns/sandbox-system/sa/dra-agents-net"
	nodeCertDER, nodeKeyDER, _, _ := pki.issueLeaf(t, "node-svid", nil, nodeSPIFFE, false)

	workloadSock := filepath.Join(t.TempDir(), "spire-agent.sock")
	wLn, err := net.Listen("unix", workloadSock)
	if err != nil {
		t.Fatalf("listen workload sock: %v", err)
	}
	wSrv := grpc.NewServer()
	workload.RegisterSpiffeWorkloadAPIServer(wSrv, &fakeWorkloadAPIServer{
		spiffeID:  nodeSPIFFE,
		certDER:   nodeCertDER,
		keyDER:    nodeKeyDER,
		bundleDER: pki.caCertDER,
	})
	go func() { _ = wSrv.Serve(wLn) }()
	t.Cleanup(func() { wSrv.Stop() })

	resolver := NewResolver(ResolverConfig{DefaultSPIFFEWorkloadSocket: workloadSock})
	defer func() { _ = resolver.Close() }()

	ccNode, err := resolver.Resolve(ctx, ResolveRequest{
		PodNamespace: "agents",
		PolicyEnforcementPoint: &apis.PolicyEnforcementPointConfig{
			URL:  "https://" + srvAddr,
			TLS:  &apis.PEPTLS{AcceptedSPIFFEIDs: []string{srvSPIFFE}},
			Auth: &apis.PEPAuth{Type: apis.PEPAuthTypeSPIFFE},
		},
	})
	if err != nil {
		t.Fatalf("Resolve SPIFFE: %v", err)
	}
	conn, err := tls.Dial("tcp", srvAddr, ccNode.TLSConfig)
	if err != nil {
		t.Fatalf("SPIFFE mTLS dial: %v", err)
	}
	_ = conn.Close()
	peer := <-peerCh
	if peer == nil || len(peer.URIs) != 1 || peer.URIs[0].String() != nodeSPIFFE {
		t.Fatalf("server saw SPIFFE SAN=%v, want %s", peer, nodeSPIFFE)
	}
}

func TestAttestedHeadersRFC8941AndSanitization(t *testing.T) {
	id := WorkloadIdentity{
		Namespace:      "agents",
		PodName:        "sb-1",
		PodUID:         "uid-123",
		SandboxID:      "gen-42",
		ServiceAccount: "runner",
		NodeName:       "node-1",
		Custom: map[string]string{
			"tenant_id": "team-a",
			"ns":        "forged-ns",
			"bad\r\n":   "injected\r\nEvil: 1",
		},
	}
	h := id.AttestedHeaders()
	if got := h.Get(HeaderPrincipal); got != "k8s://agents/runner/sb-1" {
		t.Fatalf("principal header = %q, want k8s://agents/runner/sb-1", got)
	}
	if got := h.Get(HeaderGeneration); got != "gen-42" {
		t.Fatalf("generation header = %q, want gen-42", got)
	}
	attrs := h.Get(HeaderAttributes)
	for _, want := range []string{`ns="agents"`, `pod="sb-1"`, `pod_uid="uid-123"`, `sa="runner"`, `node="node-1"`, `tenant_id="team-a"`} {
		if !strings.Contains(attrs, want) {
			t.Fatalf("Agents-Net-Attributes %q missing %q", attrs, want)
		}
	}
	if strings.Contains(attrs, "forged-ns") || strings.Contains(attrs, "Evil") {
		t.Fatalf("Agents-Net-Attributes must not allow custom override of platform fields or CRLF: %q", attrs)
	}
}

func TestSecurityHardeningMandatoryMTLSChecks(t *testing.T) {
	ctx := t.Context()
	tmp := t.TempDir()
	resolver := NewResolver(ResolverConfig{KubeletRootDir: tmp})
	defer func() { _ = resolver.Close() }()

	// 1. Plaintext http:// PEP URL is forbidden.
	if _, err := resolver.Resolve(ctx, ResolveRequest{
		PodNamespace: "agents",
		PodUID:       "pod-1",
		PolicyEnforcementPoint: &apis.PolicyEnforcementPointConfig{
			URL: "http://cleartext-pep:8080",
		},
	}); err == nil {
		t.Fatal("expected Resolve to reject cleartext http:// PEP URL")
	}

	// 2. https:// PEP without mandatory mTLS auth is forbidden.
	if _, err := resolver.Resolve(ctx, ResolveRequest{
		PodNamespace: "agents",
		PodUID:       "pod-1",
		PolicyEnforcementPoint: &apis.PolicyEnforcementPointConfig{
			URL: "https://pep:8443",
		},
	}); err == nil {
		t.Fatal("expected Resolve to reject https:// PEP without mTLS auth")
	}

	// 3. Local unix:// PEP without TLS succeeds as a capability socket.
	ccUnix, err := resolver.Resolve(ctx, ResolveRequest{
		PodNamespace: "agents",
		PodUID:       "pod-1",
		PolicyEnforcementPoint: &apis.PolicyEnforcementPointConfig{
			URL: "unix:///run/pep/egress.sock",
		},
	})
	if err != nil || ccUnix.AuthMode != AuthModeUnix {
		t.Fatalf("Resolve unix:// = (%+v, %v), want AuthModeUnix", ccUnix, err)
	}

	// 4. Path traversal in PodUID rejected for PodCertificate.
	if _, err := resolver.Resolve(ctx, ResolveRequest{
		PodNamespace:      "agents",
		PodUID:            "../../etc",
		PodCertVolumeName: "valid-vol",
		PolicyEnforcementPoint: &apis.PolicyEnforcementPointConfig{
			URL:  "https://pep:8443",
			Auth: &apis.PEPAuth{Type: apis.PEPAuthTypePodCertificate, PodCertificate: &apis.PodCertificateAuth{SignerName: "s"}},
		},
	}); err == nil {
		t.Fatal("expected PodCertificate to reject path-traversal PodUID")
	}

	// 5. SPIFFE authorizer fails closed with no constraints and rejects mismatched trustDomain + acceptedSPIFFEIDs.
	if _, err := buildSPIFFEAuthorizer(nil); err == nil {
		t.Fatal("expected buildSPIFFEAuthorizer(nil) to fail closed")
	}
	if _, err := buildSPIFFEAuthorizer(&apis.PEPTLS{}); err == nil {
		t.Fatal("expected buildSPIFFEAuthorizer({}) to fail closed")
	}
	if _, err := buildSPIFFEAuthorizer(&apis.PEPTLS{
		TrustDomain:       "cluster.local",
		AcceptedSPIFFEIDs: []string{"spiffe://other.domain/ns/a/sa/b"},
	}); err == nil {
		t.Fatal("expected buildSPIFFEAuthorizer to reject acceptedSPIFFEID outside trustDomain")
	}
}
