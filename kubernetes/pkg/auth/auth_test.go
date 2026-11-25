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
	"google.golang.org/protobuf/encoding/protowire"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	k8sfake "k8s.io/client-go/kubernetes/fake"

	"github.com/aojea/agents.net/kubernetes/pkg/apis"
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

func TestMTLSAuthDirRotationAndSecretRef(t *testing.T) {
	ctx := t.Context()
	pki := newTestPKI(t)
	srvAddr, peerCh := startMTLSServer(t, pki, "", true)

	// 1. Rotating certDir mode.
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

	// 2. Kubernetes Secret (cert-manager kubernetes.io/tls convention with ca.crt) + ConfigMap mode.
	_, _, secCertPEM, secKeyPEM := pki.issueLeaf(t, "secret-client", nil, "", false)
	fakeKube := k8sfake.NewClientset(
		&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Name: "upstream-ca", Namespace: "agents"},
			Data:       map[string]string{"ca.crt": string(pki.caCertPEM)},
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "client-tls", Namespace: "agents"},
			Type:       corev1.SecretTypeTLS,
			Data: map[string][]byte{
				"tls.crt": secCertPEM,
				"tls.key": secKeyPEM,
				"ca.crt":  pki.caCertPEM,
			},
		},
	)
	kubeResolver := NewResolver(ResolverConfig{KubeClient: fakeKube})
	defer func() { _ = kubeResolver.Close() }()

	// Verify both ConfigMap and Secret (cert-manager ca.crt) CA sources work in upstream.tls.caCertificateRefs.
	for _, caSrc := range []apis.CASource{
		{
			Type:         apis.CASourceTypeConfigMap,
			ConfigMapRef: &apis.ConfigMapKeyRef{Name: "upstream-ca"},
		},
		{
			Type:      apis.CASourceTypeSecret,
			SecretRef: &apis.SecretKeyRef{Name: "client-tls"},
		},
	} {
		ccSec, err := kubeResolver.Resolve(ctx, ResolveRequest{
			PodNamespace: "agents",
			PolicyEnforcementPoint: &apis.PolicyEnforcementPointConfig{
				URL: "https://" + srvAddr,
				TLS: &apis.PEPTLS{
					ServerName:        "upstream.local",
					CACertificateRefs: []apis.CASource{caSrc},
				},
				Auth: &apis.PEPAuth{
					Type: apis.PEPAuthTypeMTLS,
					MTLS: &apis.MTLSAuth{
						SecretRef: &corev1.LocalObjectReference{Name: "client-tls"},
					},
				},
			},
		})
		if err != nil {
			t.Fatalf("Resolve MTLS secretRef (%s): %v", caSrc.Type, err)
		}
		conn, err = tls.Dial("tcp", srvAddr, ccSec.TLSConfig)
		if err != nil {
			t.Fatalf("mTLS dial secretRef (%s): %v", caSrc.Type, err)
		}
		_ = conn.Close()
		if peer := <-peerCh; peer == nil || peer.Subject.CommonName != "secret-client" {
			t.Fatalf("server saw secretRef (%s) peer CN=%v, want secret-client", caSrc.Type, peer)
		}
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

	// KEP-4317 credential bundle format: PKCS#8 PRIVATE KEY block followed by CERTIFICATE block(s).
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

func TestServiceAccountTokenNodeAndPodModesWithRotation(t *testing.T) {
	ctx := t.Context()
	kubeletRoot := t.TempDir()
	nodeTokPath := filepath.Join(kubeletRoot, "node-token")
	if err := os.WriteFile(nodeTokPath, []byte("jwt-node-v1\n"), 0o600); err != nil {
		t.Fatalf("write node token: %v", err)
	}

	podUID := types.UID("pod-uid-jwt")
	podTokPath := PodSATokenPath(kubeletRoot, podUID, "")
	if err := os.MkdirAll(filepath.Dir(podTokPath), 0o700); err != nil {
		t.Fatalf("mkdir pod token dir: %v", err)
	}
	if err := os.WriteFile(podTokPath, []byte("jwt-pod-v1"), 0o600); err != nil {
		t.Fatalf("write pod token: %v", err)
	}

	resolver := NewResolver(ResolverConfig{
		KubeletRootDir:       kubeletRoot,
		DefaultNodeTokenPath: nodeTokPath,
	})
	defer func() { _ = resolver.Close() }()

	// 1. Node mode (service-portals style).
	ccNode, err := resolver.Resolve(ctx, ResolveRequest{
		PodNamespace: "agents",
		PodUID:       podUID,
		PolicyEnforcementPoint: &apis.PolicyEnforcementPointConfig{
			URL: "https://portal.corp:8443",
			Auth: &apis.PEPAuth{
				Type: apis.PEPAuthTypeServiceAccountToken,
				ServiceAccountToken: &apis.ServiceAccountTokenAuth{
					Audience: "https://portal.corp",
					Mode:     apis.ServiceAccountTokenModeNode,
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("Resolve SA token Node mode: %v", err)
	}
	hdr, err := ccNode.ProxyAuthorization(ctx)
	if err != nil || hdr != "Bearer jwt-node-v1" {
		t.Fatalf("Node ProxyAuthorization = %q err=%v, want Bearer jwt-node-v1", hdr, err)
	}

	// 2. Pod mode with rotation.
	ccPod, err := resolver.Resolve(ctx, ResolveRequest{
		PodNamespace: "agents",
		PodUID:       podUID,
		PolicyEnforcementPoint: &apis.PolicyEnforcementPointConfig{
			URL: "https://portal.corp:8443",
			Auth: &apis.PEPAuth{
				Type: apis.PEPAuthTypeServiceAccountToken,
				ServiceAccountToken: &apis.ServiceAccountTokenAuth{
					Audience: "https://portal.corp",
					Mode:     apis.ServiceAccountTokenModePod,
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("Resolve SA token Pod mode: %v", err)
	}
	hdr, err = ccPod.ProxyAuthorization(ctx)
	if err != nil || hdr != "Bearer jwt-pod-v1" {
		t.Fatalf("Pod ProxyAuthorization v1 = %q err=%v, want Bearer jwt-pod-v1", hdr, err)
	}

	if err := os.WriteFile(podTokPath, []byte("jwt-pod-v2-rotated"), 0o600); err != nil {
		t.Fatalf("rotate pod token: %v", err)
	}
	future := time.Now().Add(2 * time.Second)
	_ = os.Chtimes(podTokPath, future, future)

	hdr, err = ccPod.ProxyAuthorization(ctx)
	if err != nil || hdr != "Bearer jwt-pod-v2-rotated" {
		t.Fatalf("Pod ProxyAuthorization v2 = %q err=%v, want Bearer jwt-pod-v2-rotated", hdr, err)
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

func TestSPIFFENodeWorkloadAPIAndDelegatedPodModes(t *testing.T) {
	ctx := t.Context()
	pki := newTestPKI(t)
	srvSPIFFE := "spiffe://cluster.local/ns/sandbox-system/sa/portal"
	srvAddr, peerCh := startMTLSServer(t, pki, srvSPIFFE, true)

	// 1. SPIFFE Node mode over real SPIFFE Workload API UDS.
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
			URL: "https://" + srvAddr,
			TLS: &apis.PEPTLS{AcceptedSPIFFEIDs: []string{srvSPIFFE}},
			Auth: &apis.PEPAuth{
				Type:   apis.PEPAuthTypeSPIFFE,
				SPIFFE: &apis.SPIFFEAuth{Mode: apis.SPIFFEModeNode},
			},
		},
	})
	if err != nil {
		t.Fatalf("Resolve SPIFFE Node mode: %v", err)
	}
	conn, err := tls.Dial("tcp", srvAddr, ccNode.TLSConfig)
	if err != nil {
		t.Fatalf("SPIFFE Node mTLS dial: %v", err)
	}
	_ = conn.Close()
	peer := <-peerCh
	if peer == nil || len(peer.URIs) != 1 || peer.URIs[0].String() != nodeSPIFFE {
		t.Fatalf("server saw SPIFFE Node SAN=%v, want %s", peer, nodeSPIFFE)
	}

	// 2. SPIFFE DelegatedPod mode over real SPIRE Delegated Identity v1 UDS.
	podUID := types.UID("pod-uid-delegated-99")
	podSPIFFE := "spiffe://cluster.local/ns/agents/sa/isolated-agent"
	podCertDER, podKeyDER, _, _ := pki.issueLeaf(t, "delegated-pod", nil, podSPIFFE, false)

	delegatedSock := filepath.Join(t.TempDir(), "spire-admin.sock")
	dLn, err := net.Listen("unix", delegatedSock)
	if err != nil {
		t.Fatalf("listen delegated sock: %v", err)
	}
	var observedReq []byte
	dSrv := grpc.NewServer(grpc.UnknownServiceHandler(func(_ any, stream grpc.ServerStream) error {
		method, _ := grpc.MethodFromServerStream(stream)
		var req []byte
		if err := stream.RecvMsg(&req); err != nil {
			return err
		}
		switch method {
		case spireDelegatedSVIDMethod:
			observedReq = append([]byte(nil), req...)
			// Encode SubscribeToX509SVIDsResponse -> X509SVIDWithKey -> X509SVID{cert_chain} + key
			var svidMsg []byte
			svidMsg = protowire.AppendTag(svidMsg, 1, protowire.BytesType)
			svidMsg = protowire.AppendBytes(svidMsg, podCertDER)

			var withKey []byte
			withKey = protowire.AppendTag(withKey, 1, protowire.BytesType)
			withKey = protowire.AppendBytes(withKey, svidMsg)
			withKey = protowire.AppendTag(withKey, 2, protowire.BytesType)
			withKey = protowire.AppendBytes(withKey, podKeyDER)

			var resp []byte
			resp = protowire.AppendTag(resp, 1, protowire.BytesType)
			resp = protowire.AppendBytes(resp, withKey)
			if err := stream.SendMsg(resp); err != nil {
				return err
			}
			<-stream.Context().Done()
			return nil
		case spireDelegatedBundleMethod:
			// Encode SubscribeToX509BundlesResponse -> map<string, bytes> ca_certificates
			var entry []byte
			entry = protowire.AppendTag(entry, 1, protowire.BytesType)
			entry = protowire.AppendString(entry, "cluster.local")
			entry = protowire.AppendTag(entry, 2, protowire.BytesType)
			entry = protowire.AppendBytes(entry, pki.caCertDER)

			var resp []byte
			resp = protowire.AppendTag(resp, 1, protowire.BytesType)
			resp = protowire.AppendBytes(resp, entry)
			if err := stream.SendMsg(resp); err != nil {
				return err
			}
			<-stream.Context().Done()
			return nil
		}
		return nil
	}), grpc.ForceServerCodec(rawBytesCodec{}))
	go func() { _ = dSrv.Serve(dLn) }()
	t.Cleanup(func() { dSrv.Stop() })

	ccPod, err := resolver.Resolve(ctx, ResolveRequest{
		PodNamespace: "agents",
		PodUID:       podUID,
		PolicyEnforcementPoint: &apis.PolicyEnforcementPointConfig{
			URL: "https://" + srvAddr,
			TLS: &apis.PEPTLS{TrustDomain: "cluster.local"},
			Auth: &apis.PEPAuth{
				Type: apis.PEPAuthTypeSPIFFE,
				SPIFFE: &apis.SPIFFEAuth{
					Mode:                apis.SPIFFEModeDelegatedPod,
					DelegatedSocketPath: delegatedSock,
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("Resolve SPIFFE DelegatedPod mode: %v", err)
	}
	defer func() { _ = ccPod.Close() }()

	if !strings.Contains(string(observedReq), "pod-uid:"+string(podUID)) {
		t.Fatalf("expected delegated identity request to select pod-uid:%s", podUID)
	}

	conn, err = tls.Dial("tcp", srvAddr, ccPod.TLSConfig)
	if err != nil {
		t.Fatalf("SPIFFE DelegatedPod mTLS dial: %v", err)
	}
	_ = conn.Close()
	peer = <-peerCh
	if peer == nil || len(peer.URIs) != 1 || peer.URIs[0].String() != podSPIFFE {
		t.Fatalf("server saw SPIFFE DelegatedPod SAN=%v, want %s", peer, podSPIFFE)
	}
}

func TestAttestedHeadersSanitization(t *testing.T) {
	id := WorkloadIdentity{
		Namespace:      "agents",
		PodName:        "sb-1",
		PodUID:         "uid-123",
		ServiceAccount: "default",
		NodeName:       "node-1",
		SandboxName:    "sb-1",
		ClaimUID:       "claim-uid",
		ClaimName:      "claim-1",
		Custom: map[string]string{
			"tenant_id": "team-a",
			"bad\r\n":   "injected\r\nEvil: 1",
		},
	}
	h := id.AttestedHeaders()
	if got := h.Get(HeaderSandboxNamespace); got != "agents" {
		t.Fatalf("namespace header = %q, want agents", got)
	}
	if got := h.Get(HeaderCustomPrefix + "tenant_id"); got != "team-a" {
		t.Fatalf("custom header = %q, want team-a", got)
	}
	if got := h.Get(HeaderCustomPrefix + "bad"); got != "" {
		t.Fatalf("CRLF-containing custom parameter must be dropped, got %q", got)
	}

	// ClaimName annotation containing CRLF must also be dropped.
	idInjected := WorkloadIdentity{
		Namespace: "agents",
		ClaimName: "claim-1\r\nProxy-Authorization: Bearer evil",
	}
	if got := idInjected.AttestedHeaders().Get(HeaderClaimName); got != "" {
		t.Fatalf("CRLF-containing ClaimName must be dropped, got %q", got)
	}
}

func TestSecurityHardeningAuthChecks(t *testing.T) {
	ctx := t.Context()
	tmp := t.TempDir()
	badTokPath := filepath.Join(tmp, "bad-token")
	_ = os.WriteFile(badTokPath, []byte("jwt\r\nEvil: 1"), 0o600)

	resolver := NewResolver(ResolverConfig{
		KubeletRootDir:       tmp,
		DefaultNodeTokenPath: badTokPath,
	})
	defer func() { _ = resolver.Close() }()

	// 1. ServiceAccountToken rejects cleartext http:// URL.
	if _, err := resolver.Resolve(ctx, ResolveRequest{
		PodNamespace: "agents",
		PodUID:       "pod-1",
		PolicyEnforcementPoint: &apis.PolicyEnforcementPointConfig{
			URL: "http://cleartext-pep:8080",
			Auth: &apis.PEPAuth{
				Type:                apis.PEPAuthTypeServiceAccountToken,
				ServiceAccountToken: &apis.ServiceAccountTokenAuth{Audience: "pep"},
			},
		},
	}); err == nil {
		t.Fatal("expected ServiceAccountToken to reject cleartext http:// PEP URL")
	}

	// 2. BearerHeader rejects token containing CR/LF.
	cc, err := resolver.Resolve(ctx, ResolveRequest{
		PodNamespace: "agents",
		PodUID:       "pod-1",
		PolicyEnforcementPoint: &apis.PolicyEnforcementPointConfig{
			URL: "https://pep:8443",
			Auth: &apis.PEPAuth{
				Type:                apis.PEPAuthTypeServiceAccountToken,
				ServiceAccountToken: &apis.ServiceAccountTokenAuth{Audience: "pep"},
			},
		},
	})
	if err != nil {
		t.Fatalf("Resolve SA token: %v", err)
	}
	if _, err := cc.ProxyAuthorization(ctx); err == nil {
		t.Fatal("expected BearerHeader to reject token with CRLF")
	}

	// 3. Path traversal in PodUID and volume names rejected for PodCertificate and Pod SA token.
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
	if _, err := resolver.Resolve(ctx, ResolveRequest{
		PodNamespace:      "agents",
		PodUID:            "pod-ok",
		SATokenVolumeName: "../escape",
		PolicyEnforcementPoint: &apis.PolicyEnforcementPointConfig{
			URL: "https://pep:8443",
			Auth: &apis.PEPAuth{
				Type:                apis.PEPAuthTypeServiceAccountToken,
				ServiceAccountToken: &apis.ServiceAccountTokenAuth{Audience: "pep", Mode: apis.ServiceAccountTokenModePod},
			},
		},
	}); err == nil {
		t.Fatal("expected Pod SA token to reject path-traversal volumeName")
	}

	// 4. SPIFFE authorizer fails closed with no constraints and rejects mismatched trustDomain + acceptedSPIFFEIDs.
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

	// 5. Empty delegated SVID response signals revocation (errEmptyDelegatedSVIDs).
	if _, err := decodeFirstDelegatedSVID(nil); err != errEmptyDelegatedSVIDs {
		t.Fatalf("decodeFirstDelegatedSVID(nil) err = %v, want errEmptyDelegatedSVIDs", err)
	}
}
