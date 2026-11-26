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

package catrust

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	certificatesv1beta1 "k8s.io/api/certificates/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sfake "k8s.io/client-go/kubernetes/fake"

	"github.com/aojea/agents.net/pkg/apis"
)

func makeSelfSignedCAPEM(t *testing.T, cn string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<60))
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestMaterializeAllSourcesAppendAndReplace(t *testing.T) {
	ctx := t.Context()
	sysCA := makeSelfSignedCAPEM(t, "system-root-ca")
	cmCA := makeSelfSignedCAPEM(t, "configmap-ca")
	ctbCA := makeSelfSignedCAPEM(t, "ctb-ca")
	hostCA := makeSelfSignedCAPEM(t, "host-ca")

	// Include a stray PRIVATE KEY block alongside a ConfigMap CA cert to verify
	// Materialize extracts only valid CERTIFICATE PEM blocks.
	cmDataWithKey := append([]byte("-----BEGIN PRIVATE KEY-----\nZmFrZS1rZXk=\n-----END PRIVATE KEY-----\n"), cmCA...)

	tmp := t.TempDir()
	sysPath := filepath.Join(tmp, "sys-roots.pem")
	hostPath := filepath.Join(tmp, "host-ca.pem")
	_ = os.WriteFile(sysPath, sysCA, 0o600)
	_ = os.WriteFile(hostPath, hostCA, 0o600)

	fakeKube := k8sfake.NewClientset(
		&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Name: "corp-ca", Namespace: "agents"},
			Data:       map[string]string{"ca.crt": string(cmDataWithKey)},
		},
		&certificatesv1beta1.ClusterTrustBundle{
			ObjectMeta: metav1.ObjectMeta{Name: "egress-ctb", Labels: map[string]string{"env": "prod"}},
			Spec: certificatesv1beta1.ClusterTrustBundleSpec{
				SignerName:  "example.com/egress-ca",
				TrustBundle: string(ctbCA),
			},
		},
	)

	mat := NewMaterializer(fakeKube, sysPath)
	spec := &apis.CATrustConfig{
		Mode:       apis.CATrustModeInjectEnv,
		BundleMode: apis.CABundleModeAppendSystemRoots,
		Sources: []apis.CASource{
			{
				Type:         apis.CASourceTypeConfigMap,
				ConfigMapRef: &apis.ConfigMapKeyRef{Name: "corp-ca"},
			},
			{
				Type: apis.CASourceTypeClusterTrustBundle,
				ClusterTrustBundle: &apis.ClusterTrustBundleRef{
					SignerName:    "example.com/egress-ca",
					LabelSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"env": "prod"}},
				},
			},
			{
				Type:     apis.CASourceTypeHostPath,
				HostPath: hostPath,
			},
		},
	}

	outDir := filepath.Join(tmp, "out-append")
	bundle, err := mat.Materialize(ctx, spec, "agents", outDir)
	if err != nil {
		t.Fatalf("Materialize AppendSystemRoots: %v", err)
	}

	merged, err := os.ReadFile(bundle.MergedHostPath)
	if err != nil {
		t.Fatalf("read merged: %v", err)
	}
	extra, err := os.ReadFile(bundle.ExtraHostPath)
	if err != nil {
		t.Fatalf("read extra: %v", err)
	}

	if strings.Contains(string(merged), "PRIVATE KEY") || strings.Contains(string(extra), "PRIVATE KEY") {
		t.Fatalf("private key leaked into materialized CA bundle")
	}

	// Merged bundle has system root + 3 custom CAs = 4 certs.
	if got := strings.Count(string(merged), "BEGIN CERTIFICATE"); got != 4 {
		t.Fatalf("merged cert count = %d, want 4", got)
	}
	// Extra bundle (for NODE_EXTRA_CA_CERTS) has only the 3 custom CAs.
	if got := strings.Count(string(extra), "BEGIN CERTIFICATE"); got != 3 {
		t.Fatalf("extra cert count = %d, want 3", got)
	}

	// Replace mode must NOT include system root CA.
	spec.BundleMode = apis.CABundleModeReplace
	bundleRep, err := mat.Materialize(ctx, spec, "agents", filepath.Join(tmp, "out-replace"))
	if err != nil {
		t.Fatalf("Materialize Replace: %v", err)
	}
	repBytes, _ := os.ReadFile(bundleRep.MergedHostPath)
	if got := strings.Count(string(repBytes), "BEGIN CERTIFICATE"); got != 3 {
		t.Fatalf("replace cert count = %d, want 3", got)
	}

	// Verify env var mapping covers agents.net + all major runtimes.
	envs := EnvVars("", "")
	for _, key := range []string{
		"AGENT_CA_CERT", "AGENTS_NET_CA_BUNDLE", "SSL_CERT_FILE",
		"REQUESTS_CA_BUNDLE", "PIP_CERT", "CURL_CA_BUNDLE", "GIT_SSL_CAINFO",
		"NODE_EXTRA_CA_CERTS", "NPM_CONFIG_CAFILE", "DENO_CERT",
		"CARGO_HTTP_CAINFO", "AWS_CA_BUNDLE", "CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE",
	} {
		if envs[key] == "" {
			t.Fatalf("missing CA env var %q", key)
		}
	}
	if envs["NODE_EXTRA_CA_CERTS"] != ContainerExtraCAPath {
		t.Fatalf("NODE_EXTRA_CA_CERTS = %q, want %q", envs["NODE_EXTRA_CA_CERTS"], ContainerExtraCAPath)
	}
}

func TestCATrustValidationAndRegularFileEnforcement(t *testing.T) {
	ctx := t.Context()
	mat := NewMaterializer(nil, "")
	outDir := filepath.Join(t.TempDir(), "out")

	// Reject special device files like /dev/null (non-regular).
	if _, err := mat.Materialize(ctx, &apis.CATrustConfig{
		Mode: apis.CATrustModeInjectEnv,
		Sources: []apis.CASource{
			{Type: apis.CASourceTypeHostPath, HostPath: "/dev/null"},
		},
	}, "default", outDir); err == nil {
		t.Fatal("expected Materialize to reject non-regular file /dev/null")
	}

	// Reject unknown Mode and BundleMode enums.
	if _, err := mat.Materialize(ctx, &apis.CATrustConfig{
		Mode: apis.CATrustMode("InvalidMode"),
	}, "default", outDir); err == nil {
		t.Fatal("expected Materialize to reject unknown Mode")
	}
	if _, err := mat.Materialize(ctx, &apis.CATrustConfig{
		Mode:       apis.CATrustModeInjectEnv,
		BundleMode: apis.CABundleMode("InvalidBundleMode"),
		Sources: []apis.CASource{
			{Type: apis.CASourceTypeHostPath, HostPath: "/dev/null"},
		},
	}, "default", outDir); err == nil {
		t.Fatal("expected Materialize to reject unknown BundleMode")
	}
}
