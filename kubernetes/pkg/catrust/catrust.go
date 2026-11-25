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

// Package catrust resolves declarative CA certificate sources (ConfigMap,
// Kubernetes ClusterTrustBundle, HostPath), materializes per-Pod PEM bundles
// (merged system roots + custom CAs, and custom-only CAs for additive runtimes),
// and computes the agents.net and multi-language TLS trust environment variables.
package catrust

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"

	"github.com/aojea/agents.net/kubernetes/pkg/apis"
)

const (
	// ContainerCABundlePath is the canonical agents.net CA bundle path mounted read-only
	// inside workload containers (matching agents.net Section 2.3.B: AGENT_CA_CERT).
	ContainerCABundlePath = "/var/run/agent-ca.pem"

	// ContainerExtraCAPath is the custom-only CA bundle path mounted read-only inside
	// workload containers for runtimes whose env var appends to built-in roots (for
	// example NODE_EXTRA_CA_CERTS).
	ContainerExtraCAPath = "/var/run/agent-extra-ca.pem"

	mergedBundleFilename = "agent-ca.pem"
	extraBundleFilename  = "agent-extra-ca.pem"

	// maxCABundleBytes caps host CA bundle reads to prevent OOM DoS from
	// oversized files or special devices.
	maxCABundleBytes = 4 * 1024 * 1024
)

// defaultSystemRootFiles lists standard Linux distribution system CA bundle locations.
var defaultSystemRootFiles = []string{
	"/etc/ssl/certs/ca-certificates.crt", // Debian / Ubuntu / Alpine / Gentoo
	"/etc/pki/tls/certs/ca-bundle.crt",   // Fedora / RHEL / Rocky / Amazon Linux
	"/etc/ssl/ca-bundle.pem",             // openSUSE
	"/etc/ssl/cert.pem",                  // Alpine / BSD / macOS
}

// MaterializedBundle holds the host paths written for a single Pod's CA bundles.
type MaterializedBundle struct {
	MergedHostPath string `json:"mergedHostPath,omitempty"`
	ExtraHostPath  string `json:"extraHostPath,omitempty"`
}

// Materializer resolves CA sources and writes per-Pod CA bundle files on the host.
type Materializer struct {
	kubeClient      kubernetes.Interface
	systemRootsPath string
}

// NewMaterializer constructs a Materializer. If systemRootsPath is empty, the first
// readable file from standard Linux system root paths is used for AppendSystemRoots mode.
func NewMaterializer(kubeClient kubernetes.Interface, systemRootsPath string) *Materializer {
	return &Materializer{
		kubeClient:      kubeClient,
		systemRootsPath: systemRootsPath,
	}
}

// Materialize resolves spec.Sources, validates every PEM certificate, and writes
// agent-ca.pem (merged or custom-only per BundleMode) and agent-extra-ca.pem under outDir.
// Returns an empty MaterializedBundle with nil error when caTrust is nil or Mode is None.
func (m *Materializer) Materialize(
	ctx context.Context,
	spec *apis.CATrustConfig,
	namespace string,
	outDir string,
) (MaterializedBundle, error) {
	if spec == nil {
		return MaterializedBundle{}, nil
	}
	switch spec.Mode {
	case "", apis.CATrustModeInjectEnv, apis.CATrustModeMountOnly:
	case apis.CATrustModeNone:
		return MaterializedBundle{}, nil
	default:
		return MaterializedBundle{}, fmt.Errorf("unsupported caTrust mode %q", spec.Mode)
	}
	if len(spec.Sources) == 0 {
		return MaterializedBundle{}, nil
	}

	bundleMode := spec.BundleMode
	if bundleMode == "" {
		bundleMode = apis.CABundleModeAppendSystemRoots
	}
	switch bundleMode {
	case apis.CABundleModeAppendSystemRoots, apis.CABundleModeReplace:
	default:
		return MaterializedBundle{}, fmt.Errorf("unsupported caTrust bundleMode %q", bundleMode)
	}

	customBytes, err := LoadSourcesPEM(ctx, m.kubeClient, spec.Sources, namespace)
	if err != nil {
		return MaterializedBundle{}, err
	}

	var mergedBuf bytes.Buffer
	if bundleMode == apis.CABundleModeAppendSystemRoots {
		sysRoots, err := m.loadSystemRoots()
		if err != nil {
			return MaterializedBundle{}, fmt.Errorf("load system root CAs for AppendSystemRoots: %w", err)
		}
		mergedBuf.Write(sysRoots)
		if len(sysRoots) > 0 && sysRoots[len(sysRoots)-1] != '\n' {
			mergedBuf.WriteByte('\n')
		}
	}
	mergedBuf.Write(customBytes)

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return MaterializedBundle{}, fmt.Errorf("create CA bundle dir %q: %w", outDir, err)
	}

	mergedPath := filepath.Join(outDir, mergedBundleFilename)
	extraPath := filepath.Join(outDir, extraBundleFilename)
	if err := os.WriteFile(mergedPath, mergedBuf.Bytes(), 0o644); err != nil {
		return MaterializedBundle{}, fmt.Errorf("write merged CA bundle %q: %w", mergedPath, err)
	}
	if err := os.WriteFile(extraPath, customBytes, 0o644); err != nil {
		return MaterializedBundle{}, fmt.Errorf("write extra CA bundle %q: %w", extraPath, err)
	}

	// TODO(dra-agents-net): Generate a PKCS#12 truststore (cacerts.p12) from mergedBuf
	// and append -Djavax.net.ssl.trustStore / -Djavax.net.ssl.trustStoreType=PKCS12
	// to JAVA_TOOL_OPTIONS so JVM workloads trust custom Pod CA certificates automatically.

	return MaterializedBundle{
		MergedHostPath: mergedPath,
		ExtraHostPath:  extraPath,
	}, nil
}

// EnvVars returns the agents.net and multi-language CA trust environment variables
// mapped to ContainerCABundlePath (merged) and ContainerExtraCAPath (custom-only).
func EnvVars(mergedPath, extraPath string) map[string]string {
	if mergedPath == "" {
		mergedPath = ContainerCABundlePath
	}
	if extraPath == "" {
		extraPath = ContainerExtraCAPath
	}
	return map[string]string{
		// agents.net specification (Section 2.3.B)
		"AGENT_CA_CERT":              mergedPath,
		"AGENTS_NET_CA_BUNDLE":       mergedPath,
		"AGENTS_NET_EXTRA_CA_BUNDLE": extraPath,
		// OpenSSL, Go, Rust (openssl-probe), Ruby, PHP, Debian/Alpine tools
		"SSL_CERT_FILE": mergedPath,
		// Python (requests, urllib3, httpx, pip, uv, aiohttp)
		"REQUESTS_CA_BUNDLE": mergedPath,
		"PIP_CERT":           mergedPath,
		// curl / libcurl and git
		"CURL_CA_BUNDLE": mergedPath,
		"GIT_SSL_CAINFO": mergedPath,
		// Node.js / Bun (additive extra CAs) and npm
		"NODE_EXTRA_CA_CERTS": extraPath,
		"NPM_CONFIG_CAFILE":   mergedPath,
		// Deno
		"DENO_CERT": mergedPath,
		// Rust / Cargo
		"CARGO_HTTP_CAINFO": mergedPath,
		// Cloud CLIs and SDKs
		"AWS_CA_BUNDLE":                      mergedPath,
		"CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE": mergedPath,
	}
}

// LoadSourcesPEM resolves one or more SandboxCASource entries in namespace, strictly
// extracts valid X.509 CERTIFICATE PEM blocks (ignoring any private keys or non-cert
// blocks), and returns the concatenated PEM bundle.
func LoadSourcesPEM(ctx context.Context, kubeClient kubernetes.Interface, sources []apis.CASource, namespace string) ([]byte, error) {
	var buf bytes.Buffer
	for i, src := range sources {
		raw, err := loadSource(ctx, kubeClient, src, namespace)
		if err != nil {
			return nil, fmt.Errorf("ca source[%d] (%s): %w", i, src.Type, err)
		}
		cleanPEM, err := normalizeAndValidateCertPEM(raw)
		if err != nil {
			return nil, fmt.Errorf("ca source[%d] (%s): %w", i, src.Type, err)
		}
		buf.Write(cleanPEM)
	}
	return buf.Bytes(), nil
}

func loadSource(ctx context.Context, kubeClient kubernetes.Interface, src apis.CASource, namespace string) ([]byte, error) {
	switch src.Type {
	case apis.CASourceTypeConfigMap:
		if src.ConfigMapRef == nil || src.ConfigMapRef.Name == "" {
			return nil, errors.New("configMapRef.name is required")
		}
		if kubeClient == nil {
			return nil, errors.New("kubernetes client is required to read ConfigMap CA source")
		}
		cm, err := kubeClient.CoreV1().ConfigMaps(namespace).Get(ctx, src.ConfigMapRef.Name, metav1.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("get ConfigMap %s/%s: %w", namespace, src.ConfigMapRef.Name, err)
		}
		key := src.ConfigMapRef.Key
		if key == "" {
			key = "ca.crt"
		}
		val, ok := cm.Data[key]
		if !ok || strings.TrimSpace(val) == "" {
			return nil, fmt.Errorf("ConfigMap %s/%s missing non-empty key %q", namespace, cm.Name, key)
		}
		return []byte(val), nil

	case apis.CASourceTypeClusterTrustBundle:
		if src.ClusterTrustBundle == nil {
			return nil, errors.New("clusterTrustBundle ref is required")
		}
		if kubeClient == nil {
			return nil, errors.New("kubernetes client is required to read ClusterTrustBundle CA source")
		}
		ref := src.ClusterTrustBundle
		if ref.Name != "" {
			ctb, err := kubeClient.CertificatesV1beta1().ClusterTrustBundles().Get(ctx, ref.Name, metav1.GetOptions{})
			if err != nil {
				return nil, fmt.Errorf("get ClusterTrustBundle %q: %w", ref.Name, err)
			}
			return []byte(ctb.Spec.TrustBundle), nil
		}
		if ref.SignerName == "" {
			return nil, errors.New("clusterTrustBundle requires name or signerName")
		}
		listOpts := metav1.ListOptions{}
		if ref.LabelSelector != nil {
			sel, err := metav1.LabelSelectorAsSelector(ref.LabelSelector)
			if err != nil {
				return nil, fmt.Errorf("invalid labelSelector: %w", err)
			}
			listOpts.LabelSelector = sel.String()
		}
		list, err := kubeClient.CertificatesV1beta1().ClusterTrustBundles().List(ctx, listOpts)
		if err != nil {
			return nil, fmt.Errorf("list ClusterTrustBundles: %w", err)
		}
		var out bytes.Buffer
		matched := 0
		for i := range list.Items {
			item := &list.Items[i]
			if item.Spec.SignerName != ref.SignerName {
				continue
			}
			if ref.LabelSelector != nil {
				sel, _ := metav1.LabelSelectorAsSelector(ref.LabelSelector)
				if !sel.Matches(labels.Set(item.Labels)) {
					continue
				}
			}
			matched++
			out.WriteString(item.Spec.TrustBundle)
			if !strings.HasSuffix(item.Spec.TrustBundle, "\n") {
				out.WriteByte('\n')
			}
		}
		if matched == 0 {
			return nil, fmt.Errorf("no ClusterTrustBundle matched signerName %q", ref.SignerName)
		}
		return out.Bytes(), nil

	case apis.CASourceTypeHostPath:
		if src.HostPath == "" {
			return nil, errors.New("hostPath is required")
		}
		data, err := readBoundedRegularFile(src.HostPath, maxCABundleBytes)
		if err != nil {
			return nil, fmt.Errorf("read host CA file %q: %w", src.HostPath, err)
		}
		return data, nil

	default:
		return nil, fmt.Errorf("unsupported CA source type %q", src.Type)
	}
}

func readBoundedRegularFile(path string, maxBytes int64) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("path %q must be absolute", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("path %q is not a regular file", path)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("file %q exceeds maximum allowed size of %d bytes", path, maxBytes)
	}
	return data, nil
}

func (m *Materializer) loadSystemRoots() ([]byte, error) {
	if m.systemRootsPath != "" {
		data, err := readBoundedRegularFile(m.systemRootsPath, maxCABundleBytes)
		if err != nil {
			return nil, err
		}
		return normalizeAndValidateCertPEM(data)
	}
	for _, candidate := range defaultSystemRootFiles {
		data, err := readBoundedRegularFile(candidate, maxCABundleBytes)
		if err == nil && len(data) > 0 {
			if clean, perr := normalizeAndValidateCertPEM(data); perr == nil {
				return clean, nil
			}
		}
	}
	return nil, errors.New("no readable system root CA bundle found on host")
}

func normalizeAndValidateCertPEM(raw []byte) ([]byte, error) {
	var out bytes.Buffer
	count := 0
	rest := raw
	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = remaining
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("invalid X.509 certificate in PEM bundle: %w", err)
		}
		// Re-encode strictly from cert.Raw so arbitrary PEM headers are never copied.
		out.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
		count++
	}
	if count == 0 {
		return nil, errors.New("no valid CERTIFICATE PEM blocks found")
	}
	return out.Bytes(), nil
}
