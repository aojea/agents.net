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

package main

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
	"testing"
	"time"
)

func TestBuildIngressMTLSConfigAndClientSANVerification(t *testing.T) {
	// Missing any mTLS file must fail closed.
	if _, err := buildIngressMTLSConfig("", "", "", nil); err == nil {
		t.Fatal("expected error when ingress mTLS flags are empty")
	}
	if _, err := buildIngressMTLSConfig("cert", "key", "", nil); err == nil {
		t.Fatal("expected error when --ingress-client-ca is missing")
	}

	// Generate CA + server cert + authorized client + unauthorized client.
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)

	issue := func(dns string, uri string, isServer bool) ([]byte, []byte, tls.Certificate) {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		serial, _ := rand.Int(rand.Reader, big.NewInt(1<<60))
		tmpl := &x509.Certificate{
			SerialNumber: serial,
			Subject:      pkix.Name{CommonName: dns},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		}
		if dns != "" {
			tmpl.DNSNames = []string{dns}
		}
		if uri != "" {
			u, _ := url.Parse(uri)
			tmpl.URIs = []*url.URL{u}
		}
		if isServer {
			tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		} else {
			tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		}
		der, _ := x509.CreateCertificate(rand.Reader, tmpl, caCert, &k.PublicKey, caKey)
		kDER, _ := x509.MarshalPKCS8PrivateKey(k)
		cPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		kPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kDER})
		pair, _ := tls.X509KeyPair(cPEM, kPEM)
		return cPEM, kPEM, pair
	}

	dir := t.TempDir()
	srvCertPEM, srvKeyPEM, _ := issue("dra-agents-net.local", "", true)
	_, _, goodClient := issue("agents-net-ingress-gateway", "spiffe://cluster.local/ns/kube-system/sa/gateway", false)
	_, _, badClient := issue("rogue-client", "spiffe://cluster.local/ns/default/sa/rogue", false)

	caFile := filepath.Join(dir, "ca.crt")
	certFile := filepath.Join(dir, "tls.crt")
	keyFile := filepath.Join(dir, "tls.key")
	_ = os.WriteFile(caFile, caPEM, 0o600)
	_ = os.WriteFile(certFile, srvCertPEM, 0o600)
	_ = os.WriteFile(keyFile, srvKeyPEM, 0o600)

	tlsCfg, err := buildIngressMTLSConfig(certFile, keyFile, caFile, []string{"spiffe://cluster.local/ns/kube-system/sa/gateway"})
	if err != nil {
		t.Fatalf("buildIngressMTLSConfig: %v", err)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer func() { _ = conn.Close() }()
				if tc, ok := conn.(*tls.Conn); ok {
					_ = tc.Handshake()
				}
			}(c)
		}
	}()

	// Allowed SPIFFE SAN client succeeds.
	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{goodClient},
		RootCAs:      caPool,
		ServerName:   "dra-agents-net.local",
	})
	if err != nil {
		t.Fatalf("authorized client handshake failed: %v", err)
	}
	_ = conn.Close()

	// Valid-CA but unauthorized SAN client MUST fail handshake.
	badConn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{badClient},
		RootCAs:      caPool,
		ServerName:   "dra-agents-net.local",
	})
	if err == nil {
		// Trigger TLS 1.3 post-handshake alert read.
		buf := make([]byte, 1)
		_, err = badConn.Read(buf)
		_ = badConn.Close()
	}
	if err == nil {
		t.Fatal("expected unauthorized client SAN to be rejected by ingress mTLS bridge")
	}
}
