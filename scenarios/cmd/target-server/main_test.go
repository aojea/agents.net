package main

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestEnsureCertificate(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "cert.pem")
	keyPath := filepath.Join(tmpDir, "key.pem")

	sans := []string{"test.example.com", "target.internal", "127.0.0.1"}
	if err := ensureCertificate(certPath, keyPath, sans); err != nil {
		t.Fatalf("ensureCertificate failed: %v", err)
	}

	certBytes, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	if len(certBytes) == 0 {
		t.Fatalf("cert file is empty")
	}

	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	if len(keyBytes) == 0 {
		t.Fatalf("key file is empty")
	}

	// Calling again should be idempotent and not fail
	if err := ensureCertificate(certPath, keyPath, sans); err != nil {
		t.Fatalf("subsequent ensureCertificate failed: %v", err)
	}
}

func TestTargetServerEndpoints(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "cert.pem")
	keyPath := filepath.Join(tmpDir, "key.pem")

	if err := ensureCertificate(certPath, keyPath, []string{"127.0.0.1", "localhost"}); err != nil {
		t.Fatalf("ensure cert: %v", err)
	}

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatalf("load cert key pair: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("pong\n"))
	})
	mux.HandleFunc("/stream", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(make([]byte, 1024))
	})

	ts := httptest.NewUnstartedServer(mux)
	ts.TLS = &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	ts.StartTLS()
	defer ts.Close()

	certPEM, _ := os.ReadFile(certPath)
	cp := x509.NewCertPool()
	cp.AppendCertsFromPEM(certPEM)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: cp,
			},
		},
	}

	// Test /ping
	resp, err := client.Get(ts.URL + "/ping")
	if err != nil {
		t.Fatalf("GET /ping: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "pong\n" {
		t.Errorf("expected 'pong\\n', got %q", string(body))
	}

	// Test /stream
	resp2, err := client.Get(ts.URL + "/stream")
	if err != nil {
		t.Fatalf("GET /stream: %v", err)
	}
	defer resp2.Body.Close()
	body2, _ := io.ReadAll(resp2.Body)
	if len(body2) != 1024 {
		t.Errorf("expected 1024 bytes, got %d", len(body2))
	}
}
