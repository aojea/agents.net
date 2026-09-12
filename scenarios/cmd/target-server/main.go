package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

var (
	listenHost = flag.String("host", "0.0.0.0", "Host address to listen on")
	listenPort = flag.Int("port", 9099, "TCP port to listen on")
	enableTLS  = flag.Bool("tls", false, "Enable HTTPS/TLS server")
	certFile   = flag.String("cert", "", "Path to TLS certificate file")
	keyFile    = flag.String("key", "", "Path to TLS private key file")
	sanNames   = flag.String("san", "test.example.com,target.internal,localhost,127.0.0.1", "Comma-separated SANs for generated cert")
)

func ensureCertificate(certPath, keyPath string, sans []string) error {
	if _, err := os.Stat(certPath); err == nil {
		if _, err := os.Stat(keyPath); err == nil {
			return nil // Both exist
		}
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate private key: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("generate serial number: %w", err)
	}

	commonName := "test.example.com"
	if len(sans) > 0 {
		commonName = sans[0]
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"The Dome Local Test Authority"},
			CommonName:   commonName,
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	for _, name := range sans {
		name = strings.TrimSpace(name)
		if ip := net.ParseIP(name); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else if name != "" {
			template.DNSNames = append(template.DNSNames, name)
		}
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return fmt.Errorf("create certificate: %w", err)
	}

	certOut, err := os.Create(certPath)
	if err != nil {
		return fmt.Errorf("create cert file: %w", err)
	}
	defer certOut.Close()
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return fmt.Errorf("encode cert: %w", err)
	}

	keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("create key file: %w", err)
	}
	defer keyOut.Close()
	b, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return fmt.Errorf("marshal key: %w", err)
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}); err != nil {
		return fmt.Errorf("encode key: %w", err)
	}

	log.Printf("[TargetServer] Generated self-signed TLS cert: %s (SANs=%v)", certPath, sans)
	return nil
}

func main() {
	flag.Parse()

	mux := http.NewServeMux()

	// Latency endpoint: returns immediate 200 OK
	mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("pong\n"))
	})

	// Throughput endpoint: streams requested number of megabytes
	mux.HandleFunc("/stream", func(w http.ResponseWriter, r *http.Request) {
		sizeMB := 50
		if s := r.URL.Query().Get("mb"); s != "" {
			if v, err := strconv.Atoi(s); err == nil && v > 0 {
				sizeMB = v
			}
		}

		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)

		chunk := make([]byte, 64*1024) // 64KB chunk
		for i := range chunk {
			chunk[i] = 'A'
		}

		totalBytes := int64(sizeMB) * 1024 * 1024
		written := int64(0)
		for written < totalBytes {
			toWrite := int64(len(chunk))
			if written+toWrite > totalBytes {
				toWrite = totalBytes - written
			}
			n, err := w.Write(chunk[:toWrite])
			if err != nil {
				return
			}
			written += int64(n)
		}
	})

	addr := fmt.Sprintf("%s:%d", *listenHost, *listenPort)
	if *enableTLS {
		if *certFile == "" || *keyFile == "" {
			log.Fatalf("both -cert and -key must be specified when -tls is enabled")
		}
		sans := strings.Split(*sanNames, ",")
		if err := ensureCertificate(*certFile, *keyFile, sans); err != nil {
			log.Fatalf("failed to prepare certificate: %v", err)
		}
		log.Printf("[TargetServer] Serving HTTPS on https://%s (/ping, /stream?mb=...)", addr)
		if err := http.ListenAndServeTLS(addr, *certFile, *keyFile, mux); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	} else {
		log.Printf("[TargetServer] Serving HTTP on http://%s (/ping, /stream?mb=...)", addr)
		if err := http.ListenAndServe(addr, mux); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	}
}
