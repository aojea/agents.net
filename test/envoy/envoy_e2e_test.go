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

//go:build envoy_e2e

package envoy_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"text/template"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"k8s.io/apimachinery/pkg/types"

	"github.com/aojea/agents.net/pkg/apis"
	"github.com/aojea/agents.net/pkg/auth"
	"github.com/aojea/agents.net/pkg/ingress"
	"github.com/aojea/agents.net/pkg/params"
	"github.com/aojea/agents.net/pkg/store"
	"github.com/aojea/agents.net/pkg/tun2connect"
	"github.com/aojea/agents.net/pkg/tunnel"
)

const (
	defaultEnvoyImage = "envoyproxy/envoy:v1.36.2"
	testPodUID        = types.UID("pod-uid-envoy-1")
)

type envoyTemplateData struct {
	AdminPort    int
	OutboundPort int
	InboundPort  int
	KubePEPPort  int
	BridgePort   int
	TCPPort      int
	UDPPort      int
	CertDir      string
	PodUID       string
}

type pkiMaterial struct {
	caCertPEM     []byte
	caCert        *x509.Certificate
	caKey         *ecdsa.PrivateKey
	dir           string
	driverCertDir string
	rogueCertDir  string
}

func generatePKI(t *testing.T, dir string) *pkiMaterial {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "agents-net-envoy-e2e-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	if err := os.WriteFile(filepath.Join(dir, "ca.crt"), caPEM, 0o644); err != nil {
		t.Fatalf("write ca.crt: %v", err)
	}

	p := &pkiMaterial{
		caCertPEM:     caPEM,
		caCert:        caCert,
		caKey:         caKey,
		dir:           dir,
		driverCertDir: filepath.Join(dir, "driver-client"),
		rogueCertDir:  filepath.Join(dir, "rogue-client"),
	}
	if err := os.MkdirAll(p.driverCertDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(p.rogueCertDir, 0o755); err != nil {
		t.Fatal(err)
	}

	p.issue(t, filepath.Join(dir, "envoy-pep.crt"), filepath.Join(dir, "envoy-pep.key"),
		"envoy-pep.local", []string{"envoy-pep.local"}, []net.IP{net.ParseIP("127.0.0.1")}, x509.ExtKeyUsageServerAuth, 2)
	p.issue(t, filepath.Join(p.driverCertDir, "tls.crt"), filepath.Join(p.driverCertDir, "tls.key"),
		"kube-net-driver-envoy-test", []string{"kube-net-driver-envoy-test"}, nil, x509.ExtKeyUsageClientAuth, 3)
	p.issue(t, filepath.Join(p.rogueCertDir, "tls.crt"), filepath.Join(p.rogueCertDir, "tls.key"),
		"rogue-client", []string{"rogue-client"}, nil, x509.ExtKeyUsageClientAuth, 4)
	p.issue(t, filepath.Join(dir, "bridge.crt"), filepath.Join(dir, "bridge.key"),
		"kube-net-driver.kube-system.svc", []string{"kube-net-driver.kube-system.svc"}, []net.IP{net.ParseIP("127.0.0.1")}, x509.ExtKeyUsageServerAuth, 5)
	p.issue(t, filepath.Join(dir, "envoy-inbound.crt"), filepath.Join(dir, "envoy-inbound.key"),
		"kube-inbound", []string{"kube-inbound"}, nil, x509.ExtKeyUsageClientAuth, 6)
	return p
}

func (p *pkiMaterial) issue(t *testing.T, certPath, keyPath, cn string, dnsNames []string, ips []net.IP, eku x509.ExtKeyUsage, serial int64) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key %s: %v", cn, err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     dnsNames,
		IPAddresses:  ips,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{eku},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.caCert, &key.PublicKey, p.caKey)
	if err != nil {
		t.Fatalf("sign cert %s: %v", cn, err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key %s: %v", cn, err)
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatalf("write %s: %v", certPath, err)
	}
	// Envoy runs as a non-root UID inside the container; keep test ephemeral keys world-readable in temp dir.
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o644); err != nil {
		t.Fatalf("write %s: %v", keyPath, err)
	}
}

func reserveTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve tcp port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

func startTCPEchoHTTP(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp echo: %v", err)
	}
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprintf(w, "envoy-tcp-ok:%s", r.URL.Path)
		}),
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().(*net.TCPAddr).Port
}

func startUDPEcho(t *testing.T) int {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp echo: %v", err)
	}
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(buf[:n], addr)
		}
	}()
	t.Cleanup(func() { _ = pc.Close() })
	return pc.LocalAddr().(*net.UDPAddr).Port
}

func startSandboxInboundHTTP(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen sandbox inbound http: %v", err)
	}
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprintf(w, "envoy-inbound-ok:%s", r.URL.Path)
		}),
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().String()
}

func startKubePEPBackend(t *testing.T, repoRoot, workDir string, tcpPort, udpPort int) int {
	t.Helper()
	pepBin := filepath.Join(workDir, "kube-pep")
	buildCmd := exec.Command("go", "build", "-o", pepBin, "./cmd/kube-pep")
	buildCmd.Dir = repoRoot
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("build kube-pep: %v\n%s", err, string(out))
	}

	policy := map[string]any{
		"agents_net_policy": 1,
		"version":           "envoy-e2e-v1",
		"sandbox":           "envoy-agent",
		"default":           "deny",
		"features": map[string]bool{
			"h2":  true,
			"udp": true,
			"doh": true,
		},
		"rules": []map[string]any{
			{
				"id":         "allow-echo-tcp",
				"name":       "echo.envoy.local",
				"ports":      []int{tcpPort},
				"transports": []string{"tcp"},
				"resolve":    []string{"127.0.0.1"},
			},
			{
				"id":         "allow-echo-udp",
				"name":       "echo.envoy.local",
				"ports":      []int{udpPort},
				"transports": []string{"udp"},
				"resolve":    []string{"127.0.0.1"},
			},
		},
		"resolved_addresses": []map[string]any{
			{
				"cidr":  "127.0.0.1/32",
				"ports": []int{tcpPort, udpPort},
			},
		},
	}
	policyBytes, err := json.MarshalIndent(policy, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(workDir, "policy.json")
	if err := os.WriteFile(policyPath, policyBytes, 0o644); err != nil {
		t.Fatal(err)
	}

	port := reserveTCPPort(t)
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, pepBin,
		"-listen", fmt.Sprintf("tcp://127.0.0.1:%d", port),
		"-h2",
		"-policy", policyPath,
		"-generation", "envoy-e2e-1",
	)
	cmd.Env = append(os.Environ(), "GODEBUG=http2xconnect=1")
	var logs bytes.Buffer
	cmd.Stdout = &logs
	cmd.Stderr = &logs
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatalf("start kube-pep: %v", err)
	}
	t.Cleanup(func() {
		cancel()
		_ = cmd.Wait()
		if t.Failed() {
			t.Logf("kube-pep logs:\n%s", logs.String())
		}
	})

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 100*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return port
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("kube-pep did not listen on :%d\n%s", port, logs.String())
	return 0
}

func startIngressBridge(t *testing.T, pki *pkiMaterial, sandboxAddr string) (*ingress.Server, int) {
	t.Helper()
	st, err := store.New(nil)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	if err := st.Upsert(store.PodConfig{
		PodUID:       testPodUID,
		PodName:      "agent-1",
		PodNamespace: "default",
		NetNS:        "/proc/self/ns/net",
		Parameters: params.NetworkParameters{
			AdapterMode: apis.AdapterModeHostTun,
			IngressPorts: []apis.IngressPort{
				{Port: 8080, Protocol: "TCP"},
			},
		},
	}); err != nil {
		t.Fatalf("store.Upsert: %v", err)
	}

	cert, err := tls.LoadX509KeyPair(filepath.Join(pki.dir, "bridge.crt"), filepath.Join(pki.dir, "bridge.key"))
	if err != nil {
		t.Fatalf("load bridge cert: %v", err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(pki.caCertPEM) {
		t.Fatal("append CA PEM")
	}
	tlsCfg := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
		ClientCAs:    caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return fmt.Errorf("missing client certificate")
			}
			for _, name := range cs.PeerCertificates[0].DNSNames {
				if name == "kube-inbound" {
					return nil
				}
			}
			return fmt.Errorf("unauthorized client SANs: %v", cs.PeerCertificates[0].DNSNames)
		},
	}

	srv, err := ingress.NewServer(ingress.Config{
		ListenAddr: "127.0.0.1:0",
		Store:      st,
		TLSConfig:  tlsCfg,
		DialNetNS: func(_, _, addr string, timeout time.Duration) (net.Conn, error) {
			if addr != "127.0.0.1:8080" {
				return nil, fmt.Errorf("unexpected target address %q", addr)
			}
			return net.DialTimeout("tcp", sandboxAddr, timeout)
		},
	})
	if err != nil {
		t.Fatalf("ingress.NewServer: %v", err)
	}
	addr, err := srv.Start()
	if err != nil {
		t.Fatalf("ingress.Start: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	return srv, addr.(*net.TCPAddr).Port
}

func startEnvoyContainer(t *testing.T, workDir, configPath string, adminPort int) {
	t.Helper()
	image := os.Getenv("ENVOY_IMAGE")
	if image == "" {
		image = defaultEnvoyImage
	}
	name := fmt.Sprintf("agents-net-envoy-e2e-%d", time.Now().UnixNano())
	cmd := exec.Command("docker", "run", "-d",
		"--name", name,
		"--network", "host",
		"--add-host=echo.envoy.local:127.0.0.1",
		"-v", fmt.Sprintf("%s:%s:ro", workDir, workDir),
		image,
		"-c", configPath,
		"--log-level", "warning",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("start envoy container: %v\n%s", err, string(out))
	}
	t.Cleanup(func() {
		if t.Failed() {
			logs, _ := exec.Command("docker", "logs", "--tail", "80", name).CombinedOutput()
			t.Logf("envoy logs:\n%s", string(logs))
		}
		_ = exec.Command("docker", "rm", "-f", name).Run()
	})

	readyURL := fmt.Sprintf("http://127.0.0.1:%d/ready", adminPort)
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(readyURL)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	logs, _ := exec.Command("docker", "logs", "--tail", "80", name).CombinedOutput()
	t.Fatalf("envoy never became ready on %s\n%s", readyURL, string(logs))
}

// buildGuestEngine creates an in-memory guest gVisor netstack paired with
// tun2connect.Engine + DoHVirtualDNS backed by the Tier 1 tunnel.Manager egress socket.
func buildGuestEngine(t *testing.T, egressSock string) (*stack.Stack, *tun2connect.VirtualDNS) {
	t.Helper()
	const nicID = 1
	guestEP := channel.New(256, 1500, "")
	engineEP := channel.New(256, 1500, "")

	done := make(chan struct{})
	t.Cleanup(func() { close(done) })
	bridge := func(src, dst *channel.Endpoint) {
		for {
			pkt := src.ReadContext(context.Background())
			if pkt == nil {
				return
			}
			v := pkt.ToView()
			pkt.DecRef()
			out := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithView(v)})
			dst.InjectInbound(ipv4.ProtocolNumber, out)
			out.DecRef()
		}
	}
	go bridge(guestEP, engineEP)
	go bridge(engineEP, guestEP)

	guest := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	if err := guest.CreateNIC(nicID, guestEP); err != nil {
		t.Fatalf("guest CreateNIC: %v", err)
	}
	if err := guest.AddProtocolAddress(nicID, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddrFrom4([4]byte{10, 200, 0, 2}).WithPrefix(),
	}, stack.AddressProperties{}); err != nil {
		t.Fatalf("guest AddProtocolAddress: %v", err)
	}
	guest.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: nicID}})

	bc := &tun2connect.BoundaryClient{
		DialBoundary: func(ctx context.Context) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", egressSock)
		},
	}
	vdns := tun2connect.NewVirtualDNS()
	doh := tun2connect.NewDoHVirtualDNS(vdns, bc.QueryDoH)
	eng, err := tun2connect.New(tun2connect.Config{
		Device:     engineEP,
		Addresses:  []netip.Prefix{netip.MustParsePrefix("10.200.0.1/24")},
		Dialer:     bc,
		DNS:        vdns,
		DNSHandler: doh,
		EnableUDP:  true,
	})
	if err != nil {
		t.Fatalf("tun2connect.New: %v", err)
	}
	t.Cleanup(func() {
		eng.Close()
		guestEP.Close()
		engineEP.Close()
		guest.Close()
	})
	return guest, vdns
}

func queryDNS(t *testing.T, guest *stack.Stack, name string) (dnsmessage.RCode, netip.Addr) {
	t.Helper()
	var b dnsmessage.Builder
	b = dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 0x4242, RecursionDesired: true})
	if err := b.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := b.Question(dnsmessage.Question{
		Name:  dnsmessage.MustNewName(name),
		Type:  dnsmessage.TypeA,
		Class: dnsmessage.ClassINET,
	}); err != nil {
		t.Fatal(err)
	}
	wire, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}

	raddr := tcpip.FullAddress{Addr: tcpip.AddrFrom4([4]byte{198, 19, 255, 253}), Port: 53}
	conn, err := gonet.DialUDP(guest, nil, &raddr, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("DialUDP DNS: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write(wire); err != nil {
		t.Fatalf("write DNS query: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read DNS reply for %s: %v", name, err)
	}

	var p dnsmessage.Parser
	hdr, err := p.Start(buf[:n])
	if err != nil {
		t.Fatalf("parse DNS reply: %v", err)
	}
	if hdr.RCode != dnsmessage.RCodeSuccess {
		return hdr.RCode, netip.Addr{}
	}
	if err := p.SkipAllQuestions(); err != nil {
		t.Fatal(err)
	}
	answers, err := p.AllAnswers()
	if err != nil || len(answers) != 1 {
		t.Fatalf("expected 1 A answer for %s, got %v (err %v)", name, answers, err)
	}
	return hdr.RCode, netip.AddrFrom4(answers[0].Body.(*dnsmessage.AResource).A)
}

func TestEnvoyPEPObservabilityOutboundDoHAndInbound(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatalf("docker is required for envoy_e2e tests: %v", err)
	}
	repoRoot, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	workDir, err := os.MkdirTemp("", "agents-net-envoy-e2e-*")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(workDir, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(workDir) })

	pki := generatePKI(t, workDir)
	tcpPort := startTCPEchoHTTP(t)
	udpPort := startUDPEcho(t)
	sandboxAddr := startSandboxInboundHTTP(t)
	kubePEPPort := startKubePEPBackend(t, repoRoot, workDir, tcpPort, udpPort)
	bridgeSrv, bridgePort := startIngressBridge(t, pki, sandboxAddr)

	adminPort := reserveTCPPort(t)
	outboundPort := reserveTCPPort(t)
	inboundPort := reserveTCPPort(t)

	tmplPath := filepath.Join(repoRoot, "test", "envoy", "envoy.yaml.tmpl")
	tmpl, err := template.ParseFiles(tmplPath)
	if err != nil {
		t.Fatalf("parse envoy.yaml.tmpl: %v", err)
	}
	configPath := filepath.Join(workDir, "envoy.yaml")
	var rendered bytes.Buffer
	if err := tmpl.Execute(&rendered, envoyTemplateData{
		AdminPort:    adminPort,
		OutboundPort: outboundPort,
		InboundPort:  inboundPort,
		KubePEPPort:  kubePEPPort,
		BridgePort:   bridgePort,
		TCPPort:      tcpPort,
		UDPPort:      udpPort,
		CertDir:      workDir,
		PodUID:       string(testPodUID),
	}); err != nil {
		t.Fatalf("render envoy.yaml: %v", err)
	}
	if err := os.WriteFile(configPath, rendered.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}

	startEnvoyContainer(t, workDir, configPath, adminPort)

	// 1. Verify Envoy rejects plaintext and wrong-SAN mTLS clients.
	t.Run("mTLSAndRBACAuth", func(t *testing.T) {
		raw, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", outboundPort), 5*time.Second)
		if err != nil {
			t.Fatalf("dial envoy outbound: %v", err)
		}
		_, _ = raw.Write([]byte("CONNECT echo.envoy.local:80 HTTP/1.1\r\nHost: echo.envoy.local:80\r\n\r\n"))
		_ = raw.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 64)
		n, _ := raw.Read(buf)
		_ = raw.Close()
		if strings.HasPrefix(string(buf[:n]), "HTTP/1.1 200") {
			t.Fatalf("plaintext client unexpectedly succeeded: %q", string(buf[:n]))
		}

		// Valid CA cert with rogue SAN must be rejected by Envoy RBAC with 403.
		rogueCert, err := tls.LoadX509KeyPair(filepath.Join(pki.rogueCertDir, "tls.crt"), filepath.Join(pki.rogueCertDir, "tls.key"))
		if err != nil {
			t.Fatal(err)
		}
		caPool := x509.NewCertPool()
		caPool.AppendCertsFromPEM(pki.caCertPEM)
		protos := new(http.Protocols)
		protos.SetHTTP2(true)
		tr := &http.Transport{
			Protocols: protos,
			TLSClientConfig: &tls.Config{
				MinVersion:   tls.VersionTLS12,
				ServerName:   "envoy-pep.local",
				RootCAs:      caPool,
				Certificates: []tls.Certificate{rogueCert},
				NextProtos:   []string{"h2"},
			},
		}
		defer tr.CloseIdleConnections()
		pr, pw := io.Pipe()
		defer pw.Close()
		req, _ := http.NewRequest(http.MethodConnect, fmt.Sprintf("https://127.0.0.1:%d", outboundPort), pr)
		req.Host = fmt.Sprintf("echo.envoy.local:%d", tcpPort)
		resp, err := tr.RoundTrip(req)
		if err != nil {
			t.Fatalf("rogue client roundtrip: %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("rogue client status = %d, want 403", resp.StatusCode)
		}
	})

	// 2. Wire Tier 1 tunnel.Manager + tun2connect.Engine + DoHVirtualDNS to Envoy PEP.
	sockRoot := filepath.Join(workDir, "pods")
	var auditBuf bytes.Buffer
	mgr, err := tunnel.NewManager(sockRoot, nil, tunnel.WithAuditWriter(&auditBuf))
	if err != nil {
		t.Fatalf("tunnel.NewManager: %v", err)
	}
	t.Cleanup(func() {
		mgr.Close()
		if t.Failed() {
			t.Logf("tunnel audit:\n%s", auditBuf.String())
		}
	})

	pepCfg := &apis.PolicyEnforcementPointConfig{
		URL: fmt.Sprintf("https://127.0.0.1:%d", outboundPort),
		TLS: &apis.PEPTLS{
			ServerName: "envoy-pep.local",
			CACertificateRefs: []apis.CASource{
				{Type: apis.CASourceTypeHostPath, HostPath: filepath.Join(workDir, "ca.crt")},
			},
		},
		Auth: &apis.PEPAuth{
			Type: apis.PEPAuthTypeMTLS,
			MTLS: &apis.MTLSAuth{CertDir: pki.driverCertDir},
		},
	}
	paths, err := mgr.EnsureListener(context.Background(), testPodUID, tunnel.ListenerConfig{
		Identity: auth.WorkloadIdentity{
			PodUID:         testPodUID,
			PodName:        "agent-1",
			Namespace:      "default",
			ServiceAccount: "default",
		},
		PolicyEnforcementPoint: pepCfg,
		DNSMode:                apis.DNSModeDoH,
		MaxConnections:         64,
		IdleTimeoutSeconds:     60,
	})
	if err != nil {
		t.Fatalf("EnsureListener: %v", err)
	}

	guest, vdns := buildGuestEngine(t, paths.EgressSocketPath)

	var syntheticIP netip.Addr
	t.Run("OutboundDoHAllowedAndNXDOMAIN", func(t *testing.T) {
		rcode, ip := queryDNS(t, guest, "echo.envoy.local.")
		if rcode != dnsmessage.RCodeSuccess {
			t.Fatalf("DoH echo.envoy.local rcode = %v, want NOERROR", rcode)
		}
		if !vdns.InSyntheticPool(ip) {
			t.Fatalf("DoH returned non-synthetic IP %s", ip)
		}
		syntheticIP = ip

		nxCode, _ := queryDNS(t, guest, "doesnotexist.example.")
		if nxCode != dnsmessage.RCodeNameError {
			t.Fatalf("DoH doesnotexist.example rcode = %v, want NXDOMAIN", nxCode)
		}
	})

	t.Run("OutboundTCPConnectAndDenyViaEnvoy", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		conn, err := gonet.DialContextTCP(ctx, guest, tcpip.FullAddress{
			Addr: tcpip.AddrFrom4(syntheticIP.As4()),
			Port: uint16(tcpPort),
		}, ipv4.ProtocolNumber)
		if err != nil {
			t.Fatalf("guest TCP dial via Envoy CONNECT: %v", err)
		}
		defer conn.Close()
		_, err = fmt.Fprintf(conn, "GET /from-guest-via-envoy HTTP/1.1\r\nHost: echo.envoy.local\r\nConnection: close\r\n\r\n")
		if err != nil {
			t.Fatalf("write HTTP request: %v", err)
		}
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatalf("read HTTP response: %v", err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK || string(body) != "envoy-tcp-ok:/from-guest-via-envoy" {
			t.Fatalf("unexpected TCP echo response: status=%d body=%q", resp.StatusCode, string(body))
		}

		// Denied host must fail closed via Envoy RBAC (403).
		blockedIP, err := vdns.Resolve4("blocked.example")
		if err != nil {
			t.Fatal(err)
		}
		deniedConn, err := gonet.DialContextTCP(ctx, guest, tcpip.FullAddress{
			Addr: tcpip.AddrFrom4(blockedIP.As4()),
			Port: 443,
		}, ipv4.ProtocolNumber)
		if err == nil {
			_ = deniedConn.SetReadDeadline(time.Now().Add(2 * time.Second))
			buf := make([]byte, 16)
			n, rerr := deniedConn.Read(buf)
			_ = deniedConn.Close()
			if rerr == nil && n > 0 {
				t.Fatalf("blocked.example unexpectedly returned data: %q", string(buf[:n]))
			}
		}
	})

	t.Run("OutboundUDPConnectUDPViaEnvoy", func(t *testing.T) {
		raddr := tcpip.FullAddress{
			Addr: tcpip.AddrFrom4(syntheticIP.As4()),
			Port: uint16(udpPort),
		}
		uconn, err := gonet.DialUDP(guest, nil, &raddr, ipv4.ProtocolNumber)
		if err != nil {
			t.Fatalf("guest DialUDP: %v", err)
		}
		defer uconn.Close()
		want := []byte("udp-via-envoy-h2-ok")
		if _, err := uconn.Write(want); err != nil {
			t.Fatalf("guest UDP write: %v", err)
		}
		_ = uconn.SetReadDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 1024)
		n, err := uconn.Read(buf)
		if err != nil {
			t.Fatalf("guest UDP read via Envoy connect-udp: %v", err)
		}
		if string(buf[:n]) != string(want) {
			t.Fatalf("UDP echo mismatch: got %q want %q", string(buf[:n]), string(want))
		}
	})

	t.Run("InboundMTLSConnectTunnelingViaEnvoy", func(t *testing.T) {
		client := &http.Client{
			Timeout:   5 * time.Second,
			Transport: &http.Transport{DisableKeepAlives: true},
		}

		// Allowed pinned port 8080 succeeds end to end through Envoy -> mTLS CONNECT -> pkg/ingress.Server -> sandbox.
		resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/agents/default/agent-1/hello-envoy", inboundPort))
		if err != nil {
			t.Fatalf("inbound GET allowed: %v", err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK || string(body) != "envoy-inbound-ok:/hello-envoy" {
			t.Fatalf("inbound GET allowed = %d %q, want 200 envoy-inbound-ok:/hello-envoy", resp.StatusCode, string(body))
		}

		// Unpinned port 9999 is rejected by pkg/ingress.Server (403 -> Envoy 503).
		respDenied, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/agents/default/agent-1-unpinned/nope", inboundPort))
		if err != nil {
			t.Fatalf("inbound GET unpinned: %v", err)
		}
		_ = respDenied.Body.Close()
		if respDenied.StatusCode == http.StatusOK {
			t.Fatalf("inbound GET unpinned port 9999 unexpectedly returned 200")
		}

		// Revoke pod in node ingress bridge; subsequent request through Envoy must fail immediately.
		bridgeSrv.Revoke(testPodUID)
		respRevoked, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/agents/default/agent-1/after-revoke", inboundPort))
		if err != nil {
			t.Fatalf("inbound GET after revoke: %v", err)
		}
		_ = respRevoked.Body.Close()
		if respRevoked.StatusCode == http.StatusOK {
			t.Fatalf("inbound GET after RevokePod unexpectedly returned 200")
		}
	})

	// 3. Assert Envoy's own counters prove Envoy handled every datapath flow.
	t.Run("EnvoyStatsVerification", func(t *testing.T) {
		resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/stats", adminPort))
		if err != nil {
			t.Fatalf("GET envoy /stats: %v", err)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		stats := parseEnvoyStats(string(raw))

		checks := []struct {
			key string
			min int64
		}{
			{"http.outbound_pep.downstream_cx_upgrades_total", 2},
			{"cluster.dfp.upstream_cx_total", 1},
			{"cluster.kube_pep_doh.upstream_rq_200", 2},
			{"cluster.kube_pep_udp.upstream_rq_total", 1},
			{"http.outbound_pep.rbac.denied", 2},
			{"tcp.inbound_tunnel_ok.downstream_cx_total", 2},
			{"tcp.inbound_tunnel_denied.downstream_cx_total", 1},
		}
		for _, c := range checks {
			if stats[c.key] < c.min {
				t.Errorf("envoy stat %s = %d, want >= %d", c.key, stats[c.key], c.min)
			}
		}
	})
}

func parseEnvoyStats(body string) map[string]int64 {
	out := make(map[string]int64)
	for _, line := range strings.Split(body, "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		if err == nil {
			out[strings.TrimSpace(k)] = n
		}
	}
	return out
}
