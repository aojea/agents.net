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

//go:build microvm_e2e && linux

package microvm_test

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
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"k8s.io/apimachinery/pkg/types"

	"github.com/aojea/agents.net/pkg/apis"
	"github.com/aojea/agents.net/pkg/auth"
	"github.com/aojea/agents.net/pkg/hosttun"
	"github.com/aojea/agents.net/pkg/ingress"
	"github.com/aojea/agents.net/pkg/params"
	"github.com/aojea/agents.net/pkg/store"
	"github.com/aojea/agents.net/pkg/tun2connect"
	"github.com/aojea/agents.net/pkg/tunnel"
)

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

func (s *syncBuffer) waitFor(substr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if strings.Contains(s.String(), substr) {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("timed out waiting for %q in console output", substr)
}

type pkiBundle struct {
	caCertPEM     []byte
	caCert        *x509.Certificate
	caKey         *ecdsa.PrivateKey
	dir           string
	driverCertDir string
}

func generatePKI(t *testing.T, dir string) *pkiBundle {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "agents-net-microvm-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	if err := os.WriteFile(filepath.Join(dir, "ca.crt"), caPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	driverDir := filepath.Join(dir, "driver-client")
	if err := os.MkdirAll(driverDir, 0o755); err != nil {
		t.Fatal(err)
	}
	p := &pkiBundle{
		caCertPEM:     caPEM,
		caCert:        caCert,
		caKey:         caKey,
		dir:           dir,
		driverCertDir: driverDir,
	}
	p.issue(t, filepath.Join(dir, "pep.crt"), filepath.Join(dir, "pep.key"),
		"kube-pep.local", []string{"kube-pep.local"}, []net.IP{net.ParseIP("127.0.0.1")}, x509.ExtKeyUsageServerAuth, 2)
	p.issue(t, filepath.Join(driverDir, "tls.crt"), filepath.Join(driverDir, "tls.key"),
		"kube-net-driver-microvm-client", []string{"kube-net-driver-microvm-client"}, nil, x509.ExtKeyUsageClientAuth, 3)
	p.issue(t, filepath.Join(dir, "bridge.crt"), filepath.Join(dir, "bridge.key"),
		"kube-net-driver.kube-system.svc", []string{"kube-net-driver.kube-system.svc"}, []net.IP{net.ParseIP("127.0.0.1")}, x509.ExtKeyUsageServerAuth, 4)
	p.issue(t, filepath.Join(dir, "inbound-client.crt"), filepath.Join(dir, "inbound-client.key"),
		"kube-inbound", []string{"kube-inbound"}, nil, x509.ExtKeyUsageClientAuth, 5)
	return p
}

func (p *pkiBundle) issue(t *testing.T, certPath, keyPath, cn string, dnsNames []string, ips []net.IP, eku x509.ExtKeyUsage, serial int64) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
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
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
}

func startEchoServers(t *testing.T) (tcpPort, udpPort int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprintf(w, "microvm-tcp-ok:%s", r.URL.Path)
		}),
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
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
	return ln.Addr().(*net.TCPAddr).Port, pc.LocalAddr().(*net.UDPAddr).Port
}

func buildBinary(t *testing.T, repoRoot, outPath, pkg string) string {
	t.Helper()
	cmd := exec.Command("go", "build", "-o", outPath, pkg)
	cmd.Dir = repoRoot
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build %s: %v\n%s", pkg, err, string(out))
	}
	return outPath
}

func writePEPPolicy(t *testing.T, path, sandbox string, tcpPort, udpPort int) {
	t.Helper()
	policy := map[string]any{
		"agents_net_policy": 1,
		"version":           "microvm-v1",
		"sandbox":           sandbox,
		"default":           "deny",
		"features": map[string]bool{
			"h2":  true,
			"udp": true,
			"doh": true,
		},
		"rules": []map[string]any{
			{
				"id":         "allow-echo-tcp",
				"name":       "echo.microvm.local",
				"ports":      []int{tcpPort},
				"transports": []string{"tcp"},
				"resolve":    []string{"127.0.0.1"},
			},
			{
				"id":         "allow-echo-udp",
				"name":       "echo.microvm.local",
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
	raw, err := json.MarshalIndent(policy, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
}

func assertPEPAudit(t *testing.T, rawLogs, wantPeer string) {
	t.Helper()
	var records []map[string]any
	for _, line := range strings.Split(rawLogs, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err == nil {
			records = append(records, rec)
		}
	}
	has := func(pred func(map[string]any) bool) bool {
		for _, r := range records {
			if pred(r) {
				return true
			}
		}
		return false
	}
	peerOK := func(r map[string]any) bool {
		return wantPeer == "" || r["peer"] == wantPeer
	}
	if !has(func(r map[string]any) bool {
		return r["decision"] == "allow" && r["transport"] == "dns" && r["wire"] == "h2" && peerOK(r)
	}) {
		t.Fatalf("missing DoH allow record in kube-pep audit:\n%s", rawLogs)
	}
	if !has(func(r map[string]any) bool {
		return r["decision"] == "block" && r["transport"] == "dns" && r["destination"] == "doesnotexist.example"
	}) {
		t.Fatalf("missing DoH block record for doesnotexist.example:\n%s", rawLogs)
	}
	if !has(func(r map[string]any) bool {
		return r["decision"] == "allow" && r["transport"] == "tcp" && r["wire"] == "h2" && peerOK(r)
	}) {
		t.Fatalf("missing TCP allow record in kube-pep audit:\n%s", rawLogs)
	}
	if !has(func(r map[string]any) bool {
		return r["decision"] == "block" && r["transport"] == "tcp" && r["destination"] == "echo.microvm.local:9999"
	}) {
		t.Fatalf("missing TCP port-block record for echo.microvm.local:9999:\n%s", rawLogs)
	}
	if !has(func(r map[string]any) bool {
		return r["decision"] == "allow" && r["transport"] == "udp" && r["wire"] == "h2" && peerOK(r)
	}) {
		t.Fatalf("missing UDP allow record in kube-pep audit:\n%s", rawLogs)
	}
}

func reserveTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return p
}

// TestMicroVMQEMUTAPZeroAgent boots a real KVM Linux microVM (QEMU microvm)
// with ZERO network agents inside the guest. QEMU's virtio-net L2 Ethernet
// frames travel directly over an AF_UNIX SOCK_DGRAM socketpair into the
// unprivileged kube-netstack process (LinkModeTAP, AF_UNIX-only seccomp), which
// forwards TCP CONNECT, UDP connect-udp, and RFC 8484 DoH through
// pkg/tunnel.Manager over mandatory mTLS HTTP/2 to kube-pep, and serves IP-less
// inbound connections from pkg/ingress.Server via hosttun.Manager.DialInbound.
func TestMicroVMQEMUTAPZeroAgent(t *testing.T) {
	kernel := os.Getenv("MICROVM_KERNEL")
	rootfs := os.Getenv("MICROVM_ROOTFS")
	if kernel == "" || rootfs == "" {
		t.Fatal("MICROVM_KERNEL and MICROVM_ROOTFS must be set (run via ./test/microvm/run.sh)")
	}
	repoRoot, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	workDir := t.TempDir()
	pki := generatePKI(t, workDir)
	tcpPort, udpPort := startEchoServers(t)

	pepBin := buildBinary(t, repoRoot, filepath.Join(workDir, "kube-pep"), "./cmd/kube-pep")
	stackBin := buildBinary(t, repoRoot, filepath.Join(workDir, "kube-netstack"), "./cmd/kube-netstack")

	// 1. Start kube-pep with mandatory mTLS HTTP/2 (TCP + UDP + DoH).
	policyPath := filepath.Join(workDir, "policy-tap.json")
	writePEPPolicy(t, policyPath, "microvm-tap", tcpPort, udpPort)
	pepPort := reserveTCPPort(t)
	pepLogs := &syncBuffer{}
	pepCtx, pepCancel := context.WithCancel(context.Background())
	pepCmd := exec.CommandContext(pepCtx, pepBin,
		"-listen", fmt.Sprintf("tcp://127.0.0.1:%d", pepPort),
		"-h2",
		"-policy", policyPath,
		"-generation", "microvm-tap-1",
		"-tls-cert", filepath.Join(workDir, "pep.crt"),
		"-tls-key", filepath.Join(workDir, "pep.key"),
		"-tls-client-ca", filepath.Join(workDir, "ca.crt"),
	)
	pepCmd.Env = append(os.Environ(), "GODEBUG=http2xconnect=1")
	pepCmd.Stdout = pepLogs
	pepCmd.Stderr = pepLogs
	if err := pepCmd.Start(); err != nil {
		pepCancel()
		t.Fatalf("start kube-pep: %v", err)
	}
	t.Cleanup(func() {
		pepCancel()
		_ = pepCmd.Wait()
		if t.Failed() {
			t.Logf("kube-pep logs:\n%s", pepLogs.String())
		}
	})
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); {
		if c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", pepPort), 100*time.Millisecond); err == nil {
			_ = c.Close()
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	// 2. Start unprivileged kube-netstack listening on AF_UNIX SOCK_SEQPACKET.
	workerSock := filepath.Join(workDir, "worker.sock")
	stackLogs := &syncBuffer{}
	stackCtx, stackCancel := context.WithCancel(context.Background())
	stackCmd := exec.CommandContext(stackCtx, stackBin, "--socket", workerSock)
	stackCmd.Stdout = stackLogs
	stackCmd.Stderr = stackLogs
	if err := stackCmd.Start(); err != nil {
		stackCancel()
		t.Fatalf("start kube-netstack: %v", err)
	}
	t.Cleanup(func() {
		stackCancel()
		_ = stackCmd.Wait()
		if t.Failed() {
			t.Logf("kube-netstack logs:\n%s", stackLogs.String())
		}
	})

	// 3. Configure Tier 1 tunnel.Manager (mTLS HTTP/2 + DoH) and hosttun.Manager (LinkModeTAP).
	const podUID = types.UID("microvm-tap-pod-1")
	mgr, err := tunnel.NewManager(filepath.Join(workDir, "pods"), nil, tunnel.WithAuditWriter(io.Discard))
	if err != nil {
		t.Fatalf("tunnel.NewManager: %v", err)
	}
	t.Cleanup(mgr.Close)

	pepCfg := &apis.PolicyEnforcementPointConfig{
		URL: fmt.Sprintf("https://127.0.0.1:%d", pepPort),
		TLS: &apis.PEPTLS{
			ServerName: "kube-pep.local",
			CACertificateRefs: []apis.CASource{
				{Type: apis.CASourceTypeHostPath, HostPath: filepath.Join(workDir, "ca.crt")},
			},
		},
		Auth: &apis.PEPAuth{
			Type: apis.PEPAuthTypeMTLS,
			MTLS: &apis.MTLSAuth{CertDir: pki.driverCertDir},
		},
	}
	if _, err := mgr.EnsureListener(context.Background(), podUID, tunnel.ListenerConfig{
		Identity: auth.WorkloadIdentity{
			PodUID:         podUID,
			PodName:        "microvm-tap",
			Namespace:      "default",
			ServiceAccount: "default",
		},
		PolicyEnforcementPoint: pepCfg,
		DNSMode:                apis.DNSModeDoH,
		MaxConnections:         128,
		IdleTimeoutSeconds:     60,
	}); err != nil {
		t.Fatalf("EnsureListener: %v", err)
	}

	// Create AF_UNIX SOCK_DGRAM pair connecting QEMU virtio-net <-> unprivileged kube-netstack.
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatalf("socketpair(AF_UNIX, SOCK_DGRAM): %v", err)
	}
	qemuFD, tapFD := fds[0], fds[1]
	qemuFile := os.NewFile(uintptr(qemuFD), "qemu-virtio-net-dgram")
	t.Cleanup(func() { _ = qemuFile.Close() })

	htMgr := hosttun.NewManager(hosttun.ManagerConfig{WorkerSocket: workerSock})
	t.Cleanup(func() { _ = htMgr.Close() })
	htHandle, err := htMgr.Attach(hosttun.AttachConfig{
		PodID:       string(podUID),
		TunFD:       tapFD,
		MTU:         1500,
		EnableUDP:   true,
		DNSMode:     hosttun.DNSModeDoH,
		LinkMode:    hosttun.LinkModeTAP,
		ServeEgress: func(c net.Conn) error { return mgr.ServeConn(podUID, c) },
	})
	if err != nil {
		t.Fatalf("hosttun.Attach(LinkModeTAP): %v", err)
	}
	t.Cleanup(func() { _ = htHandle.Close() })

	// 4. Start mandatory mTLS node ingress bridge (pkg/ingress.Server) backed by htMgr.DialInbound!
	st, err := store.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Upsert(store.PodConfig{
		PodUID: podUID,
		NetNS:  "microvm-tap-virtual",
		Parameters: params.NetworkParameters{
			AdapterMode:  apis.AdapterModeHostTun,
			IngressPorts: []apis.IngressPort{{Port: 8080, Protocol: apis.IngressProtocolTCP}},
		},
	}); err != nil {
		t.Fatal(err)
	}
	bridgeCert, err := tls.LoadX509KeyPair(filepath.Join(workDir, "bridge.crt"), filepath.Join(workDir, "bridge.key"))
	if err != nil {
		t.Fatal(err)
	}
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(pki.caCertPEM)
	guestIP := netip.MustParseAddr(tun2connect.DefaultGuestAddr4)
	bridgeSrv, err := ingress.NewServer(ingress.Config{
		ListenAddr: "127.0.0.1:0",
		Store:      st,
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{bridgeCert},
			ClientCAs:    caPool,
			ClientAuth:   tls.RequireAndVerifyClientCert,
		},
		DialNetNS: func(_, _, addr string, timeout time.Duration) (net.Conn, error) {
			_, portStr, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			var p uint16
			if _, err := fmt.Sscanf(portStr, "%d", &p); err != nil {
				return nil, err
			}
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			return htMgr.DialInbound(ctx, string(podUID), guestIP, p)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	bridgeAddr, err := bridgeSrv.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = bridgeSrv.Close() })

	// 5. Boot QEMU KVM microVM with virtio-net-pci attached to FD 3 (zero in-VM agent!).
	cmdline := fmt.Sprintf("console=ttyS0 reboot=k panic=1 root=/dev/vda ro quiet AGENT_MODE=tap ECHO_TCP_PORT=%d ECHO_UDP_PORT=%d", tcpPort, udpPort)
	vmCtx, vmCancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer vmCancel()
	console := &syncBuffer{}
	vmCmd := exec.CommandContext(vmCtx, "qemu-system-x86_64",
		"-enable-kvm",
		"-machine", "q35,accel=kvm",
		"-cpu", "host",
		"-m", "256M",
		"-nodefaults",
		"-no-user-config",
		"-no-reboot",
		"-nographic",
		"-serial", "stdio",
		"-kernel", kernel,
		"-append", cmdline,
		"-drive", fmt.Sprintf("id=root,file=%s,format=raw,readonly=on,if=none", rootfs),
		"-device", "virtio-blk-pci,drive=root",
		"-netdev", "dgram,id=net0,local.type=fd,local.str=3",
		"-device", "virtio-net-pci,netdev=net0",
	)
	vmCmd.ExtraFiles = []*os.File{qemuFile}
	vmCmd.Stdout = console
	vmCmd.Stderr = console
	if err := vmCmd.Start(); err != nil {
		t.Fatalf("start qemu microvm: %v", err)
	}
	// Close parent copy of qemuFile so QEMU owns FD 3 cleanly.
	_ = qemuFile.Close()
	t.Cleanup(func() {
		vmCancel()
		_ = vmCmd.Wait()
		if t.Failed() {
			t.Logf("QEMU microVM console:\n%s", console.String())
		}
	})

	if err := console.waitFor("GUEST_READY", 45*time.Second); err != nil {
		t.Fatalf("%v\nconsole:\n%s", err, console.String())
	}

	// 6. Verify mandatory mTLS inbound through pkg/ingress.Server -> kube-netstack -> virtio-net -> guest :8080!
	inClientCert, err := tls.LoadX509KeyPair(filepath.Join(workDir, "inbound-client.crt"), filepath.Join(workDir, "inbound-client.key"))
	if err != nil {
		t.Fatal(err)
	}
	inTLS := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		ServerName:   "kube-net-driver.kube-system.svc",
		RootCAs:      caPool,
		Certificates: []tls.Certificate{inClientCert},
	}
	dialInboundHTTP := func(port int, path string) (int, string, error) {
		conn, err := tls.Dial("tcp", bridgeAddr.String(), inTLS)
		if err != nil {
			return 0, "", err
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		if _, err := fmt.Fprintf(conn, "CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n\r\n", podUID, port, podUID, port); err != nil {
			return 0, "", err
		}
		br := bufio.NewReader(conn)
		cResp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
		if err != nil {
			return 0, "", err
		}
		if cResp.StatusCode != http.StatusOK {
			return cResp.StatusCode, cResp.Header.Get("Proxy-Status"), nil
		}
		if _, err := fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n", path); err != nil {
			return 0, "", err
		}
		hResp, err := http.ReadResponse(br, nil)
		if err != nil {
			return 0, "", err
		}
		body, _ := io.ReadAll(hResp.Body)
		_ = hResp.Body.Close()
		return hResp.StatusCode, string(body), nil
	}

	// Retry briefly while guest ARP resolves on initial boot.
	var status int
	var body string
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); {
		status, body, err = dialInboundHTTP(8080, "/hello-tap")
		if err == nil && status == http.StatusOK {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if err != nil || status != http.StatusOK || body != "microvm-tap-inbound-ok:/hello-tap" {
		t.Fatalf("QEMU L2 tap inbound :8080 = (%d, %q, %v)", status, body, err)
	}

	// Unpinned port 9999 must fail closed with 403 + Proxy-Status.
	denyStatus, proxyStatus, err := dialInboundHTTP(9999, "/nope")
	if err != nil || denyStatus != http.StatusForbidden || !strings.Contains(proxyStatus, "port-not-permitted") {
		t.Fatalf("QEMU L2 tap unpinned :9999 = (%d, %q, %v), want 403 port-not-permitted", denyStatus, proxyStatus, err)
	}

	// 7. Wait for guest outbound DoH + TCP + UDP assertions to pass!
	if err := console.waitFor("GUEST_OUTBOUND_PASS", 45*time.Second); err != nil {
		t.Fatalf("%v\nconsole:\n%s", err, console.String())
	}

	// Trigger clean guest shutdown through the inbound tunnel, then verify Revoke -> 404.
	if stCode, _, err := dialInboundHTTP(8080, "/shutdown"); err != nil || stCode != http.StatusOK {
		t.Fatalf("inbound /shutdown failed: status=%d err=%v", stCode, err)
	}
	bridgeSrv.Revoke(podUID)
	if revStatus, _, err := dialInboundHTTP(8080, "/after-revoke"); err != nil || revStatus != http.StatusNotFound {
		t.Fatalf("post-Revoke inbound = (%d, %v), want 404", revStatus, err)
	}

	if err := vmCmd.Wait(); err != nil {
		t.Fatalf("QEMU microVM exited with error: %v\nconsole:\n%s", err, console.String())
	}
	assertPEPAudit(t, pepLogs.String(), "kube-net-driver-microvm-client")
}

// TestMicroVMFirecrackerVsock boots a real Firecracker v1.16.1 KVM microVM with
// ZERO network interfaces (AF_VSOCK only). Inside the VM, kube-tun2connect runs
// with -h2 -udp -doh over vsock://2:1024 -> host kube-pep (TCP CONNECT, UDP
// connect-udp, RFC 8484 DoH NOERROR + NXDOMAIN) and serves inbound connections
// over vsock://5000 -> 127.0.0.1:8080.
func TestMicroVMFirecrackerVsock(t *testing.T) {
	kernel := os.Getenv("MICROVM_KERNEL")
	rootfs := os.Getenv("MICROVM_ROOTFS")
	fcBin := os.Getenv("FIRECRACKER_BIN")
	if kernel == "" || rootfs == "" || fcBin == "" {
		t.Fatal("MICROVM_KERNEL, MICROVM_ROOTFS, and FIRECRACKER_BIN must be set (run via ./test/microvm/run.sh)")
	}
	repoRoot, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	workDir := t.TempDir()
	tcpPort, udpPort := startEchoServers(t)
	pepBin := buildBinary(t, repoRoot, filepath.Join(workDir, "kube-pep"), "./cmd/kube-pep")

	vsockUDS := filepath.Join(workDir, "fc.vsock")
	boundaryUDS := vsockUDS + "_1024"

	// 1. Start kube-pep directly on Firecracker's host vsock listener "<uds>_1024".
	policyPath := filepath.Join(workDir, "policy-fc.json")
	writePEPPolicy(t, policyPath, "firecracker-vsock", tcpPort, udpPort)
	pepLogs := &syncBuffer{}
	pepCtx, pepCancel := context.WithCancel(context.Background())
	pepCmd := exec.CommandContext(pepCtx, pepBin,
		"-listen", "unix://"+boundaryUDS,
		"-h2",
		"-policy", policyPath,
		"-generation", "fc-vsock-1",
	)
	pepCmd.Env = append(os.Environ(), "GODEBUG=http2xconnect=1")
	pepCmd.Stdout = pepLogs
	pepCmd.Stderr = pepLogs
	if err := pepCmd.Start(); err != nil {
		pepCancel()
		t.Fatalf("start kube-pep on vsock UDS: %v", err)
	}
	t.Cleanup(func() {
		pepCancel()
		_ = pepCmd.Wait()
		if t.Failed() {
			t.Logf("kube-pep logs:\n%s", pepLogs.String())
		}
	})
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); {
		if _, err := os.Stat(boundaryUDS); err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	// 2. Write Firecracker config with ZERO network-interfaces and AF_VSOCK CID 3.
	fcConfig := map[string]any{
		"boot-source": map[string]any{
			"kernel_image_path": kernel,
			"boot_args": fmt.Sprintf(
				"console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda ro quiet AGENT_MODE=vsock BOUNDARY_PORT=1024 INGRESS_PORT=5000 ECHO_TCP_PORT=%d ECHO_UDP_PORT=%d",
				tcpPort, udpPort,
			),
		},
		"drives": []map[string]any{
			{
				"drive_id":       "rootfs",
				"path_on_host":   rootfs,
				"is_root_device": true,
				"is_read_only":   true,
			},
		},
		"machine-config": map[string]any{
			"vcpu_count":   1,
			"mem_size_mib": 256,
		},
		"vsock": map[string]any{
			"guest_cid": 3,
			"uds_path":  vsockUDS,
		},
	}
	fcConfigBytes, err := json.MarshalIndent(fcConfig, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	fcConfigPath := filepath.Join(workDir, "fc.json")
	if err := os.WriteFile(fcConfigPath, fcConfigBytes, 0o644); err != nil {
		t.Fatal(err)
	}

	vmCtx, vmCancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer vmCancel()
	console := &syncBuffer{}
	fcCmd := exec.CommandContext(vmCtx, fcBin, "--no-api", "--config-file", fcConfigPath)
	fcCmd.Stdout = console
	fcCmd.Stderr = console
	if err := fcCmd.Start(); err != nil {
		t.Fatalf("start firecracker: %v", err)
	}
	t.Cleanup(func() {
		vmCancel()
		_ = fcCmd.Wait()
		if t.Failed() {
			t.Logf("Firecracker console:\n%s", console.String())
		}
	})

	if err := console.waitFor("GUEST_READY", 45*time.Second); err != nil {
		t.Fatalf("%v\nconsole:\n%s", err, console.String())
	}

	// 3. Verify host-initiated inbound over Firecracker vsock ("CONNECT 5000\n" -> "OK ...\n" -> HTTP CONNECT 127.0.0.1:<port>).
	dialVsockInbound := func(port int, path string) (int, string, error) {
		conn, err := net.DialTimeout("unix", vsockUDS, 5*time.Second)
		if err != nil {
			return 0, "", err
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		if _, err := io.WriteString(conn, "CONNECT 5000\n"); err != nil {
			return 0, "", err
		}
		br := bufio.NewReader(conn)
		okLine, err := br.ReadString('\n')
		if err != nil {
			return 0, "", fmt.Errorf("read firecracker vsock handshake: %w", err)
		}
		if !strings.HasPrefix(okLine, "OK ") {
			return 0, "", fmt.Errorf("firecracker vsock handshake failed: %q", okLine)
		}
		if _, err := fmt.Fprintf(conn, "CONNECT 127.0.0.1:%d HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n\r\n", port, port); err != nil {
			return 0, "", err
		}
		cResp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
		if err != nil {
			return 0, "", err
		}
		if cResp.StatusCode != http.StatusOK {
			return cResp.StatusCode, cResp.Header.Get("Proxy-Status"), nil
		}
		if _, err := fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n", path); err != nil {
			return 0, "", err
		}
		hResp, err := http.ReadResponse(br, nil)
		if err != nil {
			return 0, "", err
		}
		body, _ := io.ReadAll(hResp.Body)
		_ = hResp.Body.Close()
		return hResp.StatusCode, string(body), nil
	}

	var status int
	var body string
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); {
		status, body, err = dialVsockInbound(8080, "/hello-fc")
		if err == nil && status == http.StatusOK {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if err != nil || status != http.StatusOK || body != "microvm-vsock-inbound-ok:/hello-fc" {
		t.Fatalf("Firecracker vsock inbound :8080 = (%d, %q, %v)", status, body, err)
	}

	// Unpinned port 9999 must fail closed with 403 inside kube-tun2connect.
	denyStatus, _, err := dialVsockInbound(9999, "/nope")
	if err != nil || denyStatus != http.StatusForbidden {
		t.Fatalf("Firecracker vsock unpinned :9999 = (%d, %v), want 403", denyStatus, err)
	}

	// 4. Wait for guest outbound DoH + TCP + UDP assertions to pass!
	if err := console.waitFor("GUEST_OUTBOUND_PASS", 45*time.Second); err != nil {
		t.Fatalf("%v\nconsole:\n%s", err, console.String())
	}

	// Trigger clean guest shutdown over vsock inbound and wait for Firecracker exit.
	if stCode, _, err := dialVsockInbound(8080, "/shutdown"); err != nil || stCode != http.StatusOK {
		t.Fatalf("vsock inbound /shutdown failed: status=%d err=%v", stCode, err)
	}
	if err := fcCmd.Wait(); err != nil {
		t.Fatalf("Firecracker exited with error: %v\nconsole:\n%s", err, console.String())
	}
	assertPEPAudit(t, pepLogs.String(), "")
}
