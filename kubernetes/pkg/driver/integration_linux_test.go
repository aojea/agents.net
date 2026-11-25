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

//go:build linux

package driver

import (
	"bufio"
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
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	nriapi "github.com/containerd/nri/pkg/api"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	resourceapi "k8s.io/api/resource/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"

	"github.com/aojea/agents.net/kubernetes/internal/testutils"
	"github.com/aojea/agents.net/kubernetes/pkg/apis"
	"github.com/aojea/agents.net/kubernetes/pkg/auth"
	"github.com/aojea/agents.net/kubernetes/pkg/ingress"
	"github.com/aojea/agents.net/kubernetes/pkg/metrics"
	"github.com/aojea/agents.net/kubernetes/pkg/params"
	"github.com/aojea/agents.net/kubernetes/pkg/socketat"
	"github.com/aojea/agents.net/kubernetes/pkg/store"
	"github.com/aojea/agents.net/kubernetes/pkg/tunnel"
)

func createNamedPodNetNS(t *testing.T, prefix string) (nsPath string, nsHandle netns.NsHandle) {
	t.Helper()
	var rnd [4]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		t.Fatalf("random netns suffix: %v", err)
	}
	name := fmt.Sprintf("%s-%x", prefix, rnd)

	runtime.LockOSThread()
	orig, err := netns.Get()
	if err != nil {
		runtime.UnlockOSThread()
		t.Fatalf("get original netns: %v", err)
	}
	ns, createErr := netns.NewNamed(name)
	restoreErr := netns.Set(orig)
	_ = orig.Close()
	runtime.UnlockOSThread()
	if restoreErr != nil {
		t.Fatalf("restore original netns: %v", restoreErr)
	}
	if createErr != nil {
		t.Fatalf("create named netns %s: %v", name, createErr)
	}

	t.Cleanup(func() {
		_ = ns.Close()
		_ = netns.DeleteNamed(name)
	})

	// Bring loopback up inside the new Pod netns.
	nh, err := netlink.NewHandleAt(ns)
	if err != nil {
		t.Fatalf("netlink handle for %s: %v", name, err)
	}
	defer nh.Close()
	lo, err := nh.LinkByName("lo")
	if err != nil {
		t.Fatalf("lookup lo in %s: %v", name, err)
	}
	if err := nh.LinkSetUp(lo); err != nil {
		t.Fatalf("set lo up in %s: %v", name, err)
	}

	return filepath.Join("/run/netns", name), ns
}

func bringUpHostLoopback(t *testing.T) {
	t.Helper()
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatalf("lookup host lo: %v", err)
	}
	if err := netlink.LinkSetUp(lo); err != nil {
		t.Fatalf("set host lo up: %v", err)
	}
}

func TestIntegrationNetworkPolicyDenyAllRouteFlush(t *testing.T) {
	testutils.Run(t, testIntegrationNetworkPolicyDenyAllRouteFlush, syscall.CLONE_NEWNET, syscall.CLONE_NEWNS)
}

func testIntegrationNetworkPolicyDenyAllRouteFlush(t *testing.T) {
	bringUpHostLoopback(t)
	podNSPath, podNS := createNamedPodNetNS(t, "denyall")

	// Connect host netns (host0) and Pod netns (eth0) via a real dual-stack veth pair.
	veth := &netlink.Veth{
		LinkAttrs:     netlink.LinkAttrs{Name: "host0"},
		PeerName:      "eth0",
		PeerNamespace: netlink.NsFd(int(podNS)),
	}
	if err := netlink.LinkAdd(veth); err != nil {
		t.Fatalf("add veth pair: %v", err)
	}

	hostHandle, err := netlink.NewHandle()
	if err != nil {
		t.Fatalf("host netlink handle: %v", err)
	}
	defer hostHandle.Close()

	podHandle, err := netlink.NewHandleAt(podNS)
	if err != nil {
		t.Fatalf("pod netlink handle: %v", err)
	}
	defer podHandle.Close()

	setupLink := func(h *netlink.Handle, name string, cidrs ...string) netlink.Link {
		link, err := h.LinkByName(name)
		if err != nil {
			t.Fatalf("link %s: %v", name, err)
		}
		for _, cidr := range cidrs {
			addr, err := netlink.ParseAddr(cidr)
			if err != nil {
				t.Fatalf("parse addr %s: %v", cidr, err)
			}
			addr.Flags = syscall.IFA_F_NODAD
			if err := h.AddrAdd(link, addr); err != nil {
				t.Fatalf("add addr %s to %s: %v", cidr, name, err)
			}
		}
		if err := h.LinkSetUp(link); err != nil {
			t.Fatalf("link %s up: %v", name, err)
		}
		return link
	}

	setupLink(hostHandle, "host0", "192.0.2.1/30", "fd00:1234::1/64")
	podEth := setupLink(podHandle, "eth0", "192.0.2.2/30", "fd00:1234::2/64")

	for _, gw := range []string{"192.0.2.1", "fd00:1234::1"} {
		if err := podHandle.RouteAdd(&netlink.Route{Gw: net.ParseIP(gw)}); err != nil {
			t.Fatalf("add default route via %s: %v", gw, err)
		}
	}

	// Host TCP server reachable from Pod netns BEFORE route flush.
	hostLn, err := net.Listen("tcp4", "192.0.2.1:0")
	if err != nil {
		t.Fatalf("listen on host0: %v", err)
	}
	defer func() { _ = hostLn.Close() }()
	go func() {
		for {
			c, err := hostLn.Accept()
			if err != nil {
				return
			}
			_, _ = io.WriteString(c, "direct-reachable")
			_ = c.Close()
		}
	}()

	conn, err := socketat.DialAtPath(podNSPath, "tcp4", hostLn.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("expected direct dial to succeed before FlushNonLoopbackRoutes: %v", err)
	}
	_ = conn.Close()

	// Run the real NRI RunPodSandbox route flush on the Pod netns.
	netnsMgr := NewLinuxNetNSManager()
	if err := netnsMgr.FlushNonLoopbackRoutes(podNSPath); err != nil {
		t.Fatalf("FlushNonLoopbackRoutes: %v", err)
	}

	// Verify all IPv4 and IPv6 routes on eth0 were removed.
	for _, fam := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		routes, err := podHandle.RouteList(podEth, fam)
		if err != nil {
			t.Fatalf("list routes family %d: %v", fam, err)
		}
		if len(routes) != 0 {
			t.Fatalf("expected 0 remaining routes on eth0 (family %d), got %+v", fam, routes)
		}
	}

	// Direct dial from Pod netns to host0 MUST now fail.
	if c, err := socketat.DialAtPath(podNSPath, "tcp4", hostLn.Addr().String(), time.Second); err == nil {
		_ = c.Close()
		t.Fatal("direct dial to host0 succeeded after FlushNonLoopbackRoutes")
	}

	// Pod loopback MUST still work after flushing non-loopback routes.
	loLn, err := socketat.ListenAtPath(podNSPath, "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("loopback listen after route flush: %v", err)
	}
	defer func() { _ = loLn.Close() }()
	go func() {
		if c, err := loLn.Accept(); err == nil {
			_ = c.Close()
		}
	}()
	loConn, err := socketat.DialAtPath(podNSPath, "tcp4", loLn.Addr().String(), time.Second)
	if err != nil {
		t.Fatalf("loopback dial after route flush: %v", err)
	}
	_ = loConn.Close()
}

func TestIntegrationTCBlockNonLoopbackNICsPrimaryAndSecondary(t *testing.T) {
	testutils.Run(t, testIntegrationTCBlockNonLoopbackNICsPrimaryAndSecondary, syscall.CLONE_NEWNET, syscall.CLONE_NEWNS)
}

func testIntegrationTCBlockNonLoopbackNICsPrimaryAndSecondary(t *testing.T) {
	podNSPath, podNS := createNamedPodNetNS(t, "tcblock")

	hostHandle, err := netlink.NewHandle()
	if err != nil {
		t.Fatalf("host netlink handle: %v", err)
	}
	defer hostHandle.Close()
	podHandle, err := netlink.NewHandleAt(podNS)
	if err != nil {
		t.Fatalf("pod netlink handle: %v", err)
	}
	defer podHandle.Close()

	// Create TWO veth pairs into the Pod netns (primary eth0 + secondary net1)
	// with NO iptables/nftables/NetworkPolicy and NO route flushing to prove
	// pure-netlink tc clsact alone blocks both ingress and egress on every NIC.
	type nicPair struct {
		hostName, podName string
		hostCIDR, podCIDR string
		hostIP, podIP     string
	}
	pairs := []nicPair{
		{hostName: "host0", podName: "eth0", hostCIDR: "192.0.2.1/30", podCIDR: "192.0.2.2/30", hostIP: "192.0.2.1", podIP: "192.0.2.2"},
		{hostName: "host1", podName: "net1", hostCIDR: "198.51.100.1/30", podCIDR: "198.51.100.2/30", hostIP: "198.51.100.1", podIP: "198.51.100.2"},
	}

	setupAddrUp := func(h *netlink.Handle, name, cidr string) netlink.Link {
		link, err := h.LinkByName(name)
		if err != nil {
			t.Fatalf("link %s: %v", name, err)
		}
		addr, err := netlink.ParseAddr(cidr)
		if err != nil {
			t.Fatalf("parse addr %s: %v", cidr, err)
		}
		addr.Flags = syscall.IFA_F_NODAD
		if err := h.AddrAdd(link, addr); err != nil {
			t.Fatalf("add addr %s to %s: %v", cidr, name, err)
		}
		if err := h.LinkSetUp(link); err != nil {
			t.Fatalf("link %s up: %v", name, err)
		}
		return link
	}

	hostListeners := make([]net.Listener, 0, len(pairs))
	podUDPConns := make([]net.PacketConn, 0, len(pairs))
	for _, p := range pairs {
		veth := &netlink.Veth{
			LinkAttrs: netlink.LinkAttrs{Name: p.hostName},
			PeerName:  p.podName,
		}
		if err := hostHandle.LinkAdd(veth); err != nil {
			t.Fatalf("add veth %s/%s: %v", p.hostName, p.podName, err)
		}
		peer, err := hostHandle.LinkByName(p.podName)
		if err != nil {
			t.Fatalf("lookup peer %s: %v", p.podName, err)
		}
		if err := hostHandle.LinkSetNsFd(peer, int(podNS)); err != nil {
			t.Fatalf("move %s to pod netns: %v", p.podName, err)
		}
		setupAddrUp(hostHandle, p.hostName, p.hostCIDR)
		setupAddrUp(podHandle, p.podName, p.podCIDR)

		ln, err := net.Listen("tcp4", net.JoinHostPort(p.hostIP, "0"))
		if err != nil {
			t.Fatalf("host TCP listen %s: %v", p.hostIP, err)
		}
		defer func() { _ = ln.Close() }()
		go func(l net.Listener) {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				_, _ = io.WriteString(c, "ok")
				_ = c.Close()
			}
		}(ln)
		hostListeners = append(hostListeners, ln)

		var pc net.PacketConn
		if err := socketat.DoAtNSPath(podNSPath, func() error {
			var lerr error
			pc, lerr = net.ListenPacket("udp4", net.JoinHostPort(p.podIP, "0"))
			return lerr
		}); err != nil {
			t.Fatalf("pod UDP listen %s: %v", p.podIP, err)
		}
		defer func() { _ = pc.Close() }()
		podUDPConns = append(podUDPConns, pc)
	}

	// 1. Before BlockNonLoopbackNICs, both NICs pass egress TCP and inbound UDP.
	netnsMgr := NewLinuxNetNSManager()
	blocked, err := netnsMgr.VerifyNonLoopbackNICsBlocked(podNSPath, false)
	if err != nil {
		t.Fatalf("VerifyNonLoopbackNICsBlocked before: %v", err)
	}
	if blocked {
		t.Fatal("expected VerifyNonLoopbackNICsBlocked=false before attaching tc filters")
	}

	for i, p := range pairs {
		c, err := socketat.DialAtPath(podNSPath, "tcp4", hostListeners[i].Addr().String(), time.Second)
		if err != nil {
			t.Fatalf("pre-block egress TCP on %s failed: %v", p.podName, err)
		}
		_ = c.Close()

		sender, err := net.Dial("udp4", podUDPConns[i].LocalAddr().String())
		if err != nil {
			t.Fatalf("pre-block host UDP dial %s: %v", p.podName, err)
		}
		_, _ = sender.Write([]byte("ping"))
		_ = sender.Close()
		_ = podUDPConns[i].SetReadDeadline(time.Now().Add(time.Second))
		buf := make([]byte, 64)
		if _, _, err := podUDPConns[i].ReadFrom(buf); err != nil {
			t.Fatalf("pre-block inbound UDP on %s failed: %v", p.podName, err)
		}
	}

	// 2. Attach tc clsact matchall DROP filters TWICE (proving idempotency) without flushing routes.
	for attempt := range 2 {
		if err := netnsMgr.BlockNonLoopbackNICs(podNSPath, false); err != nil {
			t.Fatalf("BlockNonLoopbackNICs attempt %d: %v", attempt+1, err)
		}
	}

	blocked, err = netnsMgr.VerifyNonLoopbackNICsBlocked(podNSPath, false)
	if err != nil || !blocked {
		t.Fatalf("VerifyNonLoopbackNICsBlocked after = (%v, %v), want (true, nil)", blocked, err)
	}

	// 3. Both eth0 and secondary net1 MUST drop egress TCP AND inbound UDP while staying UP.
	for i, p := range pairs {
		link, err := podHandle.LinkByName(p.podName)
		if err != nil {
			t.Fatalf("link %s after tc block: %v", p.podName, err)
		}
		if link.Attrs().Flags&net.FlagUp == 0 {
			t.Fatalf("expected %s to remain UP after tc block", p.podName)
		}

		if c, err := socketat.DialAtPath(podNSPath, "tcp4", hostListeners[i].Addr().String(), 300*time.Millisecond); err == nil {
			_ = c.Close()
			t.Fatalf("egress TCP on %s unexpectedly succeeded after tc block", p.podName)
		}

		sender, err := net.Dial("udp4", podUDPConns[i].LocalAddr().String())
		if err != nil {
			t.Fatalf("post-block host UDP dial %s: %v", p.podName, err)
		}
		for range 3 {
			_, _ = sender.Write([]byte("blocked-udp"))
		}
		_ = sender.Close()
		_ = podUDPConns[i].SetReadDeadline(time.Now().Add(250 * time.Millisecond))
		buf := make([]byte, 64)
		if n, _, err := podUDPConns[i].ReadFrom(buf); err == nil {
			t.Fatalf("inbound UDP on %s unexpectedly delivered %d bytes (%q) after tc block", p.podName, n, string(buf[:n]))
		}
	}

	// 4. Loopback MUST remain completely unaffected.
	loLn, err := socketat.ListenAtPath(podNSPath, "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("loopback listen after tc block: %v", err)
	}
	defer func() { _ = loLn.Close() }()
	go func() {
		if c, err := loLn.Accept(); err == nil {
			_ = c.Close()
		}
	}()
	loConn, err := socketat.DialAtPath(podNSPath, "tcp4", loLn.Addr().String(), time.Second)
	if err != nil {
		t.Fatalf("loopback dial after tc block: %v", err)
	}
	_ = loConn.Close()
}

func TestIntegrationPodNetworkIsolatedNetNSCheck(t *testing.T) {
	testutils.Run(t, testIntegrationPodNetworkIsolatedNetNSCheck, syscall.CLONE_NEWNET, syscall.CLONE_NEWNS)
}

func testIntegrationPodNetworkIsolatedNetNSCheck(t *testing.T) {
	podNSPath, podNS := createNamedPodNetNS(t, "iso")

	netnsMgr := NewLinuxNetNSManager()

	// Loopback-only Pod netns passes verification.
	if err := netnsMgr.VerifyLoopbackOnly(podNSPath, false); err != nil {
		t.Fatalf("loopback-only netns rejected: %v", err)
	}

	// Adding any non-loopback interface causes verification to fail closed.
	podHandle, err := netlink.NewHandleAt(podNS)
	if err != nil {
		t.Fatalf("pod netlink handle: %v", err)
	}
	defer podHandle.Close()
	if err := podHandle.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "eth0"}}); err != nil {
		t.Fatalf("add dummy eth0: %v", err)
	}
	if err := netnsMgr.VerifyLoopbackOnly(podNSPath, false); err == nil {
		t.Fatal("expected VerifyLoopbackOnly to reject non-loopback eth0")
	}
}

type integrationPKI struct {
	caCert *x509.Certificate
	caKey  *ecdsa.PrivateKey
	caPEM  []byte
	caPool *x509.CertPool
}

func newIntegrationPKI(t *testing.T) *integrationPKI {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "integration-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA: %v", err)
	}
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &integrationPKI{
		caCert: cert,
		caKey:  key,
		caPEM:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		caPool: pool,
	}
}

func (p *integrationPKI) issue(t *testing.T, cn string, isServer bool) tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	eku := x509.ExtKeyUsageClientAuth
	var ips []net.IP
	if isServer {
		eku = x509.ExtKeyUsageServerAuth
		ips = []net.IP{net.ParseIP("127.0.0.1")}
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{eku},
		IPAddresses:  ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.caCert, &key.PublicKey, p.caKey)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	cPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	kPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	pair, err := tls.X509KeyPair(cPEM, kPEM)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}
	return pair
}

type countingListener struct {
	net.Listener
	count *atomic.Int32
}

func (l *countingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		l.count.Add(1)
	}
	return c, err
}

func TestIntegrationExplicitProxyCrossNetNS(t *testing.T) {
	testutils.Run(t, testIntegrationExplicitProxyCrossNetNS, syscall.CLONE_NEWNET, syscall.CLONE_NEWNS)
}

func testIntegrationExplicitProxyCrossNetNS(t *testing.T) {
	ctx := t.Context()
	bringUpHostLoopback(t)
	podNSPath, _ := createNamedPodNetNS(t, "egress")

	// Host-netns destinations: HTTP server + UDP echo server (unreachable directly from Pod netns).
	destHTTP := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "host-dest:"+r.URL.Path)
	}))
	defer destHTTP.Close()
	destHTTPAddr := strings.TrimPrefix(destHTTP.URL, "http://")

	udpEcho, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen host udp echo: %v", err)
	}
	defer func() { _ = udpEcho.Close() }()
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, rerr := udpEcho.ReadFrom(buf)
			if rerr != nil {
				return
			}
			_, _ = udpEcho.WriteTo(append([]byte("udp-echo:"), buf[:n]...), addr)
		}
	}()

	// Host-netns TLS upstream supporting HTTP/2 CONNECT + HTTP/1.1 connect-udp + policy deny.
	pki := newIntegrationPKI(t)
	srvPair := pki.issue(t, "127.0.0.1", true)
	caPath := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(caPath, pki.caPEM, 0o600); err != nil {
		t.Fatalf("write CA file: %v", err)
	}

	var (
		tlsConns atomic.Int32
		recMu    sync.Mutex
		h2Count  int
		udpCount int
		gotParam string
	)
	rawUpLn, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen upstream: %v", err)
	}
	tlsUpLn := &countingListener{
		Listener: tls.NewListener(rawUpLn, &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{srvPair},
			NextProtos:   []string{"h2", "http/1.1"},
		}),
		count: &tlsConns,
	}
	protos := new(http.Protocols)
	protos.SetHTTP1(true)
	protos.SetHTTP2(true)
	upSrv := &http.Server{
		Protocols: protos,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			recMu.Lock()
			if p := r.Header.Get(auth.HeaderCustomPrefix + "tenant"); p != "" {
				gotParam = p
			}
			recMu.Unlock()

			if r.Method == http.MethodConnect {
				if strings.Contains(r.Host, "blocked") {
					w.Header().Set("Proxy-Status", `test-portal; error=http_request_denied; details="blocked-by-portal"`)
					w.WriteHeader(http.StatusForbidden)
					return
				}
				dst, dialErr := net.DialTimeout("tcp4", r.Host, 2*time.Second)
				if dialErr != nil {
					w.WriteHeader(http.StatusBadGateway)
					return
				}
				defer func() { _ = dst.Close() }()
				recMu.Lock()
				if r.ProtoMajor == 2 {
					h2Count++
				}
				recMu.Unlock()

				w.WriteHeader(http.StatusOK)
				rc := http.NewResponseController(w)
				_ = rc.Flush()
				var wg sync.WaitGroup
				wg.Go(func() {
					_, _ = io.Copy(dst, r.Body)
					if tc, ok := dst.(*net.TCPConn); ok {
						_ = tc.CloseWrite()
					}
				})
				buf := make([]byte, 4096)
				for {
					n, rerr := dst.Read(buf)
					if n > 0 {
						if _, werr := w.Write(buf[:n]); werr != nil {
							break
						}
						_ = rc.Flush()
					}
					if rerr != nil {
						break
					}
				}
				_ = dst.Close()
				wg.Wait()
				return
			}

			if r.Method == http.MethodGet && strings.EqualFold(r.Header.Get("Upgrade"), "connect-udp") {
				rest := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/.well-known/masque/udp/"), "/")
				host, port, _ := strings.Cut(rest, "/")
				udpConn, dialErr := net.DialTimeout("udp4", net.JoinHostPort(host, port), 2*time.Second)
				if dialErr != nil {
					w.WriteHeader(http.StatusBadGateway)
					return
				}
				defer func() { _ = udpConn.Close() }()
				recMu.Lock()
				udpCount++
				recMu.Unlock()

				conn, brw, hijErr := http.NewResponseController(w).Hijack()
				if hijErr != nil {
					return
				}
				defer func() { _ = conn.Close() }()
				_, _ = io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: connect-udp\r\nCapsule-Protocol: ?1\r\n\r\n")
				cs := tunnel.NewCapsuleStream(brw.Reader, conn)
				go func() {
					buf := make([]byte, 4096)
					for {
						n, rerr := udpConn.Read(buf)
						if n > 0 {
							if cs.WriteDatagram(buf[:n]) != nil {
								return
							}
						}
						if rerr != nil {
							return
						}
					}
				}()
				for {
					dg, rerr := cs.ReadDatagram()
					if rerr != nil {
						return
					}
					if _, werr := udpConn.Write(dg); werr != nil {
						return
					}
				}
			}
			w.WriteHeader(http.StatusMethodNotAllowed)
		}),
	}
	go func() { _ = upSrv.Serve(tlsUpLn) }()
	defer func() { _ = upSrv.Close() }()

	// Wire real dra-agents-net Store + Tunnel Manager + Driver.
	boltDB, err := store.OpenBolt(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("OpenBolt: %v", err)
	}
	defer func() { _ = boltDB.Close() }()
	st, err := store.New(boltDB)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	tm, err := tunnel.NewManager(t.TempDir(), auth.NewResolver(auth.ResolverConfig{}), tunnel.WithAuditWriter(io.Discard))
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	defer tm.Close()
	drv, err := New(Config{
		DriverName: apis.DriverName,
		NodeName:   "test-node",
		Store:      st,
		Tunnel:     tm,
	})
	if err != nil {
		t.Fatalf("driver.New: %v", err)
	}
	drv.nriConnected.Store(true)

	const podUID = types.UID("pod-egress-uid-1")
	rawParams, err := json.Marshal(params.NetworkParameters{
		ConfinementMode: apis.ConfinementModePodNetworkIsolated,
		AdapterMode:     apis.AdapterModeExplicitProxy,
		Proxy:           &apis.ExplicitProxyConfig{Port: new(int32(15001))},
		PolicyEnforcementPoint: &apis.PolicyEnforcementPointConfig{
			URL: "https://" + rawUpLn.Addr().String(),
			TLS: &apis.PEPTLS{
				ServerName: "127.0.0.1",
				CACertificateRefs: []apis.CASource{
					{Type: apis.CASourceTypeHostPath, HostPath: caPath},
				},
			},
		},
		Custom: map[string]string{"tenant": "team-netns"},
	})
	if err != nil {
		t.Fatalf("marshal params: %v", err)
	}

	claim := &resourceapi.ResourceClaim{
		ObjectMeta: metav1.ObjectMeta{Name: "sb-claim", Namespace: "agents", UID: "claim-uid-1"},
		Status: resourceapi.ResourceClaimStatus{
			ReservedFor: []resourceapi.ResourceClaimConsumerReference{
				{Resource: "pods", Name: "sb-pod", UID: podUID},
			},
			Allocation: &resourceapi.AllocationResult{
				Devices: resourceapi.DeviceAllocationResult{
					Results: []resourceapi.DeviceRequestAllocationResult{
						{Request: apis.PodClaimName, Driver: apis.DriverName, Pool: "test-node", Device: DefaultDeviceName, ShareID: new(types.UID("33333333-3333-3333-3333-333333333333"))},
					},
					Config: []resourceapi.DeviceAllocationConfiguration{
						{
							Source: resourceapi.AllocationConfigSourceClass,
							DeviceConfiguration: resourceapi.DeviceConfiguration{
								Opaque: &resourceapi.OpaqueDeviceConfiguration{
									Driver:     apis.DriverName,
									Parameters: k8sruntime.RawExtension{Raw: rawParams},
								},
							},
						},
					},
				},
			},
		},
	}

	// 1. DRA PrepareResourceClaims + NRI RunPodSandbox (binds 127.0.0.1:15001 inside isolated Pod netns!).
	prepRes, err := drv.PrepareResourceClaims(ctx, []*resourceapi.ResourceClaim{claim})
	if err != nil || prepRes[claim.UID].Err != nil {
		t.Fatalf("PrepareResourceClaims: err=%v res=%+v", err, prepRes[claim.UID])
	}
	nriPod := &nriapi.PodSandbox{
		Uid:       string(podUID),
		Name:      "sb-pod",
		Namespace: "agents",
		Linux: &nriapi.LinuxPodSandbox{
			Namespaces: []*nriapi.LinuxNamespace{{Type: "network", Path: podNSPath}},
		},
	}
	if err := drv.RunPodSandbox(ctx, nriPod); err != nil {
		t.Fatalf("RunPodSandbox: %v", err)
	}

	// 2. Direct dial from isolated Pod netns to host destination MUST fail (isolated loopback).
	if c, dialErr := socketat.DialAtPath(podNSPath, "tcp4", destHTTPAddr, time.Second); dialErr == nil {
		_ = c.Close()
		t.Fatal("direct dial from isolated Pod netns to host destination unexpectedly succeeded")
	}

	// 3. HTTP requests from inside the Pod netns through 127.0.0.1:15001 multiplex over HTTP/2 CONNECT.
	proxyURL, _ := url.Parse("http://127.0.0.1:15001")
	podHTTPCli := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			DialContext: func(_ context.Context, network, addr string) (net.Conn, error) {
				return socketat.DialAtPath(podNSPath, network, addr, 2*time.Second)
			},
		},
	}
	for _, path := range []string{"/first", "/second"} {
		resp, reqErr := podHTTPCli.Get("http://" + destHTTPAddr + path)
		if reqErr != nil {
			t.Fatalf("GET %s via Pod 127.0.0.1:15001: %v", path, reqErr)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK || string(body) != "host-dest:"+path {
			t.Fatalf("GET %s: status=%d body=%q", path, resp.StatusCode, string(body))
		}
	}

	// 4. Blocked destination returns 403 + Proxy-Status over HTTP/2.
	blkConn, err := socketat.DialAtPath(podNSPath, "tcp4", "127.0.0.1:15001", 2*time.Second)
	if err != nil {
		t.Fatalf("dial Pod 127.0.0.1:15001: %v", err)
	}
	_ = blkConn.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = io.WriteString(blkConn, "CONNECT blocked.example:443 HTTP/1.1\r\nHost: blocked.example:443\r\n\r\n")
	blkResp, _ := io.ReadAll(blkConn)
	_ = blkConn.Close()
	if !strings.HasPrefix(string(blkResp), "HTTP/1.1 403 ") || !strings.Contains(string(blkResp), "blocked-by-portal") {
		t.Fatalf("blocked response = %q, want 403 blocked-by-portal", string(blkResp))
	}

	// Verify all 3 TCP tunnels multiplexed onto 1 upstream HTTP/2 TLS connection.
	if got := tlsConns.Load(); got != 1 {
		t.Fatalf("expected 1 multiplexed HTTP/2 TLS conn for 3 TCP tunnels, got %d", got)
	}

	// 5. RFC 9298 connect-udp over the Pod's egress.sock relays real UDP datagrams to host UDP echo.
	podCfg, ok := st.Get(podUID)
	if !ok {
		t.Fatalf("store missing pod %s", podUID)
	}
	udpHost, udpPort, _ := net.SplitHostPort(udpEcho.LocalAddr().String())
	udsConn, err := net.DialTimeout("unix", podCfg.SocketPaths.EgressSocketPath, 2*time.Second)
	if err != nil {
		t.Fatalf("dial egress.sock: %v", err)
	}
	defer func() { _ = udsConn.Close() }()
	_ = udsConn.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = fmt.Fprintf(udsConn, "GET /.well-known/masque/udp/%s/%s/ HTTP/1.1\r\nHost: egress.local\r\nConnection: Upgrade\r\nUpgrade: connect-udp\r\nCapsule-Protocol: ?1\r\n\r\n", udpHost, udpPort)
	br := bufio.NewReader(udsConn)
	uResp, err := http.ReadResponse(br, &http.Request{Method: http.MethodGet})
	if err != nil || uResp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("connect-udp upgrade failed: resp=%v err=%v", uResp, err)
	}
	_ = uResp.Body.Close()
	cs := tunnel.NewCapsuleStream(br, udsConn)
	if err := cs.WriteDatagram([]byte("cross-netns-ping")); err != nil {
		t.Fatalf("WriteDatagram: %v", err)
	}
	echoDG, err := cs.ReadDatagram()
	if err != nil || string(echoDG) != "udp-echo:cross-netns-ping" {
		t.Fatalf("ReadDatagram = %q err=%v, want udp-echo:cross-netns-ping", string(echoDG), err)
	}

	recMu.Lock()
	if h2Count != 2 || udpCount != 1 || gotParam != "team-netns" {
		t.Fatalf("upstream observations: h2=%d udp=%d param=%q, want 2/1/team-netns", h2Count, udpCount, gotParam)
	}
	recMu.Unlock()

	// 6. StopPodSandbox revokes egress immediately (503 listener-revoked).
	if err := drv.StopPodSandbox(ctx, nriPod); err != nil {
		t.Fatalf("StopPodSandbox: %v", err)
	}
	revConn, err := socketat.DialAtPath(podNSPath, "tcp4", "127.0.0.1:15001", 2*time.Second)
	if err != nil {
		t.Fatalf("dial revoked listener: %v", err)
	}
	_ = revConn.SetDeadline(time.Now().Add(2 * time.Second))
	_, _ = io.WriteString(revConn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
	revResp, _ := io.ReadAll(revConn)
	_ = revConn.Close()
	if !strings.HasPrefix(string(revResp), "HTTP/1.1 503 ") || !strings.Contains(string(revResp), "listener-revoked") {
		t.Fatalf("revoked response = %q, want 503 listener-revoked", string(revResp))
	}
}

func TestIntegrationHostIngressBridgeCrossNetNS(t *testing.T) {
	testutils.Run(t, testIntegrationHostIngressBridgeCrossNetNS, syscall.CLONE_NEWNET, syscall.CLONE_NEWNS)
}

func testIntegrationHostIngressBridgeCrossNetNS(t *testing.T) {
	bringUpHostLoopback(t)
	podNSPath, _ := createNamedPodNetNS(t, "ingress")

	// Start two loopback-only HTTP servers INSIDE the isolated Pod netns: :8080 (allowed) and :9999 (denied).
	ln8080, err := socketat.ListenAtPath(podNSPath, "tcp4", "127.0.0.1:8080")
	if err != nil {
		t.Fatalf("listen 127.0.0.1:8080 in Pod netns: %v", err)
	}
	srv8080 := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "pod-netns-8080:"+r.URL.Path)
	})}
	go func() { _ = srv8080.Serve(ln8080) }()
	defer func() { _ = srv8080.Close() }()

	ln9999, err := socketat.ListenAtPath(podNSPath, "tcp4", "127.0.0.1:9999")
	if err != nil {
		t.Fatalf("listen 127.0.0.1:9999 in Pod netns: %v", err)
	}
	srv9999 := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "secret-9999")
	})}
	go func() { _ = srv9999.Serve(ln9999) }()
	defer func() { _ = srv9999.Close() }()

	// Confirm host netns CANNOT reach Pod's 127.0.0.1:8080 directly.
	if c, dialErr := net.DialTimeout("tcp4", "127.0.0.1:8080", 500*time.Millisecond); dialErr == nil {
		_ = c.Close()
		t.Fatal("host unexpectedly reached Pod loopback 127.0.0.1:8080 directly")
	}

	// Start real mTLS host ingress bridge wired to Driver + Store.
	pki := newIntegrationPKI(t)
	srvPair := pki.issue(t, "dra-agents-net-ingress", true)
	cliPair := pki.issue(t, "sandbox-router", false)

	boltDB, err := store.OpenBolt(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("OpenBolt: %v", err)
	}
	defer func() { _ = boltDB.Close() }()
	st, err := store.New(boltDB)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}

	const podUID = types.UID("pod-ingress-uid-1")
	if err := st.Upsert(store.PodConfig{
		PodUID: podUID,
		NetNS:  podNSPath,
		Parameters: params.NetworkParameters{
			ConfinementMode: apis.ConfinementModePodNetworkIsolated,
			AdapterMode:     apis.AdapterModeExplicitProxy,
			IngressPorts:    []apis.IngressPort{{Port: 8080, Protocol: apis.IngressProtocolTCP}},
		},
	}); err != nil {
		t.Fatalf("store.Upsert: %v", err)
	}

	ingSrv, err := ingress.NewServer(ingress.Config{
		ListenAddr: "127.0.0.1:0",
		Store:      st,
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{srvPair},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    pki.caPool,
		},
	})
	if err != nil {
		t.Fatalf("ingress.NewServer: %v", err)
	}
	bridgeNetAddr, err := ingSrv.Start()
	if err != nil {
		t.Fatalf("ingress.Start: %v", err)
	}
	defer func() { _ = ingSrv.Close() }()
	bridgeAddr := bridgeNetAddr.String()

	cliTLS := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		RootCAs:      pki.caPool,
		Certificates: []tls.Certificate{cliPair},
		ServerName:   "127.0.0.1",
	}

	dialBridge := func(authority string) (*http.Response, *bufio.Reader, net.Conn) {
		c, err := tls.Dial("tcp4", bridgeAddr, cliTLS)
		if err != nil {
			t.Fatalf("tls dial ingress bridge: %v", err)
		}
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		_, _ = fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", authority, authority)
		br := bufio.NewReader(c)
		resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
		if err != nil {
			_ = c.Close()
			t.Fatalf("read CONNECT response for %s: %v", authority, err)
		}
		return resp, br, c
	}

	// 1. Declared port 8080 reaches Pod netns loopback via socketat.DialAtPath over mTLS.
	resp, br, conn := dialBridge(string(podUID) + ":8080")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("allowed port 8080 status = %d, want 200", resp.StatusCode)
	}
	_, _ = io.WriteString(conn, "GET /webhook HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n")
	httpResp, err := http.ReadResponse(br, &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("read tunneled HTTP response: %v", err)
	}
	body, _ := io.ReadAll(httpResp.Body)
	_ = httpResp.Body.Close()
	_ = conn.Close()
	if string(body) != "pod-netns-8080:/webhook" {
		t.Fatalf("tunneled body = %q, want pod-netns-8080:/webhook", string(body))
	}

	// 2. Undeclared port 9999 returns 403 with RFC 9209 Proxy-Status.
	denyResp, _, denyConn := dialBridge(string(podUID) + ":9999")
	_ = denyConn.Close()
	if denyResp.StatusCode != http.StatusForbidden || !strings.Contains(denyResp.Header.Get("Proxy-Status"), "error=http_request_denied; reason=port-not-permitted") {
		t.Fatalf("undeclared port 9999: status=%d Proxy-Status=%q, want 403 port-not-permitted", denyResp.StatusCode, denyResp.Header.Get("Proxy-Status"))
	}

	// 3. Unknown Pod UID returns 404 with RFC 9209 Proxy-Status.
	unkResp, _, unkConn := dialBridge("unknown-pod-uid:8080")
	_ = unkConn.Close()
	if unkResp.StatusCode != http.StatusNotFound || !strings.Contains(unkResp.Header.Get("Proxy-Status"), "error=destination_not_found; reason=unknown-sandbox") {
		t.Fatalf("unknown pod: status=%d Proxy-Status=%q, want 404 unknown-sandbox", unkResp.StatusCode, unkResp.Header.Get("Proxy-Status"))
	}

	// 4. Revoke closes an active ingress tunnel immediately and rejects subsequent dials with 404.
	liveResp, _, liveConn := dialBridge(string(podUID) + ":8080")
	if liveResp.StatusCode != http.StatusOK {
		t.Fatalf("live tunnel status = %d, want 200", liveResp.StatusCode)
	}
	ingSrv.Revoke(podUID)
	buf := make([]byte, 16)
	_, readErr := liveConn.Read(buf)
	_ = liveConn.Close()
	if readErr == nil {
		t.Fatal("expected active ingress tunnel to close immediately after Revoke")
	}
	revokedResp, _, revokedConn := dialBridge(string(podUID) + ":8080")
	_ = revokedConn.Close()
	if revokedResp.StatusCode != http.StatusNotFound || !strings.Contains(revokedResp.Header.Get("Proxy-Status"), "reason=sandbox-revoked") {
		t.Fatalf("revoked pod: status=%d Proxy-Status=%q, want 404 sandbox-revoked", revokedResp.StatusCode, revokedResp.Header.Get("Proxy-Status"))
	}
}

// TestIntegrationSynchronizeReportsMissingPlumbing runs inside an unprivileged
// Linux user/network namespace and verifies that Synchronize inspects the live
// Pod network namespace (via netlink) and container mounts to detect Pods
// created while dra-agents-net NRI was disconnected.
func TestIntegrationSynchronizeReportsMissingPlumbing(t *testing.T) {
	testutils.Run(t, testIntegrationSynchronizeReportsMissingPlumbing, syscall.CLONE_NEWNET|syscall.CLONE_NEWNS)
}

func testIntegrationSynchronizeReportsMissingPlumbing(t *testing.T) {
	ctx := t.Context()

	// 1. NetworkPolicyDenyAll pod with real veth + routes (never flushed because NRI was down).
	podDenyNSPath, podDenyNS := createNamedPodNetNS(t, "missing-deny")
	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: "veth-mh0"},
		PeerName:  "eth0",
	}
	if err := netlink.LinkAdd(veth); err != nil {
		t.Fatalf("LinkAdd veth: %v", err)
	}
	peer, err := netlink.LinkByName("eth0")
	if err != nil {
		t.Fatalf("LinkByName eth0: %v", err)
	}
	if err := netlink.LinkSetNsFd(peer, int(podDenyNS)); err != nil {
		t.Fatalf("LinkSetNsFd eth0: %v", err)
	}
	if err := netlink.LinkSetUp(veth); err != nil {
		t.Fatalf("LinkSetUp host veth: %v", err)
	}
	if err := socketat.DoAtNSPath(podDenyNSPath, func() error {
		h, err := netlink.NewHandle()
		if err != nil {
			return err
		}
		defer h.Close()
		eth0, err := h.LinkByName("eth0")
		if err != nil {
			return err
		}
		if err := h.LinkSetUp(eth0); err != nil {
			return err
		}
		addr, _ := netlink.ParseAddr("10.201.0.2/24")
		return h.AddrAdd(eth0, addr)
	}); err != nil {
		t.Fatalf("configure pod eth0: %v", err)
	}

	// 2. PodNetworkIsolated pod with an unexpected dummy interface.
	podIsoNSPath, _ := createNamedPodNetNS(t, "missing-iso")
	if err := socketat.DoAtNSPath(podIsoNSPath, func() error {
		h, err := netlink.NewHandle()
		if err != nil {
			return err
		}
		defer h.Close()
		return h.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "eth0"}})
	}); err != nil {
		t.Fatalf("add dummy eth0 in isolated netns: %v", err)
	}

	st, _ := store.New(nil)
	tm, err := tunnel.NewManager(shortTempDir(t), nil, tunnel.WithAuditWriter(io.Discard))
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	defer tm.Close()

	recorder := record.NewFakeRecorder(10)
	drv, err := New(Config{
		NodeName:      "test-node",
		Store:         st,
		Tunnel:        tm,
		EventRecorder: recorder,
	})
	if err != nil {
		t.Fatalf("driver.New: %v", err)
	}

	const denyUID = types.UID("pod-missing-deny")
	const isoUID = types.UID("pod-missing-iso")
	_ = st.Upsert(store.PodConfig{
		PodUID:       denyUID,
		PodName:      "sb-deny",
		PodNamespace: "agents",
		Parameters: params.NetworkParameters{
			ConfinementMode: apis.ConfinementModeNetworkPolicyDenyAll,
			AdapterMode:     apis.AdapterModeExplicitProxy,
			Proxy:           &apis.ExplicitProxyConfig{Port: new(int32(15001))},
		},
	})
	_ = st.Upsert(store.PodConfig{
		PodUID:       isoUID,
		PodName:      "sb-iso",
		PodNamespace: "agents",
		Parameters: params.NetworkParameters{
			ConfinementMode: apis.ConfinementModePodNetworkIsolated,
			AdapterMode:     apis.AdapterModeExplicitProxy,
			Proxy:           &apis.ExplicitProxyConfig{Port: new(int32(15002))},
		},
	})

	denyPod := &nriapi.PodSandbox{
		Id: "sb-deny", Uid: string(denyUID), Name: "sb-deny", Namespace: "agents",
		Linux: &nriapi.LinuxPodSandbox{Namespaces: []*nriapi.LinuxNamespace{{Type: "network", Path: podDenyNSPath}}},
	}
	isoPod := &nriapi.PodSandbox{
		Id: "sb-iso", Uid: string(isoUID), Name: "sb-iso", Namespace: "agents",
		Linux: &nriapi.LinuxPodSandbox{Namespaces: []*nriapi.LinuxNamespace{{Type: "network", Path: podIsoNSPath}}},
	}

	// Running containers missing mounts + real kernel routes/interfaces -> both reported.
	before := testutil.ToFloat64(metrics.PodsMissingPlumbingTotal)
	_, err = drv.Synchronize(ctx, []*nriapi.PodSandbox{denyPod, isoPod}, []*nriapi.Container{
		{Id: "c1", PodSandboxId: denyPod.Id, Name: "agent", State: nriapi.ContainerState_CONTAINER_RUNNING},
		{Id: "c2", PodSandboxId: isoPod.Id, Name: "agent", State: nriapi.ContainerState_CONTAINER_RUNNING},
	})
	if err != nil {
		t.Fatalf("Synchronize: %v", err)
	}
	if delta := testutil.ToFloat64(metrics.PodsMissingPlumbingTotal) - before; delta != 2 {
		t.Fatalf("PodsMissingPlumbingTotal delta = %v, want 2", delta)
	}
	var events []string
	for len(recorder.Events) > 0 {
		events = append(events, <-recorder.Events)
	}
	joined := strings.Join(events, "\n")
	for _, want := range []string{"non-loopback-routes-unflushed", "non-loopback-nics-unblocked", "egress-socket-mount", "loopback-only-netns"} {
		if !strings.Contains(joined, want) {
			t.Errorf("events missing %q:\n%s", want, joined)
		}
	}

	// Flush routes AND install tc NIC drop filters on denyPod netns + supply the mount -> denyPod is clean.
	netnsMgr := NewLinuxNetNSManager()
	if err := netnsMgr.FlushNonLoopbackRoutes(podDenyNSPath); err != nil {
		t.Fatalf("FlushNonLoopbackRoutes: %v", err)
	}
	if err := netnsMgr.BlockNonLoopbackNICs(podDenyNSPath, false); err != nil {
		t.Fatalf("BlockNonLoopbackNICs: %v", err)
	}
	before = testutil.ToFloat64(metrics.PodsMissingPlumbingTotal)
	_, err = drv.Synchronize(ctx, []*nriapi.PodSandbox{denyPod}, []*nriapi.Container{
		{
			Id:           "c1",
			PodSandboxId: denyPod.Id,
			Name:         "agent",
			State:        nriapi.ContainerState_CONTAINER_RUNNING,
			Mounts:       []*nriapi.Mount{{Destination: containerEgressMountDir}},
		},
	})
	if err != nil {
		t.Fatalf("Synchronize after flush+tc: %v", err)
	}
	if delta := testutil.ToFloat64(metrics.PodsMissingPlumbingTotal) - before; delta != 0 {
		t.Fatalf("healthy pod after flush+tc incremented PodsMissingPlumbingTotal by %v, want 0", delta)
	}
}
