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
	"net/netip"
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

	"github.com/aojea/agents.net/internal/testutils"
	"github.com/aojea/agents.net/pkg/apis"
	"github.com/aojea/agents.net/pkg/auth"
	"github.com/aojea/agents.net/pkg/hosttun"
	"github.com/aojea/agents.net/pkg/ingress"
	"github.com/aojea/agents.net/pkg/metrics"
	"github.com/aojea/agents.net/pkg/params"
	"github.com/aojea/agents.net/pkg/socketat"
	"github.com/aojea/agents.net/pkg/store"
	"github.com/aojea/agents.net/pkg/tun2connect"
	"github.com/aojea/agents.net/pkg/tunnel"
)

func TestMain(m *testing.M) {
	if hosttun.IsWorkerEnv() {
		if err := hosttun.RunWorker(); err != nil {
			fmt.Fprintf(os.Stderr, "host-tun worker exited with error: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

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

func (p *integrationPKI) issuePEM(t *testing.T, cn string, isServer bool) ([]byte, []byte, tls.Certificate) {
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
	return cPEM, kPEM, pair
}

func (p *integrationPKI) issue(t *testing.T, cn string, isServer bool) tls.Certificate {
	t.Helper()
	_, _, pair := p.issuePEM(t, cn, isServer)
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

// TestIntegrationL2VethGVisorCrossNetNS exercises the transparent L2 veth capture
// path used for gVisor (RuntimeHandler="runsc"):
//   - A CNI-style veth pair connects the host netns (10.244.7.1/24) to eth0
//     (10.244.7.8/24, default gw 10.244.7.1) inside the Pod netns.
//   - NRI RunPodSandbox moves the host veth peer into a fresh empty isolated
//     netns and hands an AF_PACKET descriptor to unprivileged kube-netstack in
//     TAP mode, severing host kernel routing completely.
//   - Unmodified DNS, TCP, and UDP sockets inside the Pod netns traverse eth0
//     -> veth -> AF_PACKET -> kube-netstack -> mTLS HTTP/2 PEP.
//   - Direct host reachability fails closed after veth capture.
//   - Inbound mTLS CONNECT through pkg/ingress.Server reaches a TCP server
//     listening on eth0 (10.244.7.8:8080) inside the Pod netns via DialGuest.
func TestIntegrationL2VethGVisorCrossNetNS(t *testing.T) {
	testutils.Run(t, testIntegrationL2VethGVisorCrossNetNS, syscall.CLONE_NEWNET, syscall.CLONE_NEWNS)
}

func testIntegrationL2VethGVisorCrossNetNS(t *testing.T) {
	ctx := t.Context()
	bringUpHostLoopback(t)
	podNSPath, podNS := createNamedPodNetNS(t, "l2veth")

	// Set up a CNI-style veth pair: hostveth (10.244.7.1/24) <-> pod eth0 (10.244.7.8/24).
	veth := &netlink.Veth{
		LinkAttrs:     netlink.LinkAttrs{Name: "vethgv0"},
		PeerName:      "eth0",
		PeerNamespace: netlink.NsFd(int(podNS)),
	}
	if err := netlink.LinkAdd(veth); err != nil {
		t.Fatalf("LinkAdd veth: %v", err)
	}
	hostVeth, err := netlink.LinkByName("vethgv0")
	if err != nil {
		t.Fatalf("LinkByName vethgv0: %v", err)
	}
	hostAddr, _ := netlink.ParseAddr("10.244.7.1/24")
	if err := netlink.AddrAdd(hostVeth, hostAddr); err != nil {
		t.Fatalf("AddrAdd hostVeth: %v", err)
	}
	if err := netlink.LinkSetUp(hostVeth); err != nil {
		t.Fatalf("LinkSetUp hostVeth: %v", err)
	}

	podHandle, err := netlink.NewHandleAt(podNS)
	if err != nil {
		t.Fatalf("pod netlink handle: %v", err)
	}
	defer podHandle.Close()
	eth0, err := podHandle.LinkByName("eth0")
	if err != nil {
		t.Fatalf("lookup eth0: %v", err)
	}
	podAddr, _ := netlink.ParseAddr("10.244.7.8/24")
	if err := podHandle.AddrAdd(eth0, podAddr); err != nil {
		t.Fatalf("AddrAdd eth0: %v", err)
	}
	if err := podHandle.LinkSetUp(eth0); err != nil {
		t.Fatalf("LinkSetUp eth0: %v", err)
	}
	if err := podHandle.RouteAdd(&netlink.Route{
		LinkIndex: eth0.Attrs().Index,
		Gw:        net.ParseIP("10.244.7.1"),
	}); err != nil {
		t.Fatalf("add default route via 10.244.7.1: %v", err)
	}

	// Host-netns destinations: HTTP server + UDP echo server.
	destHTTP := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "l2-host-dest:"+r.URL.Path)
	}))
	defer destHTTP.Close()
	destHTTPAddr := strings.TrimPrefix(destHTTP.URL, "http://")
	_, destHTTPPort, _ := net.SplitHostPort(destHTTPAddr)

	udpEcho, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen host udp echo: %v", err)
	}
	defer func() { _ = udpEcho.Close() }()
	_, udpEchoPort, _ := net.SplitHostPort(udpEcho.LocalAddr().String())
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

	// Host-netns mTLS PEP supporting HTTP/2 CONNECT + HTTP/1.1 connect-udp + policy deny.
	pki := newIntegrationPKI(t)
	srvPair := pki.issue(t, "127.0.0.1", true)
	cliCertPEM, cliKeyPEM, cliPair := pki.issuePEM(t, "dra-l2-client", false)
	certDir := t.TempDir()
	caPath := filepath.Join(certDir, "ca.crt")
	if err := os.WriteFile(caPath, pki.caPEM, 0o600); err != nil {
		t.Fatalf("write CA file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(certDir, "tls.crt"), cliCertPEM, 0o600); err != nil {
		t.Fatalf("write client cert: %v", err)
	}
	if err := os.WriteFile(filepath.Join(certDir, "tls.key"), cliKeyPEM, 0o600); err != nil {
		t.Fatalf("write client key: %v", err)
	}

	var (
		tlsConns atomic.Int32
		recMu    sync.Mutex
		h2Count  int
		udpCount int
		gotAttrs string
	)
	rawUpLn, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen upstream: %v", err)
	}
	tlsUpLn := &countingListener{
		Listener: tls.NewListener(rawUpLn, &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{srvPair},
			ClientCAs:    pki.caPool,
			ClientAuth:   tls.RequireAndVerifyClientCert,
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
			if a := r.Header.Get(auth.HeaderAttributes); a != "" {
				gotAttrs = a
			}
			recMu.Unlock()

			if r.Method == http.MethodConnect {
				if strings.HasPrefix(r.Host, "blocked.") || strings.HasPrefix(r.Host, "10.244.") {
					w.Header().Set("Proxy-Status", `test-pep; error=http_request_denied; reason=policy-denied`)
					w.WriteHeader(http.StatusForbidden)
					return
				}
				dialTarget := r.Host
				if strings.HasPrefix(r.Host, "api.allowed.test:") {
					dialTarget = destHTTPAddr
				}
				dst, dialErr := net.DialTimeout("tcp4", dialTarget, 2*time.Second)
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
				dialTarget := net.JoinHostPort(host, port)
				if host == "udp.allowed.test" {
					dialTarget = udpEcho.LocalAddr().String()
				}
				udpConn, dialErr := net.DialTimeout("udp4", dialTarget, 2*time.Second)
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
	htMgr := hosttun.NewManager(hosttun.ManagerConfig{Isolation: hosttun.IsolationShared})
	defer func() { _ = htMgr.Close() }()
	drv, err := New(Config{
		DriverName: apis.DriverName,
		NodeName:   "test-node",
		Store:      st,
		Tunnel:     tm,
		NetNS:      NewLinuxNetNSManagerWithHostTun(htMgr),
	})
	if err != nil {
		t.Fatalf("driver.New: %v", err)
	}
	drv.nriConnected.Store(true)
	defer drv.stopAllHostTuns(true)

	const podUID = types.UID("pod-l2-gvisor-uid-1")
	rawParams, err := json.Marshal(params.NetworkParameters{
		ConfinementMode: apis.ConfinementModeNetworkPolicyDenyAll,
		IngressPorts:    []apis.IngressPort{{Port: 8080, Protocol: apis.IngressProtocolTCP}},
		PolicyEnforcementPoint: &apis.PolicyEnforcementPointConfig{
			URL: "https://" + rawUpLn.Addr().String(),
			TLS: &apis.PEPTLS{
				ServerName: "127.0.0.1",
				CACertificateRefs: []apis.CASource{
					{Type: apis.CASourceTypeHostPath, HostPath: caPath},
				},
			},
			Auth: &apis.PEPAuth{
				Type: apis.PEPAuthTypeMTLS,
				MTLS: &apis.MTLSAuth{CertDir: certDir},
			},
		},
		Custom: map[string]string{"tenant": "team-gvisor"},
	})
	if err != nil {
		t.Fatalf("marshal params: %v", err)
	}
	claim := &resourceapi.ResourceClaim{
		ObjectMeta: metav1.ObjectMeta{Name: "gv-claim", Namespace: "agents", UID: "claim-gv-uid-1"},
		Status: resourceapi.ResourceClaimStatus{
			ReservedFor: []resourceapi.ResourceClaimConsumerReference{
				{Resource: "pods", Name: "gv-pod", UID: podUID},
			},
			Allocation: &resourceapi.AllocationResult{
				Devices: resourceapi.DeviceAllocationResult{
					Results: []resourceapi.DeviceRequestAllocationResult{
						{Request: apis.PodClaimName, Driver: apis.DriverName, Pool: "test-node", Device: DefaultDeviceName},
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

	// 1. DRA PrepareResourceClaims + NRI RunPodSandbox (RuntimeHandler="runsc").
	prepRes, err := drv.PrepareResourceClaims(ctx, []*resourceapi.ResourceClaim{claim})
	if err != nil || prepRes[claim.UID].Err != nil {
		t.Fatalf("PrepareResourceClaims: err=%v res=%+v", err, prepRes[claim.UID])
	}
	nriPod := &nriapi.PodSandbox{
		Id:             "sb-gv-1",
		Uid:            string(podUID),
		Name:           "gv-pod",
		Namespace:      "agents",
		RuntimeHandler: "runsc",
		Linux: &nriapi.LinuxPodSandbox{
			Namespaces: []*nriapi.LinuxNamespace{{Type: "network", Path: podNSPath}},
		},
	}
	if err := drv.RunPodSandbox(ctx, nriPod); err != nil {
		t.Fatalf("RunPodSandbox(runsc): %v", err)
	}

	// Host veth peer must have disappeared from the host network namespace.
	if _, err := netlink.LinkByName("vethgv0"); err == nil {
		t.Fatal("vethgv0 is still present in host netns after L2 veth capture")
	}
	podCfg, ok := st.Get(podUID)
	if !ok || podCfg.GuestIP != "10.244.7.8" {
		t.Fatalf("stored GuestIP = %q (ok=%v), want 10.244.7.8", podCfg.GuestIP, ok)
	}

	// 2. Standard DNS + TCP + UDP inside Pod netns go over eth0 -> AF_PACKET -> kube-netstack -> mTLS H2 PEP.
	syntheticPool := netip.MustParsePrefix("198.18.0.0/15")
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(_ context.Context, _, _ string) (net.Conn, error) {
			return socketat.DialAtPath(podNSPath, "udp4", tun2connect.DefaultResolverAddr+":53", 3*time.Second)
		},
	}
	ips, err := resolver.LookupNetIP(ctx, "ip4", "api.allowed.test")
	if err != nil || len(ips) != 1 || !syntheticPool.Contains(ips[0]) {
		t.Fatalf("LookupNetIP(api.allowed.test) = (%v, %v), want IP in 198.18.0.0/15", ips, err)
	}
	for _, path := range []string{"/first", "/second"} {
		conn, err := socketat.DialAtPath(podNSPath, "tcp4", net.JoinHostPort(ips[0].String(), destHTTPPort), 5*time.Second)
		if err != nil {
			t.Fatalf("L2 TCP dial %s: %v", path, err)
		}
		_, _ = io.WriteString(conn, fmt.Sprintf("GET %s HTTP/1.1\r\nHost: api.allowed.test\r\nConnection: close\r\n\r\n", path))
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			_ = conn.Close()
			t.Fatalf("read HTTP %s: %v", path, err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		_ = conn.Close()
		if string(body) != "l2-host-dest:"+path {
			t.Fatalf("GET %s body = %q, want l2-host-dest:%s", path, string(body), path)
		}
	}

	// Blocked destination fails closed.
	blkIPs, err := resolver.LookupNetIP(ctx, "ip4", "blocked.example")
	if err != nil || len(blkIPs) != 1 {
		t.Fatalf("LookupNetIP(blocked.example) = (%v, %v)", blkIPs, err)
	}
	if c, err := socketat.DialAtPath(podNSPath, "tcp4", net.JoinHostPort(blkIPs[0].String(), "443"), 3*time.Second); err == nil {
		_ = c.Close()
		t.Fatal("blocked.example unexpectedly succeeded over L2 veth")
	}

	// All 3 TCP attempts multiplexed onto 1 upstream mTLS HTTP/2 connection.
	if got := tlsConns.Load(); got != 1 {
		t.Fatalf("expected 1 multiplexed HTTP/2 TLS conn, got %d", got)
	}

	// Unmodified UDP socket traverses connect-udp cleanly.
	udpIPs, err := resolver.LookupNetIP(ctx, "ip4", "udp.allowed.test")
	if err != nil || len(udpIPs) != 1 {
		t.Fatalf("LookupNetIP(udp.allowed.test) = (%v, %v)", udpIPs, err)
	}
	uconn, err := socketat.DialAtPath(podNSPath, "udp4", net.JoinHostPort(udpIPs[0].String(), udpEchoPort), 5*time.Second)
	if err != nil {
		t.Fatalf("L2 UDP dial: %v", err)
	}
	_ = uconn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := uconn.Write([]byte("l2-udp-ping")); err != nil {
		_ = uconn.Close()
		t.Fatalf("write UDP: %v", err)
	}
	ubuf := make([]byte, 128)
	n, err := uconn.Read(ubuf)
	_ = uconn.Close()
	if err != nil || string(ubuf[:n]) != "udp-echo:l2-udp-ping" {
		t.Fatalf("L2 UDP echo = (%q, %v), want udp-echo:l2-udp-ping", string(ubuf[:n]), err)
	}

	recMu.Lock()
	if h2Count != 2 || udpCount != 1 || !strings.Contains(gotAttrs, `tenant="team-gvisor"`) {
		t.Fatalf("upstream observations: h2=%d udp=%d attrs=%q", h2Count, udpCount, gotAttrs)
	}
	recMu.Unlock()

	// 3. Inbound mTLS CONNECT through pkg/ingress.Server reaches HTTP server bound on eth0 (0.0.0.0:8080) via DialGuest!
	podHTTP8080, err := socketat.ListenAtPath(podNSPath, "tcp4", "0.0.0.0:8080")
	if err != nil {
		t.Fatalf("listen 0.0.0.0:8080 in Pod netns: %v", err)
	}
	podHTTPSrv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "l2-guest-8080:"+r.URL.Path)
	})}
	go func() { _ = podHTTPSrv.Serve(podHTTP8080) }()
	defer func() { _ = podHTTPSrv.Close() }()

	ingSrv, err := ingress.NewServer(ingress.Config{
		ListenAddr: "127.0.0.1:0",
		Store:      st,
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{srvPair},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    pki.caPool,
		},
		DialGuest: func(ctx context.Context, uid types.UID, ip netip.Addr, port uint16) (net.Conn, error) {
			return htMgr.DialInbound(ctx, string(uid), ip, port)
		},
	})
	if err != nil {
		t.Fatalf("ingress.NewServer: %v", err)
	}
	bridgeAddr, err := ingSrv.Start()
	if err != nil {
		t.Fatalf("ingress.Start: %v", err)
	}
	defer func() { _ = ingSrv.Close() }()

	inConn, err := tls.Dial("tcp4", bridgeAddr.String(), &tls.Config{
		MinVersion:   tls.VersionTLS12,
		RootCAs:      pki.caPool,
		Certificates: []tls.Certificate{cliPair},
		ServerName:   "127.0.0.1",
	})
	if err != nil {
		t.Fatalf("tls dial ingress: %v", err)
	}
	defer func() { _ = inConn.Close() }()
	_ = inConn.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = fmt.Fprintf(inConn, "CONNECT %s:8080 HTTP/1.1\r\nHost: %s:8080\r\n\r\n", podUID, podUID)
	inBR := bufio.NewReader(inConn)
	inResp, err := http.ReadResponse(inBR, &http.Request{Method: http.MethodConnect})
	if err != nil || inResp.StatusCode != http.StatusOK {
		t.Fatalf("L2 inbound CONNECT: resp=%v err=%v", inResp, err)
	}
	_, _ = io.WriteString(inConn, "GET /hello-gvisor HTTP/1.1\r\nHost: sandbox\r\nConnection: close\r\n\r\n")
	guestResp, err := http.ReadResponse(inBR, &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("read L2 inbound HTTP response: %v", err)
	}
	guestBody, _ := io.ReadAll(guestResp.Body)
	_ = guestResp.Body.Close()
	if string(guestBody) != "l2-guest-8080:/hello-gvisor" {
		t.Fatalf("L2 inbound body = %q, want l2-guest-8080:/hello-gvisor", string(guestBody))
	}

	// 4. Verify runsc-style AddrDel recovery: when eth0 has no IP/routes left in
	// the Pod netns, startL2VethHostTun recovers guestIP from NRI PodSandbox.Ips
	// and gateway CIDR from hostVeth before moving hostVeth to isolated netns.
	strippedNSPath, strippedNS := createNamedPodNetNS(t, "l2stripped")
	sv := &netlink.Veth{
		LinkAttrs:     netlink.LinkAttrs{Name: "vethstrip0"},
		PeerName:      "eth0",
		PeerNamespace: netlink.NsFd(int(strippedNS)),
	}
	if err := netlink.LinkAdd(sv); err != nil {
		t.Fatalf("LinkAdd stripped veth: %v", err)
	}
	sh, err := netlink.LinkByName("vethstrip0")
	if err != nil {
		t.Fatalf("LinkByName vethstrip0: %v", err)
	}
	shAddr, _ := netlink.ParseAddr("10.244.9.1/24")
	if err := netlink.AddrAdd(sh, shAddr); err != nil {
		t.Fatalf("AddrAdd vethstrip0: %v", err)
	}
	if err := netlink.LinkSetUp(sh); err != nil {
		t.Fatalf("LinkSetUp vethstrip0: %v", err)
	}
	// Note: eth0 inside strippedNS intentionally has zero IP addresses/routes (matching runsc AddrDel).
	strippedRoot := t.TempDir()
	strippedMgr := NewLinuxNetNSManagerWithHostTun(htMgr)
	strippedCloser, strippedGuestIP, err := strippedMgr.StartHostTun(HostTunRequest{
		PodUID:           "pod-l2-stripped",
		NetNSPath:        strippedNSPath,
		RuntimeHandler:   "runsc",
		PodIPs:           []string{"10.244.9.12"},
		PodRootDir:       strippedRoot,
		EgressSocketPath: podCfg.SocketPaths.EgressSocketPath,
	})
	if err != nil {
		t.Fatalf("StartHostTun(runsc stripped eth0): %v", err)
	}
	if strippedGuestIP != "10.244.9.12" {
		t.Fatalf("strippedGuestIP = %q, want 10.244.9.12", strippedGuestIP)
	}
	addrBytes, err := os.ReadFile(filepath.Join(strippedRoot, vethAddrsFile))
	if err != nil || !strings.Contains(string(addrBytes), "10.244.9.1/24") {
		t.Fatalf("persisted veth-addrs = %q (err=%v), want 10.244.9.1/24", string(addrBytes), err)
	}
	_ = strippedCloser.Close()
	if err := strippedMgr.CleanupHostTun(strippedNSPath, strippedRoot); err != nil {
		t.Fatalf("CleanupHostTun stripped: %v", err)
	}

	// 5. StopPodSandbox + RemovePodSandbox clean up persisted veth-netns.
	if err := drv.StopPodSandbox(ctx, nriPod); err != nil {
		t.Fatalf("StopPodSandbox: %v", err)
	}
	if err := drv.RemovePodSandbox(ctx, nriPod); err != nil {
		t.Fatalf("RemovePodSandbox: %v", err)
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
		},
		SocketPaths: store.SocketPaths{ResolvConfPath: "/run/dra-agents-net/pods/pod-missing-deny/resolv.conf"},
	})
	_ = st.Upsert(store.PodConfig{
		PodUID:       isoUID,
		PodName:      "sb-iso",
		PodNamespace: "agents",
		Parameters: params.NetworkParameters{
			ConfinementMode: apis.ConfinementModePodNetworkIsolated,
		},
		SocketPaths: store.SocketPaths{ResolvConfPath: "/run/dra-agents-net/pods/pod-missing-iso/resolv.conf"},
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
	for _, want := range []string{"non-loopback-routes-unflushed", "non-loopback-nics-unblocked", "host-tun-resolv-conf", "loopback-only-netns"} {
		if !strings.Contains(joined, want) {
			t.Errorf("events missing %q:\n%s", want, joined)
		}
	}

	// Flush routes AND install tc NIC drop filters on denyPod netns + supply the mount -> denyPod is clean.
	netnsMgr := NewLinuxNetNSManager()
	if err := netnsMgr.FlushNonLoopbackRoutes(podDenyNSPath); err != nil {
		t.Fatalf("FlushNonLoopbackRoutes: %v", err)
	}
	if err := netnsMgr.BlockNonLoopbackNICs(podDenyNSPath, true); err != nil {
		t.Fatalf("BlockNonLoopbackNICs: %v", err)
	}
	before = testutil.ToFloat64(metrics.PodsMissingPlumbingTotal)
	_, err = drv.Synchronize(ctx, []*nriapi.PodSandbox{denyPod}, []*nriapi.Container{
		{
			Id:           "c1",
			PodSandboxId: denyPod.Id,
			Name:         "agent",
			State:        nriapi.ContainerState_CONTAINER_RUNNING,
			Mounts:       []*nriapi.Mount{{Destination: containerResolvConfPath, Source: "/run/dra-agents-net/pods/pod-missing-deny/resolv.conf"}},
		},
	})
	if err != nil {
		t.Fatalf("Synchronize after flush+tc: %v", err)
	}
	if delta := testutil.ToFloat64(metrics.PodsMissingPlumbingTotal) - before; delta != 0 {
		t.Fatalf("healthy pod after flush+tc incremented PodsMissingPlumbingTotal by %v, want 0", delta)
	}
}

func TestIntegrationHostTunCrossNetNS(t *testing.T) {
	testutils.Run(t, testIntegrationHostTunCrossNetNS, syscall.CLONE_NEWNET, syscall.CLONE_NEWNS)
}

func testIntegrationHostTunCrossNetNS(t *testing.T) {
	ctx := t.Context()
	bringUpHostLoopback(t)
	podNSPath, _ := createNamedPodNetNS(t, "hosttun")

	destHTTP := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "hosttun-dest:"+r.URL.Path)
	}))
	defer destHTTP.Close()
	destHTTPAddr := strings.TrimPrefix(destHTTP.URL, "http://")
	_, destHTTPPort, _ := net.SplitHostPort(destHTTPAddr)

	udpEcho, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen host udp echo: %v", err)
	}
	defer func() { _ = udpEcho.Close() }()
	_, udpEchoPort, _ := net.SplitHostPort(udpEcho.LocalAddr().String())
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

	pki := newIntegrationPKI(t)
	srvPair := pki.issue(t, "127.0.0.1", true)
	cliCertPEM, cliKeyPEM, _ := pki.issuePEM(t, "dra-hosttun-client", false)
	certDir := t.TempDir()
	caPath := filepath.Join(certDir, "ca.crt")
	if err := os.WriteFile(caPath, pki.caPEM, 0o600); err != nil {
		t.Fatalf("write CA: %v", err)
	}
	if err := os.WriteFile(filepath.Join(certDir, "tls.crt"), cliCertPEM, 0o600); err != nil {
		t.Fatalf("write client cert: %v", err)
	}
	if err := os.WriteFile(filepath.Join(certDir, "tls.key"), cliKeyPEM, 0o600); err != nil {
		t.Fatalf("write client key: %v", err)
	}

	var (
		seenMu   sync.Mutex
		seenHost []string
	)
	rawUpLn, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen upstream: %v", err)
	}
	tlsUpLn := tls.NewListener(rawUpLn, &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{srvPair},
		ClientCAs:    pki.caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		NextProtos:   []string{"h2", "http/1.1"},
	})
	protos := new(http.Protocols)
	protos.SetHTTP1(true)
	protos.SetHTTP2(true)
	upSrv := &http.Server{
		Protocols: protos,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodConnect {
				seenMu.Lock()
				seenHost = append(seenHost, r.Host)
				seenMu.Unlock()
				if strings.HasPrefix(r.Host, "blocked.") {
					w.Header().Set("Proxy-Status", `test-pep; error=http_request_denied; reason=not-on-allowlist`)
					w.WriteHeader(http.StatusForbidden)
					return
				}
				dialTarget := r.Host
				if strings.HasPrefix(r.Host, "api.allowed.test:") {
					dialTarget = destHTTPAddr
				}
				dst, dialErr := net.DialTimeout("tcp4", dialTarget, 2*time.Second)
				if dialErr != nil {
					w.WriteHeader(http.StatusBadGateway)
					return
				}
				defer func() { _ = dst.Close() }()
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
				seenMu.Lock()
				seenHost = append(seenHost, "udp:"+host+":"+port)
				seenMu.Unlock()
				dialTarget := net.JoinHostPort(host, port)
				if host == "udp.allowed.test" {
					dialTarget = udpEcho.LocalAddr().String()
				}
				udpConn, dialErr := net.DialTimeout("udp4", dialTarget, 2*time.Second)
				if dialErr != nil {
					w.WriteHeader(http.StatusBadGateway)
					return
				}
				defer func() { _ = udpConn.Close() }()
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

	st, err := store.New(nil)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	tm, err := tunnel.NewManager(t.TempDir(), auth.NewResolver(auth.ResolverConfig{}), tunnel.WithAuditWriter(io.Discard))
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	defer tm.Close()
	htMgr := hosttun.NewManager(hosttun.ManagerConfig{Isolation: hosttun.IsolationShared})
	defer func() { _ = htMgr.Close() }()
	drv, err := New(Config{
		DriverName: apis.DriverName,
		NodeName:   "test-node",
		Store:      st,
		Tunnel:     tm,
		NetNS:      NewLinuxNetNSManagerWithHostTun(htMgr),
	})
	if err != nil {
		t.Fatalf("driver.New: %v", err)
	}
	drv.nriConnected.Store(true)
	defer drv.stopAllHostTuns(true)

	const podUID = types.UID("pod-hosttun-int-1")
	rawParams, err := json.Marshal(params.NetworkParameters{
		ConfinementMode: apis.ConfinementModePodNetworkIsolated,
		PolicyEnforcementPoint: &apis.PolicyEnforcementPointConfig{
			URL: "https://" + rawUpLn.Addr().String(),
			TLS: &apis.PEPTLS{
				ServerName: "127.0.0.1",
				CACertificateRefs: []apis.CASource{
					{Type: apis.CASourceTypeHostPath, HostPath: caPath},
				},
			},
			Auth: &apis.PEPAuth{
				Type: apis.PEPAuthTypeMTLS,
				MTLS: &apis.MTLSAuth{CertDir: certDir},
			},
		},
	})
	if err != nil {
		t.Fatalf("marshal params: %v", err)
	}
	claim := &resourceapi.ResourceClaim{
		ObjectMeta: metav1.ObjectMeta{Name: "claim-ht", Namespace: "agents", UID: "claim-ht-uid"},
		Status: resourceapi.ResourceClaimStatus{
			ReservedFor: []resourceapi.ResourceClaimConsumerReference{{Resource: "pods", Name: "sb-ht", UID: podUID}},
			Allocation: &resourceapi.AllocationResult{
				Devices: resourceapi.DeviceAllocationResult{
					Results: []resourceapi.DeviceRequestAllocationResult{
						{Request: apis.PodClaimName, Driver: apis.DriverName, Pool: "test-node", Device: DefaultDeviceName},
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
	prepRes, err := drv.PrepareResourceClaims(ctx, []*resourceapi.ResourceClaim{claim})
	if err != nil || prepRes[claim.UID].Err != nil {
		t.Fatalf("PrepareResourceClaims: err=%v res=%+v", err, prepRes[claim.UID])
	}
	pod := &nriapi.PodSandbox{
		Id: "sb-ht-1", Uid: string(podUID), Name: "sb-ht", Namespace: "agents",
		Linux: &nriapi.LinuxPodSandbox{Namespaces: []*nriapi.LinuxNamespace{{Type: "network", Path: podNSPath}}},
	}
	if err := drv.RunPodSandbox(ctx, pod); err != nil {
		t.Fatalf("RunPodSandbox: %v", err)
	}

	// Verify HostTun runs inside a separate hardened unprivileged worker process
	// and the parent driver no longer holds any open /dev/net/tun FD.
	workerPID := htMgr.WorkerPID(string(podUID))
	if workerPID <= 0 {
		t.Fatalf("expected active HostTun worker PID for %s, got %d", podUID, workerPID)
	}
	statusRaw, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", workerPID))
	if err != nil {
		t.Fatalf("read worker /proc/%d/status: %v", workerPID, err)
	}
	statusText := string(statusRaw)
	if !strings.Contains(statusText, "CapEff:\t0000000000000000") || !strings.Contains(statusText, "NoNewPrivs:\t1") {
		t.Fatalf("HostTun worker PID %d is not hardened:\n%s", workerPID, statusText)
	}
	parentNetNS, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatalf("readlink /proc/self/ns/net: %v", err)
	}
	workerNetNS, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/net", workerPID))
	if err != nil {
		t.Fatalf("readlink /proc/%d/ns/net: %v", workerPID, err)
	}
	if workerNetNS == parentNetNS {
		t.Fatalf("HostTun worker PID %d shares parent netns %s", workerPID, parentNetNS)
	}
	if fds, err := os.ReadDir("/proc/self/fd"); err == nil {
		for _, fdEntry := range fds {
			if target, err := os.Readlink(filepath.Join("/proc/self/fd", fdEntry.Name())); err == nil && strings.Contains(target, "/dev/net/tun") {
				t.Fatalf("parent driver still holds open TUN descriptor fd %s -> %s", fdEntry.Name(), target)
			}
		}
	}

	syntheticPool := netip.MustParsePrefix("198.18.0.0/15")
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(_ context.Context, _, _ string) (net.Conn, error) {
			return socketat.DialAtPath(podNSPath, "udp4", tun2connect.DefaultResolverAddr+":53", 3*time.Second)
		},
	}

	// 1. VirtualDNS returns synthetic IP in 198.18.0.0/15 and transparent HTTP succeeds with zero proxy env.
	ips, err := resolver.LookupNetIP(ctx, "ip4", "api.allowed.test")
	if err != nil || len(ips) != 1 || !syntheticPool.Contains(ips[0]) {
		t.Fatalf("LookupNetIP(api.allowed.test) = (%v, %v), want IP in 198.18.0.0/15", ips, err)
	}
	conn, err := socketat.DialAtPath(podNSPath, "tcp4", net.JoinHostPort(ips[0].String(), destHTTPPort), 5*time.Second)
	if err != nil {
		t.Fatalf("transparent TCP dial to api.allowed.test: %v", err)
	}
	_, _ = io.WriteString(conn, "GET /hosttun-ok HTTP/1.1\r\nHost: api.allowed.test\r\nConnection: close\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		_ = conn.Close()
		t.Fatalf("read HTTP response: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	_ = conn.Close()
	if string(body) != "hosttun-dest:/hosttun-ok" {
		t.Fatalf("HTTP body = %q, want hosttun-dest:/hosttun-ok", body)
	}

	// 2. Transparent UDP over connect-udp succeeds with an ordinary UDP socket.
	udpIPs, err := resolver.LookupNetIP(ctx, "ip4", "udp.allowed.test")
	if err != nil || len(udpIPs) != 1 {
		t.Fatalf("LookupNetIP(udp.allowed.test) = (%v, %v)", udpIPs, err)
	}
	uconn, err := socketat.DialAtPath(podNSPath, "udp4", net.JoinHostPort(udpIPs[0].String(), udpEchoPort), 5*time.Second)
	if err != nil {
		t.Fatalf("dial transparent UDP: %v", err)
	}
	_ = uconn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := uconn.Write([]byte("hello-hosttun")); err != nil {
		_ = uconn.Close()
		t.Fatalf("write UDP: %v", err)
	}
	ubuf := make([]byte, 128)
	n, err := uconn.Read(ubuf)
	_ = uconn.Close()
	if err != nil || string(ubuf[:n]) != "udp-echo:hello-hosttun" {
		t.Fatalf("UDP echo = (%q, %v), want udp-echo:hello-hosttun", ubuf[:n], err)
	}

	// 3. Denied host fails closed.
	blkIPs, err := resolver.LookupNetIP(ctx, "ip4", "blocked.example")
	if err != nil || len(blkIPs) != 1 {
		t.Fatalf("LookupNetIP(blocked.example) = (%v, %v)", blkIPs, err)
	}
	if c, err := socketat.DialAtPath(podNSPath, "tcp4", net.JoinHostPort(blkIPs[0].String(), "443"), 3*time.Second); err == nil {
		_ = c.Close()
		t.Fatal("blocked.example dial unexpectedly succeeded")
	}

	// 4. Unmapped synthetic IP in 198.18.0.0/15 fails closed locally without reaching PEP.
	if c, err := socketat.DialAtPath(podNSPath, "tcp4", "198.18.9.9:443", 3*time.Second); err == nil {
		_ = c.Close()
		t.Fatal("unmapped synthetic IP 198.18.9.9 unexpectedly succeeded")
	}

	seenMu.Lock()
	for _, h := range seenHost {
		if strings.Contains(h, "198.18.9.9") {
			seenMu.Unlock()
			t.Fatalf("unmapped synthetic IP leaked to PEP: %v", seenHost)
		}
	}
	seenMu.Unlock()

	// 4b. Kill the unprivileged worker abruptly and verify automatic recovery over persistent tun0.
	if err := syscall.Kill(workerPID, syscall.SIGKILL); err != nil {
		t.Fatalf("SIGKILL HostTun worker %d: %v", workerPID, err)
	}
	recoverDeadline := time.Now().Add(5 * time.Second)
	var recoveredPID int
	for time.Now().Before(recoverDeadline) {
		recoveredPID = htMgr.WorkerPID(string(podUID))
		if recoveredPID > 0 && recoveredPID != workerPID {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if recoveredPID <= 0 || recoveredPID == workerPID {
		t.Fatalf("HostTun worker did not recover after SIGKILL: old=%d new=%d", workerPID, recoveredPID)
	}
	recoveredIPs, err := resolver.LookupNetIP(ctx, "ip4", "api.allowed.test")
	if err != nil || len(recoveredIPs) != 1 {
		t.Fatalf("LookupNetIP after worker crash recovery = (%v, %v)", recoveredIPs, err)
	}
	recConn, err := socketat.DialAtPath(podNSPath, "tcp4", net.JoinHostPort(recoveredIPs[0].String(), destHTTPPort), 5*time.Second)
	if err != nil {
		t.Fatalf("TCP dial after worker crash recovery: %v", err)
	}
	_, _ = io.WriteString(recConn, "GET /after-worker-kill HTTP/1.1\r\nHost: api.allowed.test\r\nConnection: close\r\n\r\n")
	recResp, err := http.ReadResponse(bufio.NewReader(recConn), nil)
	if err != nil {
		_ = recConn.Close()
		t.Fatalf("read HTTP response after worker crash recovery: %v", err)
	}
	recBody, _ := io.ReadAll(recResp.Body)
	_ = recResp.Body.Close()
	_ = recConn.Close()
	if string(recBody) != "hosttun-dest:/after-worker-kill" {
		t.Fatalf("post-recovery HTTP body = %q, want hosttun-dest:/after-worker-kill", recBody)
	}

	// 5. Verify persistent tun0 survives DaemonSet shutdown (stopAllHostTuns(false))
	// and re-attaches cleanly on NRI Synchronize so new connections succeed without recreating the Pod.
	drv.stopAllHostTuns(false)
	cfgAfterStop, _ := st.Get(podUID)
	if _, err := drv.Synchronize(ctx, []*nriapi.PodSandbox{pod}, []*nriapi.Container{
		{
			Id:           "c-ht-1",
			PodSandboxId: pod.Id,
			Name:         "agent",
			State:        nriapi.ContainerState_CONTAINER_RUNNING,
			Mounts:       []*nriapi.Mount{{Destination: containerResolvConfPath, Source: cfgAfterStop.SocketPaths.ResolvConfPath}},
		},
	}); err != nil {
		t.Fatalf("Synchronize re-attach persistent tun0: %v", err)
	}
	reattachIPs, err := resolver.LookupNetIP(ctx, "ip4", "api.allowed.test")
	if err != nil || len(reattachIPs) != 1 {
		t.Fatalf("LookupNetIP after Synchronize re-attach = (%v, %v)", reattachIPs, err)
	}
	reattachConn, err := socketat.DialAtPath(podNSPath, "tcp4", net.JoinHostPort(reattachIPs[0].String(), destHTTPPort), 5*time.Second)
	if err != nil {
		t.Fatalf("TCP dial after Synchronize re-attach: %v", err)
	}
	_ = reattachConn.Close()
	if err := drv.StopPodSandbox(ctx, pod); err != nil {
		t.Fatalf("StopPodSandbox: %v", err)
	}
	if err := drv.RemovePodSandbox(ctx, pod); err != nil {
		t.Fatalf("RemovePodSandbox: %v", err)
	}

	// 6. Verify preserveNICReturn installs source-IP policy routing when nicBlockMode=Disabled.
	disabledNSPath, disabledNS := createNamedPodNetNS(t, "hosttun-disabled")
	veth := &netlink.Veth{
		LinkAttrs:     netlink.LinkAttrs{Name: "hostret0"},
		PeerName:      "eth0",
		PeerNamespace: netlink.NsFd(int(disabledNS)),
	}
	if err := netlink.LinkAdd(veth); err != nil {
		t.Fatalf("add veth pair: %v", err)
	}
	podHandle, err := netlink.NewHandleAt(disabledNS)
	if err != nil {
		t.Fatalf("pod netlink handle: %v", err)
	}
	defer podHandle.Close()
	eth0, err := podHandle.LinkByName("eth0")
	if err != nil {
		t.Fatalf("lookup eth0: %v", err)
	}
	ethAddr, _ := netlink.ParseAddr("10.244.0.42/24")
	if err := podHandle.AddrAdd(eth0, ethAddr); err != nil {
		t.Fatalf("add eth0 addr: %v", err)
	}
	if err := podHandle.LinkSetUp(eth0); err != nil {
		t.Fatalf("bring eth0 up: %v", err)
	}
	if err := podHandle.RouteAdd(&netlink.Route{
		LinkIndex: eth0.Attrs().Index,
		Gw:        net.ParseIP("10.244.0.1"),
	}); err != nil {
		t.Fatalf("add eth0 default route: %v", err)
	}

	cfg, _ := st.Get(podUID)
	mgr := NewLinuxNetNSManager()
	defer func() {
		if closer, ok := mgr.(io.Closer); ok {
			_ = closer.Close()
		}
	}()
	htCloser, _, err := mgr.StartHostTun(HostTunRequest{
		PodUID:            "pod-hosttun-disabled",
		NetNSPath:         disabledNSPath,
		EgressSocketPath:  cfg.SocketPaths.EgressSocketPath,
		MaxConnections:    64,
		PreserveNICReturn: true,
	})
	if err != nil {
		t.Fatalf("StartHostTun preserveNICReturn: %v", err)
	}
	defer func() {
		_ = htCloser.Close()
		_ = mgr.CleanupHostTun(disabledNSPath, "")
	}()

	// Verify table 100 holds eth0's default route and IP rule routes from 10.244.0.42/32 -> table 100.
	retRoutes, err := podHandle.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{Table: hostTunReturnTable}, netlink.RT_FILTER_TABLE)
	if err != nil {
		t.Fatalf("list table %d routes: %v", hostTunReturnTable, err)
	}
	hasEthDefault := false
	for _, r := range retRoutes {
		if r.LinkIndex == eth0.Attrs().Index && isDefaultRoute(r.Dst) && r.Gw.Equal(net.ParseIP("10.244.0.1")) {
			hasEthDefault = true
		}
	}
	if !hasEthDefault {
		t.Fatalf("expected eth0 default route via 10.244.0.1 in table %d, got %+v", hostTunReturnTable, retRoutes)
	}
	rules, err := podHandle.RuleList(netlink.FAMILY_V4)
	if err != nil {
		t.Fatalf("list v4 rules: %v", err)
	}
	wantSrc := &net.IPNet{IP: net.ParseIP("10.244.0.42").To4(), Mask: net.CIDRMask(32, 32)}
	if !hasPolicyRule(rules, wantSrc, hostTunReturnTable, hostTunReturnRulePriority) {
		t.Fatalf("missing source-IP return-path rule for 10.244.0.42/32 -> table %d: %+v", hostTunReturnTable, rules)
	}
}
