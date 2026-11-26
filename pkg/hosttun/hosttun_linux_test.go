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

package hosttun

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"

	"github.com/aojea/agents.net/internal/testutils"
	"github.com/aojea/agents.net/pkg/socketat"
	"github.com/aojea/agents.net/pkg/tun2connect"
)

const (
	externalBYOSArg       = "--external-byos-test-worker"
	serveSocketTestArg    = "--serve-socket-test-worker"
	seccompProbeHelperArg = "--seccomp-probe-test-worker"
)

func TestMain(m *testing.M) {
	if IsWorkerEnv() {
		if err := RunWorker(); err != nil {
			fmt.Fprintf(os.Stderr, "host-tun worker exited with error: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	if slices.Contains(os.Args[1:], externalBYOSArg) {
		if err := runExternalBYOSTestWorker(); err != nil {
			fmt.Fprintf(os.Stderr, "external BYOS test worker exited with error: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	if idx := slices.Index(os.Args[1:], serveSocketTestArg); idx >= 0 {
		sockPath := ""
		if idx+2 < len(os.Args) {
			sockPath = os.Args[idx+2]
		}
		if err := ServeSocket(context.Background(), sockPath); err != nil {
			fmt.Fprintf(os.Stderr, "serve-socket test worker exited with error: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	if slices.Contains(os.Args[1:], seccompProbeHelperArg) {
		if err := runSeccompProbeHelper(); err != nil {
			fmt.Fprintf(os.Stderr, "seccomp probe helper failed: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func runSeccompProbeHelper() error {
	if err := hardenWorkerProcess(); err != nil {
		return fmt.Errorf("hardenWorkerProcess: %w", err)
	}
	// AF_UNIX sockets and socketpairs MUST remain allowed.
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("expected AF_UNIX socket to succeed, got: %w", err)
	}
	_ = unix.Close(fd)
	sp, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("expected AF_UNIX socketpair to succeed, got: %w", err)
	}
	_ = unix.Close(sp[0])
	_ = unix.Close(sp[1])

	// Non-AF_UNIX address families MUST fail with EPERM.
	blocked := []struct {
		name   string
		domain int
		typ    int
	}{
		{"AF_INET", unix.AF_INET, unix.SOCK_STREAM},
		{"AF_INET6", unix.AF_INET6, unix.SOCK_STREAM},
		{"AF_NETLINK", unix.AF_NETLINK, unix.SOCK_RAW},
		{"AF_PACKET", unix.AF_PACKET, unix.SOCK_RAW},
	}
	for _, tc := range blocked {
		sfd, err := unix.Socket(tc.domain, tc.typ|unix.SOCK_CLOEXEC, 0)
		if err == nil {
			_ = unix.Close(sfd)
			return fmt.Errorf("socket(%s) unexpectedly succeeded under seccomp filter", tc.name)
		}
		if !errors.Is(err, unix.EPERM) {
			return fmt.Errorf("socket(%s) err = %v, want EPERM", tc.name, err)
		}
	}
	return nil
}

// runExternalBYOSTestWorker implements a minimal external worker binary speaking
// the AGENTS_NET_CTRL_FD JSON+SCM_RIGHTS protocol. It asserts that Manager
// stripped ambient parent environment variables before execve, hardens itself,
// and handles add/remove with a custom stack identifier.
func runExternalBYOSTestWorker() error {
	if os.Getenv("AGENTS_NET_TEST_SECRET_ENV") != "" {
		return errors.New("parent environment leaked into external BYOS worker")
	}
	if os.Getenv(EnvWorkerMode) != "" {
		return errors.New("EnvWorkerMode unexpectedly set for external BYOS worker")
	}
	if err := hardenWorkerProcess(); err != nil {
		return err
	}
	ctrlFD, err := strconv.Atoi(os.Getenv(EnvCtrlFD))
	if err != nil || ctrlFD < 3 {
		return fmt.Errorf("unexpected %s=%q", EnvCtrlFD, os.Getenv(EnvCtrlFD))
	}
	if err := unix.SetNonblock(ctrlFD, true); err != nil {
		return err
	}
	ctrlFile := os.NewFile(uintptr(ctrlFD), "byos-ctrl")
	defer func() { _ = ctrlFile.Close() }()

	w := &builtinWorker{pods: make(map[string]*workerPod)}
	defer w.closeAll()

	for {
		payload, fds, err := recvMsgWithFDs(ctrlFile, maxControlMsgBytes, 4)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, os.ErrClosed) {
				return nil
			}
			return err
		}
		resp := w.handleRequest(payload, fds)
		if resp.OK {
			resp.Stack = "custom-byos-test"
		}
		raw, err := json.Marshal(resp)
		if err != nil {
			return err
		}
		if err := sendMsgWithFDs(ctrlFile, raw); err != nil {
			return err
		}
	}
}

func TestIDMappedInProc(t *testing.T) {
	dir := t.TempDir()
	single := filepath.Join(dir, "single")
	full := filepath.Join(dir, "full")
	offset := filepath.Join(dir, "offset")
	bad := filepath.Join(dir, "bad")

	_ = os.WriteFile(single, []byte("         0       1000          1\n"), 0o600)
	_ = os.WriteFile(full, []byte("         0          0 4294967295\n"), 0o600)
	_ = os.WriteFile(offset, []byte("     65534     165534          1\n"), 0o600)
	_ = os.WriteFile(bad, []byte("not valid\n0 0 nope\n"), 0o600)

	if idMappedInProc(single, DefaultWorkerUID) {
		t.Error("single-UID map unexpectedly reported 65534 mapped")
	}
	if !idMappedInProc(single, 0) {
		t.Error("single-UID map failed to report UID 0 mapped")
	}
	if !idMappedInProc(full, DefaultWorkerUID) {
		t.Error("full map failed to report 65534 mapped")
	}
	if !idMappedInProc(offset, DefaultWorkerUID) {
		t.Error("offset map failed to report 65534 mapped")
	}
	if idMappedInProc(offset, DefaultWorkerUID+1) {
		t.Error("offset map unexpectedly reported 65535 mapped")
	}
	if idMappedInProc(bad, DefaultWorkerUID) {
		t.Error("malformed map unexpectedly reported 65534 mapped")
	}
	if idMappedInProc(filepath.Join(dir, "missing"), DefaultWorkerUID) {
		t.Error("missing file unexpectedly reported 65534 mapped")
	}
}

func TestAttachValidation(t *testing.T) {
	mgr := NewManager(ManagerConfig{Isolation: IsolationShared})
	defer func() { _ = mgr.Close() }()

	if _, err := mgr.Attach(AttachConfig{TunFD: -1}); err == nil {
		t.Fatal("Attach with empty PodID unexpectedly succeeded")
	}
	if _, err := mgr.Attach(AttachConfig{PodID: "p1", TunFD: -1, EgressSocketPath: "/tmp/x"}); err == nil {
		t.Fatal("Attach with invalid TunFD unexpectedly succeeded")
	}

	// Pass a valid pipe FD so Attach closes it on validation error.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	defer func() { _ = w.Close() }()
	dupFD, err := unix.FcntlInt(r.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("F_DUPFD_CLOEXEC: %v", err)
	}
	_ = r.Close()

	if _, err := mgr.Attach(AttachConfig{PodID: "p1", TunFD: dupFD}); err == nil {
		t.Fatal("Attach without ServeEgress or EgressSocketPath unexpectedly succeeded")
	}
	if err := unix.Close(dupFD); !errors.Is(err, unix.EBADF) {
		t.Errorf("expected Attach validation failure to close TunFD, got close err=%v", err)
	}

	if err := mgr.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := mgr.Attach(AttachConfig{PodID: "p2", TunFD: 0, EgressSocketPath: "/tmp/x"}); err == nil {
		t.Fatal("Attach on closed manager unexpectedly succeeded")
	}
}

func createNamedPodNetNS(t *testing.T, prefix string) string {
	t.Helper()
	var rnd [4]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	name := fmt.Sprintf("%s-%x", prefix, rnd)

	runtime.LockOSThread()
	orig, err := netns.Get()
	if err != nil {
		runtime.UnlockOSThread()
		t.Fatalf("netns.Get: %v", err)
	}
	ns, createErr := netns.NewNamed(name)
	restoreErr := netns.Set(orig)
	_ = orig.Close()
	runtime.UnlockOSThread()
	if restoreErr != nil {
		t.Fatalf("restore netns: %v", restoreErr)
	}
	if createErr != nil {
		t.Fatalf("create named netns %s: %v", name, createErr)
	}
	t.Cleanup(func() {
		_ = ns.Close()
		_ = netns.DeleteNamed(name)
	})
	return filepath.Join("/run/netns", name)
}

func openPersistentTunInNS(netnsPath string) (int, error) {
	tunFD := -1
	err := socketat.DoAtNSPath(netnsPath, func() error {
		fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
		if err != nil {
			return fmt.Errorf("open /dev/net/tun: %w", err)
		}
		cleanup := true
		defer func() {
			if cleanup {
				_ = unix.Close(fd)
			}
		}()

		ifr, err := unix.NewIfreq("tun0")
		if err != nil {
			return err
		}
		ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
		if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
			return fmt.Errorf("TUNSETIFF: %w", err)
		}
		if err := unix.IoctlSetInt(fd, unix.TUNSETPERSIST, 1); err != nil {
			return fmt.Errorf("TUNSETPERSIST: %w", err)
		}
		if err := unix.SetNonblock(fd, true); err != nil {
			return err
		}

		handle, err := netlink.NewHandle()
		if err != nil {
			return err
		}
		defer handle.Close()

		if lo, err := handle.LinkByName("lo"); err == nil {
			if err := handle.LinkSetUp(lo); err != nil {
				return err
			}
		}
		link, err := handle.LinkByName("tun0")
		if err != nil {
			return err
		}
		if err := handle.LinkSetMTU(link, 1500); err != nil {
			return err
		}
		v4Addr, err := netlink.ParseAddr(fmt.Sprintf("%s/%d", tun2connect.DefaultGuestAddr4, tun2connect.DefaultPool4Bits))
		if err != nil {
			return err
		}
		if err := handle.AddrReplace(link, v4Addr); err != nil {
			return err
		}
		if err := handle.LinkSetUp(link); err != nil {
			return err
		}
		v4Default := &netlink.Route{
			LinkIndex: link.Attrs().Index,
			Scope:     netlink.SCOPE_LINK,
			Dst:       &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
		}
		if err := handle.RouteReplace(v4Default); err != nil {
			return err
		}
		cleanup = false
		tunFD = fd
		return nil
	})
	if err != nil {
		return -1, err
	}
	return tunFD, nil
}

// serveMockCONNECT handles a parent-brokered HTTP/1.1 CONNECT stream directly
// in memory (no Unix socket file on disk) and responds with an HTTP 200 payload
// echoing label + CONNECT authority + inner HTTP path.
func serveMockCONNECT(label string) func(net.Conn) error {
	return func(conn net.Conn) error {
		go func() {
			defer func() { _ = conn.Close() }()
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			br := bufio.NewReader(conn)
			req, err := http.ReadRequest(br)
			if err != nil || req.Method != http.MethodConnect {
				return
			}
			target := req.Host
			_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
			innerReq, err := http.ReadRequest(br)
			if err != nil {
				return
			}
			body := fmt.Sprintf("%s:%s:%s", label, target, innerReq.URL.Path)
			_, _ = fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
		}()
		return nil
	}
}

func probePodHTTP(t *testing.T, podNSPath, host, path string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(_ context.Context, _, _ string) (net.Conn, error) {
			return socketat.DialAtPath(podNSPath, "udp4", tun2connect.DefaultResolverAddr+":53", 3*time.Second)
		},
	}
	ips, err := resolver.LookupNetIP(ctx, "ip4", host)
	if err != nil || len(ips) != 1 {
		t.Fatalf("LookupNetIP(%s) = (%v, %v)", host, ips, err)
	}
	syntheticPool := netip.MustParsePrefix("198.18.0.0/15")
	if !syntheticPool.Contains(ips[0]) {
		t.Fatalf("resolved IP %s not in 198.18.0.0/15", ips[0])
	}

	conn, err := socketat.DialAtPath(podNSPath, "tcp4", net.JoinHostPort(ips[0].String(), "8080"), 5*time.Second)
	if err != nil {
		t.Fatalf("dial %s (%s): %v", host, ips[0], err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, host)
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("http.ReadResponse(%s): %v", host, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(raw)
}

func assertWorkerHardened(t *testing.T, workerPID int) string {
	t.Helper()
	if workerPID <= 0 {
		t.Fatalf("expected positive worker PID, got %d", workerPID)
	}
	statusBytes, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", workerPID))
	if err != nil {
		t.Fatalf("read /proc/%d/status: %v", workerPID, err)
	}
	fields := make(map[string]string)
	for line := range strings.SplitSeq(string(statusBytes), "\n") {
		k, v, ok := strings.Cut(line, ":")
		if ok {
			fields[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	for _, capKey := range []string{"CapInh", "CapPrm", "CapEff", "CapAmb"} {
		if got := fields[capKey]; got != "0000000000000000" {
			t.Errorf("worker PID %d %s = %q, want 0000000000000000", workerPID, capKey, got)
		}
	}
	if got := fields["NoNewPrivs"]; got != "1" {
		t.Errorf("worker PID %d NoNewPrivs = %q, want 1", workerPID, got)
	}
	if runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64" {
		if got := fields["Seccomp"]; got != "2" {
			t.Errorf("worker PID %d Seccomp = %q, want 2 (filter mode)", workerPID, got)
		}
	}

	parentNS, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatalf("readlink /proc/self/ns/net: %v", err)
	}
	workerNS, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/net", workerPID))
	if err != nil {
		t.Fatalf("readlink /proc/%d/ns/net: %v", workerPID, err)
	}
	if workerNS == parentNS {
		t.Errorf("worker PID %d shares parent network namespace %s", workerPID, parentNS)
	}
	return workerNS
}

func assertParentHoldsNoTunFD(t *testing.T) {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatalf("ReadDir /proc/self/fd: %v", err)
	}
	for _, e := range entries {
		target, err := os.Readlink(filepath.Join("/proc/self/fd", e.Name()))
		if err != nil {
			continue
		}
		if strings.Contains(target, "/dev/net/tun") {
			t.Fatalf("parent process still holds open TUN descriptor fd %s -> %s", e.Name(), target)
		}
	}
}

func TestWorkerPrivilegeSeparationSharedMode(t *testing.T) {
	testutils.Run(t, func(t *testing.T) {
		ns1 := createNamedPodNetNS(t, "ht-shared-1")
		ns2 := createNamedPodNetNS(t, "ht-shared-2")

		mgr := NewManager(ManagerConfig{Isolation: IsolationShared})
		defer func() { _ = mgr.Close() }()

		fd1, err := openPersistentTunInNS(ns1)
		if err != nil {
			t.Fatalf("openPersistentTunInNS(ns1): %v", err)
		}
		c1, err := mgr.Attach(AttachConfig{
			PodID:       "pod-shared-1",
			TunFD:       fd1,
			MTU:         1500,
			ServeEgress: serveMockCONNECT("pod1"),
			ReopenTun:   func() (int, error) { return openPersistentTunInNS(ns1) },
		})
		if err != nil {
			t.Fatalf("Attach pod-shared-1: %v", err)
		}
		defer func() { _ = c1.Close() }()

		fd2, err := openPersistentTunInNS(ns2)
		if err != nil {
			t.Fatalf("openPersistentTunInNS(ns2): %v", err)
		}
		c2, err := mgr.Attach(AttachConfig{
			PodID:       "pod-shared-2",
			TunFD:       fd2,
			MTU:         1500,
			ServeEgress: serveMockCONNECT("pod2"),
			ReopenTun:   func() (int, error) { return openPersistentTunInNS(ns2) },
		})
		if err != nil {
			t.Fatalf("Attach pod-shared-2: %v", err)
		}
		defer func() { _ = c2.Close() }()

		pid1 := mgr.WorkerPID("pod-shared-1")
		pid2 := mgr.WorkerPID("pod-shared-2")
		if pid1 <= 0 || pid1 != pid2 {
			t.Fatalf("shared mode expected identical worker PIDs, got pid1=%d pid2=%d", pid1, pid2)
		}
		assertWorkerHardened(t, pid1)
		assertParentHoldsNoTunFD(t)

		if got := probePodHTTP(t, ns1, "alpha.example", "/p1"); got != "pod1:alpha.example:8080:/p1" {
			t.Fatalf("pod1 response = %q, want pod1:alpha.example:8080:/p1", got)
		}
		if got := probePodHTTP(t, ns2, "beta.example", "/p2"); got != "pod2:beta.example:8080:/p2" {
			t.Fatalf("pod2 response = %q, want pod2:beta.example:8080:/p2", got)
		}

		// Simulate an abrupt worker crash and verify both Pods recover automatically
		// onto a fresh shared worker PID without recreating either Pod netns.
		if err := syscall.Kill(pid1, syscall.SIGKILL); err != nil {
			t.Fatalf("SIGKILL worker %d: %v", pid1, err)
		}
		deadline := time.Now().Add(5 * time.Second)
		var recovered1, recovered2 int
		for time.Now().Before(deadline) {
			recovered1 = mgr.WorkerPID("pod-shared-1")
			recovered2 = mgr.WorkerPID("pod-shared-2")
			if recovered1 > 0 && recovered1 != pid1 && recovered1 == recovered2 {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		if recovered1 <= 0 || recovered1 == pid1 || recovered1 != recovered2 {
			t.Fatalf("worker did not recover both Pods cleanly: old=%d new1=%d new2=%d", pid1, recovered1, recovered2)
		}
		assertWorkerHardened(t, recovered1)
		assertParentHoldsNoTunFD(t)

		if got := probePodHTTP(t, ns1, "alpha.example", "/recovered-1"); got != "pod1:alpha.example:8080:/recovered-1" {
			t.Fatalf("pod1 post-recovery response = %q", got)
		}
		if got := probePodHTTP(t, ns2, "beta.example", "/recovered-2"); got != "pod2:beta.example:8080:/recovered-2" {
			t.Fatalf("pod2 post-recovery response = %q", got)
		}
	}, syscall.CLONE_NEWNET, syscall.CLONE_NEWNS)
}

func TestWorkerPrivilegeSeparationPerPodMode(t *testing.T) {
	testutils.Run(t, func(t *testing.T) {
		ns1 := createNamedPodNetNS(t, "ht-perpod-1")
		ns2 := createNamedPodNetNS(t, "ht-perpod-2")

		mgr := NewManager(ManagerConfig{Isolation: IsolationPerPod})
		defer func() { _ = mgr.Close() }()

		fd1, err := openPersistentTunInNS(ns1)
		if err != nil {
			t.Fatalf("openPersistentTunInNS(ns1): %v", err)
		}
		c1, err := mgr.Attach(AttachConfig{
			PodID:       "pod-iso-1",
			TunFD:       fd1,
			MTU:         1500,
			ServeEgress: serveMockCONNECT("iso1"),
			ReopenTun:   func() (int, error) { return openPersistentTunInNS(ns1) },
		})
		if err != nil {
			t.Fatalf("Attach pod-iso-1: %v", err)
		}

		fd2, err := openPersistentTunInNS(ns2)
		if err != nil {
			t.Fatalf("openPersistentTunInNS(ns2): %v", err)
		}
		c2, err := mgr.Attach(AttachConfig{
			PodID:       "pod-iso-2",
			TunFD:       fd2,
			MTU:         1500,
			ServeEgress: serveMockCONNECT("iso2"),
			ReopenTun:   func() (int, error) { return openPersistentTunInNS(ns2) },
		})
		if err != nil {
			t.Fatalf("Attach pod-iso-2: %v", err)
		}
		defer func() { _ = c2.Close() }()

		pid1 := mgr.WorkerPID("pod-iso-1")
		pid2 := mgr.WorkerPID("pod-iso-2")
		if pid1 <= 0 || pid2 <= 0 || pid1 == pid2 {
			t.Fatalf("per-pod mode expected distinct worker PIDs, got pid1=%d pid2=%d", pid1, pid2)
		}
		netns1 := assertWorkerHardened(t, pid1)
		netns2 := assertWorkerHardened(t, pid2)
		if netns1 == netns2 {
			t.Fatalf("per-pod workers unexpectedly share netns %s", netns1)
		}
		assertParentHoldsNoTunFD(t)

		if got := probePodHTTP(t, ns1, "one.example", "/a"); got != "iso1:one.example:8080:/a" {
			t.Fatalf("pod-iso-1 response = %q", got)
		}
		if got := probePodHTTP(t, ns2, "two.example", "/b"); got != "iso2:two.example:8080:/b" {
			t.Fatalf("pod-iso-2 response = %q", got)
		}

		// Detaching Pod 1 must terminate only Worker 1; Pod 2's worker must stay untouched.
		if err := c1.Close(); err != nil {
			t.Fatalf("close pod-iso-1: %v", err)
		}
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			if err := syscall.Kill(pid1, 0); errors.Is(err, syscall.ESRCH) {
				break
			}
			time.Sleep(25 * time.Millisecond)
		}
		if err := syscall.Kill(pid1, 0); !errors.Is(err, syscall.ESRCH) {
			t.Fatalf("per-pod worker %d still alive after detach (err=%v)", pid1, err)
		}
		if mgr.WorkerPID("pod-iso-2") != pid2 {
			t.Fatalf("pod-iso-2 worker PID changed unexpectedly: got %d want %d", mgr.WorkerPID("pod-iso-2"), pid2)
		}
		if got := probePodHTTP(t, ns2, "two.example", "/still-up"); got != "iso2:two.example:8080:/still-up" {
			t.Fatalf("pod-iso-2 response after pod-iso-1 detach = %q", got)
		}
	}, syscall.CLONE_NEWNET, syscall.CLONE_NEWNS)
}

func TestExternalBYOSWorkerBin(t *testing.T) {
	testutils.Run(t, func(t *testing.T) {
		t.Setenv("AGENTS_NET_TEST_SECRET_ENV", "must-not-leak")
		exe, err := os.Executable()
		if err != nil {
			t.Fatalf("os.Executable: %v", err)
		}

		ns := createNamedPodNetNS(t, "ht-byos")
		mgr := NewManager(ManagerConfig{
			Isolation:  IsolationShared,
			WorkerBin:  exe,
			WorkerArgs: []string{externalBYOSArg},
		})
		defer func() { _ = mgr.Close() }()

		fd, err := openPersistentTunInNS(ns)
		if err != nil {
			t.Fatalf("openPersistentTunInNS: %v", err)
		}
		closer, err := mgr.Attach(AttachConfig{
			PodID:       "pod-byos-1",
			TunFD:       fd,
			MTU:         1500,
			ServeEgress: serveMockCONNECT("byos"),
		})
		if err != nil {
			t.Fatalf("Attach external BYOS worker: %v", err)
		}
		defer func() { _ = closer.Close() }()

		assertWorkerHardened(t, mgr.WorkerPID("pod-byos-1"))
		assertParentHoldsNoTunFD(t)

		if got := probePodHTTP(t, ns, "custom.stack.example", "/byos-ok"); got != "byos:custom.stack.example:8080:/byos-ok" {
			t.Fatalf("external BYOS worker response = %q, want byos:custom.stack.example:8080:/byos-ok", got)
		}
	}, syscall.CLONE_NEWNET, syscall.CLONE_NEWNS)
}

func TestSeccompBlocksNonUnixSockets(t *testing.T) {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		t.Skipf("seccomp BPF filter not configured for %s", runtime.GOARCH)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	cmd := exec.Command(exe, seccompProbeHelperArg)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("seccomp probe helper failed: %v\n%s", err, out)
	}
}

func TestWorkerSocketTwoContainerReconnect(t *testing.T) {
	testutils.Run(t, func(t *testing.T) {
		exe, err := os.Executable()
		if err != nil {
			t.Fatalf("os.Executable: %v", err)
		}
		sockPath := filepath.Join(t.TempDir(), "worker.sock")

		startStackServer := func() *exec.Cmd {
			cmd := exec.Command(exe, serveSocketTestArg, sockPath)
			cmd.Stdout = os.Stderr
			cmd.Stderr = os.Stderr
			if err := cmd.Start(); err != nil {
				t.Fatalf("start ServeSocket subprocess: %v", err)
			}
			return cmd
		}

		// Start companion stack process #1 (simulating Container 2 agents-net-stack).
		srv1 := startStackServer()
		defer func() {
			if srv1.Process != nil {
				_ = srv1.Process.Kill()
				_ = srv1.Wait()
			}
		}()

		ns1 := createNamedPodNetNS(t, "ht-sock-1")
		ns2 := createNamedPodNetNS(t, "ht-sock-2")

		mgr := NewManager(ManagerConfig{WorkerSocket: sockPath})
		defer func() { _ = mgr.Close() }()

		fd1, err := openPersistentTunInNS(ns1)
		if err != nil {
			t.Fatalf("openPersistentTunInNS(ns1): %v", err)
		}
		c1, err := mgr.Attach(AttachConfig{
			PodID:       "pod-sock-1",
			TunFD:       fd1,
			MTU:         1500,
			ServeEgress: serveMockCONNECT("sock1"),
			ReopenTun:   func() (int, error) { return openPersistentTunInNS(ns1) },
		})
		if err != nil {
			t.Fatalf("Attach pod-sock-1: %v", err)
		}
		defer func() { _ = c1.Close() }()

		fd2, err := openPersistentTunInNS(ns2)
		if err != nil {
			t.Fatalf("openPersistentTunInNS(ns2): %v", err)
		}
		c2, err := mgr.Attach(AttachConfig{
			PodID:       "pod-sock-2",
			TunFD:       fd2,
			MTU:         1500,
			ServeEgress: serveMockCONNECT("sock2"),
			ReopenTun:   func() (int, error) { return openPersistentTunInNS(ns2) },
		})
		if err != nil {
			t.Fatalf("Attach pod-sock-2: %v", err)
		}
		defer func() { _ = c2.Close() }()

		pid1 := mgr.WorkerPID("pod-sock-1")
		if pid1 != srv1.Process.Pid || mgr.WorkerPID("pod-sock-2") != pid1 {
			t.Fatalf("SO_PEERCRED worker PID mismatch: pod1=%d pod2=%d server=%d", pid1, mgr.WorkerPID("pod-sock-2"), srv1.Process.Pid)
		}
		assertParentHoldsNoTunFD(t)

		// Verify companion stack process has zero caps, NoNewPrivs=1, and Seccomp=2.
		statusRaw, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid1))
		if err != nil {
			t.Fatalf("read /proc/%d/status: %v", pid1, err)
		}
		statusText := string(statusRaw)
		if !strings.Contains(statusText, "CapEff:\t0000000000000000") ||
			!strings.Contains(statusText, "NoNewPrivs:\t1") ||
			((runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64") && !strings.Contains(statusText, "Seccomp:\t2")) {
			t.Fatalf("companion stack process PID %d not hardened:\n%s", pid1, statusText)
		}

		if got := probePodHTTP(t, ns1, "svc1.example", "/initial"); got != "sock1:svc1.example:8080:/initial" {
			t.Fatalf("pod-sock-1 initial response = %q", got)
		}
		if got := probePodHTTP(t, ns2, "svc2.example", "/initial"); got != "sock2:svc2.example:8080:/initial" {
			t.Fatalf("pod-sock-2 initial response = %q", got)
		}

		// Simulate abrupt Container 2 crash (SIGKILL), then restart a fresh server
		// at the same socket path after a short delay (simulating kubelet restart).
		if err := srv1.Process.Kill(); err != nil {
			t.Fatalf("SIGKILL stack server 1: %v", err)
		}
		_ = srv1.Wait()
		time.Sleep(150 * time.Millisecond)

		srv2 := startStackServer()
		defer func() {
			if srv2.Process != nil {
				_ = srv2.Process.Kill()
				_ = srv2.Wait()
			}
		}()

		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if mgr.WorkerPID("pod-sock-1") == srv2.Process.Pid && mgr.WorkerPID("pod-sock-2") == srv2.Process.Pid {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		if mgr.WorkerPID("pod-sock-1") != srv2.Process.Pid || mgr.WorkerPID("pod-sock-2") != srv2.Process.Pid {
			t.Fatalf("Manager did not reconnect both Pods to restarted stack server: got (%d, %d) want %d",
				mgr.WorkerPID("pod-sock-1"), mgr.WorkerPID("pod-sock-2"), srv2.Process.Pid)
		}
		assertParentHoldsNoTunFD(t)

		if got := probePodHTTP(t, ns1, "svc1.example", "/reconnected"); got != "sock1:svc1.example:8080:/reconnected" {
			t.Fatalf("pod-sock-1 post-reconnect response = %q", got)
		}
		if got := probePodHTTP(t, ns2, "svc2.example", "/reconnected"); got != "sock2:svc2.example:8080:/reconnected" {
			t.Fatalf("pod-sock-2 post-reconnect response = %q", got)
		}
	}, syscall.CLONE_NEWNET, syscall.CLONE_NEWNS)
}
