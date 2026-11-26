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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"k8s.io/klog/v2"

	"github.com/aojea/agents.net/pkg/tun2connect"
)

const builtinStackName = "gvisor-netstack"

// IsWorkerEnv reports whether the current process was self-reexec'd as a
// HostTun userspace stack worker (used in TestMain and dra-agents-net main).
func IsWorkerEnv() bool {
	return os.Getenv(EnvWorkerMode) == "1"
}

// RunWorker executes the built-in unprivileged HostTun userspace stack worker
// serving ControlRequests on the inherited SOCK_SEQPACKET control descriptor.
func RunWorker() error {
	if err := hardenWorkerProcess(); err != nil {
		return fmt.Errorf("harden host-tun worker: %w", err)
	}

	ctrlFD := DefaultCtrlFD
	if raw := os.Getenv(EnvCtrlFD); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 3 {
			return fmt.Errorf("invalid %s=%q", EnvCtrlFD, raw)
		}
		ctrlFD = parsed
	}
	if err := unix.SetNonblock(ctrlFD, true); err != nil {
		return fmt.Errorf("set control fd %d non-blocking: %w", ctrlFD, err)
	}
	ctrlFile := os.NewFile(uintptr(ctrlFD), "hosttun-ctrl")
	defer func() { _ = ctrlFile.Close() }()

	return serveControlFile(ctrlFile)
}

// ServeSocket hardens the process (zero capabilities, NoNewPrivs, and an
// AF_UNIX-only socket seccomp filter across all threads), listens on an AF_UNIX
// SOCK_SEQPACKET socket at socketPath, and serves HostTun control connections
// until ctx is cancelled.
//
// This entrypoint powers the unprivileged Container 2 (cmd/agents-net-stack) in
// the two-container DaemonSet deployment.
func ServeSocket(ctx context.Context, socketPath string) error {
	if socketPath == "" {
		return errors.New("socket path is required")
	}
	if err := hardenWorkerProcess(); err != nil {
		return fmt.Errorf("harden host-tun stack server: %w", err)
	}

	if dir := filepath.Dir(socketPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create socket dir %q: %w", dir, err)
		}
	}
	if err := os.Remove(socketPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove stale socket %q: %w", socketPath, err)
	}

	lnFD, err := unix.Socket(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("socket(AF_UNIX, SOCK_SEQPACKET): %w", err)
	}
	cleanupSocket := true
	defer func() {
		if cleanupSocket {
			_ = unix.Close(lnFD)
		}
	}()

	if err := unix.Bind(lnFD, &unix.SockaddrUnix{Name: socketPath}); err != nil {
		return fmt.Errorf("bind %q: %w", socketPath, err)
	}
	if err := os.Chmod(socketPath, 0o600); err != nil {
		return fmt.Errorf("chmod %q: %w", socketPath, err)
	}
	if err := unix.Listen(lnFD, 16); err != nil {
		return fmt.Errorf("listen %q: %w", socketPath, err)
	}

	lnFile := os.NewFile(uintptr(lnFD), "hosttun-listen")
	cleanupSocket = false
	defer func() {
		_ = lnFile.Close()
		_ = os.Remove(socketPath)
	}()

	var (
		activeMu    sync.Mutex
		activeConns = make(map[*os.File]struct{})
		connWG      sync.WaitGroup
	)
	stopWatcher := context.AfterFunc(ctx, func() {
		_ = lnFile.Close()
		activeMu.Lock()
		for f := range activeConns {
			_ = f.Close()
		}
		activeMu.Unlock()
	})
	defer stopWatcher()

	klog.InfoS("host-tun userspace stack listening", "socket", socketPath, "stack", builtinStackName)

	for {
		connFD, err := acceptSeqPacket(lnFile)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, os.ErrClosed) || errors.Is(err, net.ErrClosed) {
				connWG.Wait()
				return nil
			}
			connWG.Wait()
			return fmt.Errorf("accept on %q: %w", socketPath, err)
		}
		connFile := os.NewFile(uintptr(connFD), "hosttun-ctrl-conn")
		activeMu.Lock()
		if ctx.Err() != nil {
			activeMu.Unlock()
			_ = connFile.Close()
			continue
		}
		activeConns[connFile] = struct{}{}
		activeMu.Unlock()

		connWG.Add(1)
		go func(f *os.File) {
			defer connWG.Done()
			defer func() {
				activeMu.Lock()
				delete(activeConns, f)
				activeMu.Unlock()
				_ = f.Close()
			}()
			if err := serveControlFile(f); err != nil && ctx.Err() == nil {
				klog.ErrorS(err, "host-tun control connection closed with error", "socket", socketPath)
			}
		}(connFile)
	}
}

func acceptSeqPacket(lnFile *os.File) (int, error) {
	raw, err := lnFile.SyscallConn()
	if err != nil {
		return -1, err
	}
	var (
		nfd       int
		acceptErr error
	)
	ctrlErr := raw.Read(func(fd uintptr) bool {
		var err error
		nfd, _, err = unix.Accept4(int(fd), unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC)
		if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) {
			return false
		}
		acceptErr = err
		return true
	})
	if ctrlErr != nil {
		return -1, ctrlErr
	}
	if acceptErr != nil {
		return -1, acceptErr
	}
	return nfd, nil
}

func serveControlFile(ctrlFile *os.File) error {
	w := &builtinWorker{
		pods: make(map[string]*workerPod),
	}
	defer w.closeAll()

	for {
		payload, fds, err := recvMsgWithFDs(ctrlFile, maxControlMsgBytes, 4)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, os.ErrClosed) || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("read control request: %w", err)
		}
		resp := w.handleRequest(payload, fds)
		rawResp, err := json.Marshal(resp)
		if err != nil {
			return fmt.Errorf("marshal control response: %w", err)
		}
		if err := sendMsgWithFDs(ctrlFile, rawResp); err != nil {
			return fmt.Errorf("write control response: %w", err)
		}
	}
}

// hardenWorkerProcess ensures the worker process holds zero Linux capabilities,
// disables ptrace/core dumps, and irreversibly sets PR_SET_NO_NEW_PRIVS so the
// worker can never regain privileges.
//
// In CGO_ENABLED=0 builds (such as the production distroless image),
// syscall.AllThreadsSyscall6 applies per-thread capability and no_new_privs
// restrictions atomically across every OS thread. In CGO_ENABLED=1 builds (such
// as `go test -race`), AllThreadsSyscall6 returns EOPNOTSUPP and we fall back
// to the calling OS thread (in production containers SysProcAttr.Credential
// already dropped UID/GID and capabilities before execve).
func hardenWorkerProcess() error {
	// PR_SET_DUMPABLE is process-wide (mm_struct) and disables ptrace/core dumps.
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return fmt.Errorf("PR_SET_DUMPABLE: %w", err)
	}

	// Best-effort clear bounding and ambient capability sets (succeeds when
	// CAP_SETPCAP is present, e.g. inside a 1-UID unprivileged test userns;
	// harmless EPERM when already dropped to nobody before execve).
	for capNum := uintptr(0); capNum <= unix.CAP_LAST_CAP; capNum++ {
		_ = allThreadsOrCurrentSyscall6(unix.SYS_PRCTL, unix.PR_CAPBSET_DROP, capNum, 0, 0, 0, 0)
	}
	_ = allThreadsOrCurrentSyscall6(unix.SYS_PRCTL, unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0, 0)

	// Explicitly clear Effective, Permitted, and Inheritable capability sets.
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := allThreadsOrCurrentSyscall6(
		unix.SYS_CAPSET,
		uintptr(unsafe.Pointer(&hdr)),
		uintptr(unsafe.Pointer(&data[0])),
		0, 0, 0, 0,
	); err != nil {
		return fmt.Errorf("capset(0): %w", err)
	}

	// Irreversibly prevent privilege acquisition via execve or file capabilities.
	if err := allThreadsOrCurrentSyscall6(unix.SYS_PRCTL, unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0, 0); err != nil {
		return fmt.Errorf("PR_SET_NO_NEW_PRIVS: %w", err)
	}

	// Block all non-AF_UNIX socket creation across every OS thread so the
	// userspace stack cannot open host IP/netlink/packet sockets even when
	// sharing a hostNetwork: true DaemonSet Pod.
	if err := installUnixOnlySocketSeccomp(); err != nil {
		return err
	}
	return nil
}

func allThreadsOrCurrentSyscall6(trap, a1, a2, a3, a4, a5, a6 uintptr) error {
	_, _, errno := syscall.AllThreadsSyscall6(trap, a1, a2, a3, a4, a5, a6)
	if errno == syscall.EOPNOTSUPP {
		_, _, errno = unix.Syscall6(trap, a1, a2, a3, a4, a5, a6)
	}
	if errno != 0 {
		return errno
	}
	return nil
}

type workerPod struct {
	eng    *tun2connect.Engine
	tunFD  int
	broker *brokerDialClient
}

func (p *workerPod) close() {
	if p.broker != nil {
		p.broker.close()
	}
	if p.eng != nil {
		p.eng.Close()
	}
	if p.tunFD >= 0 {
		_ = unix.Close(p.tunFD)
		p.tunFD = -1
	}
}

type builtinWorker struct {
	mu   sync.Mutex
	pods map[string]*workerPod
}

func (w *builtinWorker) handleRequest(payload []byte, fds []int) ControlResponse {
	var req ControlRequest
	if err := json.Unmarshal(payload, &req); err != nil {
		closeFDs(fds)
		return ControlResponse{OK: false, Error: fmt.Sprintf("decode request: %v", err)}
	}
	switch req.Op {
	case OpAdd:
		if req.PodID == "" {
			closeFDs(fds)
			return ControlResponse{OK: false, Error: "pod_id is required"}
		}
		if len(fds) != 2 {
			closeFDs(fds)
			return ControlResponse{OK: false, Error: fmt.Sprintf("expected 2 FDs [tunFD, brokerFD], got %d", len(fds))}
		}
		tunFD, brokerFD := fds[0], fds[1]
		if err := w.addPod(req, tunFD, brokerFD); err != nil {
			return ControlResponse{OK: false, Error: err.Error()}
		}
		return ControlResponse{OK: true, Stack: builtinStackName}

	case OpRemove:
		closeFDs(fds)
		if req.PodID == "" {
			return ControlResponse{OK: false, Error: "pod_id is required"}
		}
		w.removePod(req.PodID)
		return ControlResponse{OK: true, Stack: builtinStackName}

	case OpDialInbound:
		if req.PodID == "" || req.Addr == "" || req.Port == 0 {
			closeFDs(fds)
			return ControlResponse{OK: false, Error: "pod_id, addr, and port are required"}
		}
		if len(fds) != 1 {
			closeFDs(fds)
			return ControlResponse{OK: false, Error: fmt.Sprintf("expected 1 FD [streamFD], got %d", len(fds))}
		}
		if err := w.dialInbound(req, fds[0]); err != nil {
			return ControlResponse{OK: false, Error: err.Error()}
		}
		return ControlResponse{OK: true, Stack: builtinStackName}

	default:
		closeFDs(fds)
		return ControlResponse{OK: false, Error: fmt.Sprintf("unsupported op %q", req.Op)}
	}
}

func (w *builtinWorker) addPod(req ControlRequest, tunFD, brokerFD int) error {
	cleanup := true
	defer func() {
		if cleanup {
			_ = unix.Close(tunFD)
			_ = unix.Close(brokerFD)
		}
	}()

	if err := unix.SetNonblock(tunFD, true); err != nil {
		return fmt.Errorf("set tunFD non-blocking: %w", err)
	}
	if err := unix.SetNonblock(brokerFD, true); err != nil {
		return fmt.Errorf("set brokerFD non-blocking: %w", err)
	}
	mtu := req.MTU
	if mtu <= 0 {
		mtu = 1500
	}

	var (
		dev       stack.LinkEndpoint
		err       error
		addresses []netip.Prefix
	)
	switch req.LinkMode {
	case "", LinkModeTUN:
		dev, err = tun2connect.NewTUNDevice(tunFD, uint32(mtu))
		if err != nil {
			return fmt.Errorf("create gvisor tun endpoint: %w", err)
		}
	case LinkModeTAP:
		var linkAddr tcpip.LinkAddress
		if req.MAC != "" {
			hw, merr := net.ParseMAC(req.MAC)
			if merr != nil {
				return fmt.Errorf("invalid tap MAC %q: %w", req.MAC, merr)
			}
			linkAddr = tcpip.LinkAddress(hw)
		}
		dev, err = tun2connect.NewTAPDevice(tunFD, uint32(mtu), linkAddr)
		if err != nil {
			return fmt.Errorf("create gvisor tap endpoint: %w", err)
		}
		if len(req.Addresses) == 0 {
			addresses = []netip.Prefix{
				netip.MustParsePrefix(fmt.Sprintf("%s/%d", tun2connect.DefaultResolverAddr, tun2connect.DefaultPool4Bits)),
				netip.MustParsePrefix("100::ffff:ffff:ffff:fffd/64"),
			}
		}
	default:
		return fmt.Errorf("unsupported link_mode %q", req.LinkMode)
	}
	for _, raw := range req.Addresses {
		p, perr := netip.ParsePrefix(raw)
		if perr != nil {
			return fmt.Errorf("invalid interface address %q: %w", raw, perr)
		}
		addresses = append(addresses, p)
	}

	broker := &brokerDialClient{
		file: os.NewFile(uintptr(brokerFD), "hosttun-broker-"+req.PodID),
	}
	client := &tun2connect.BoundaryClient{
		DialBoundary: broker.dial,
	}
	vdns := tun2connect.NewVirtualDNS()
	var dnsHandler tun2connect.DNSHandler = vdns
	if req.DNSMode == DNSModeDoH {
		dnsHandler = tun2connect.NewDoHVirtualDNS(vdns, client.QueryDoH)
	}
	eng, err := tun2connect.New(tun2connect.Config{
		Device:         dev,
		Addresses:      addresses,
		Dialer:         client,
		DNS:            vdns,
		DNSHandler:     dnsHandler,
		EnableUDP:      req.EnableUDP,
		MaxConnections: req.MaxConnections,
	})
	if err != nil {
		broker.close()
		_ = unix.Close(tunFD)
		cleanup = false
		return fmt.Errorf("start tun2connect engine: %w", err)
	}

	cleanup = false
	entry := &workerPod{
		eng:    eng,
		tunFD:  tunFD,
		broker: broker,
	}
	w.mu.Lock()
	prev := w.pods[req.PodID]
	w.pods[req.PodID] = entry
	w.mu.Unlock()
	if prev != nil {
		prev.close()
	}
	return nil
}

func (w *builtinWorker) dialInbound(req ControlRequest, streamFD int) error {
	closeStream := true
	defer func() {
		if closeStream {
			_ = unix.Close(streamFD)
		}
	}()

	addr, err := netip.ParseAddr(req.Addr)
	if err != nil {
		return fmt.Errorf("invalid inbound addr %q: %w", req.Addr, err)
	}
	w.mu.Lock()
	pod := w.pods[req.PodID]
	w.mu.Unlock()
	if pod == nil || pod.eng == nil {
		return fmt.Errorf("unknown pod %q", req.PodID)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	guestConn, err := pod.eng.DialGuestTCP(ctx, addr, req.Port)
	if err != nil {
		return fmt.Errorf("dial guest %s:%d: %w", addr, req.Port, err)
	}

	streamFile := os.NewFile(uintptr(streamFD), "hosttun-inbound-"+req.PodID)
	streamConn, err := net.FileConn(streamFile)
	_ = streamFile.Close()
	closeStream = false
	if err != nil {
		_ = guestConn.Close()
		return fmt.Errorf("wrap inbound stream fd: %w", err)
	}

	go relayPair(streamConn, guestConn)
	return nil
}

func relayPair(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	cp := func(dst, src net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		} else {
			_ = dst.Close()
		}
	}
	go cp(a, b)
	go cp(b, a)
	wg.Wait()
	_ = a.Close()
	_ = b.Close()
}

func (w *builtinWorker) removePod(podID string) {
	w.mu.Lock()
	prev := w.pods[podID]
	delete(w.pods, podID)
	w.mu.Unlock()
	if prev != nil {
		prev.close()
	}
}

func (w *builtinWorker) closeAll() {
	w.mu.Lock()
	all := make([]*workerPod, 0, len(w.pods))
	for id, p := range w.pods {
		all = append(all, p)
		delete(w.pods, id)
	}
	w.mu.Unlock()
	for _, p := range all {
		p.close()
	}
}

// brokerDialClient requests fresh per-flow SOCK_STREAM connections from the
// parent over the Pod's dedicated SOCK_SEQPACKET broker FD. The worker never
// accesses any filesystem path or host network socket.
type brokerDialClient struct {
	mu     sync.Mutex
	file   *os.File
	closed bool
}

func (b *brokerDialClient) close() {
	b.mu.Lock()
	if !b.closed {
		b.closed = true
		_ = b.file.Close()
	}
	b.mu.Unlock()
}

func (b *brokerDialClient) dial(ctx context.Context) (net.Conn, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil, errors.New("host-tun dial broker closed")
	}

	deadline := time.Now().Add(10 * time.Second)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = b.file.SetDeadline(deadline)
	defer func() { _ = b.file.SetDeadline(time.Time{}) }()

	stop := context.AfterFunc(ctx, func() {
		_ = b.file.SetDeadline(time.Now())
	})
	defer stop()

	if err := sendMsgWithFDs(b.file, []byte{brokerReqDial}); err != nil {
		return nil, fmt.Errorf("request egress stream: %w", err)
	}
	resp, fds, err := recvMsgWithFDs(b.file, 64, 2)
	if err != nil {
		return nil, fmt.Errorf("receive egress stream: %w", err)
	}
	if len(resp) == 0 || resp[0] != brokerRespOK || len(fds) != 1 {
		closeFDs(fds)
		return nil, errors.New("parent denied egress stream request")
	}
	connFile := os.NewFile(uintptr(fds[0]), "hosttun-egress-stream")
	conn, err := net.FileConn(connFile)
	_ = connFile.Close()
	if err != nil {
		return nil, fmt.Errorf("wrap brokered egress stream: %w", err)
	}
	return conn, nil
}
