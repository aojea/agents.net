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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"k8s.io/klog/v2"
)

const (
	workerControlTimeout       = 10 * time.Second
	workerStopTimeout          = 3 * time.Second
	workerSocketConnectTimeout = 30 * time.Second
)

// Manager supervises one or more unprivileged userspace stack worker processes
// (or connects to a companion unprivileged stack container over WorkerSocket),
// hands off sandbox TUN and dial-broker descriptors over SCM_RIGHTS, and
// recovers live sandboxes automatically if the stack restarts or crashes.
type Manager struct {
	cfg ManagerConfig

	connectMu    sync.Mutex
	mu           sync.Mutex
	closed       bool
	closeCh      chan struct{}
	sharedWorker *workerProcess
	pods         map[string]*attachedPod
	recoverWG    sync.WaitGroup
}

// NewManager creates a Manager using cfg (defaults to shared self-reexec worker
// when WorkerSocket is empty).
func NewManager(cfg ManagerConfig) *Manager {
	if cfg.Isolation == "" {
		cfg.Isolation = IsolationShared
	}
	return &Manager{
		cfg:     cfg,
		closeCh: make(chan struct{}),
		pods:    make(map[string]*attachedPod),
	}
}

// Attach hands off cfg.TunFD and a fresh per-Pod dial broker to an unprivileged
// worker process, immediately closes cfg.TunFD in the parent process, and
// returns an io.Closer that detaches the sandbox cleanly.
func (m *Manager) Attach(cfg AttachConfig) (io.Closer, error) {
	if cfg.PodID == "" {
		if cfg.TunFD >= 0 {
			_ = unix.Close(cfg.TunFD)
		}
		return nil, errors.New("pod ID is required")
	}
	if cfg.TunFD < 0 {
		return nil, errors.New("valid TUN file descriptor is required")
	}
	if cfg.ServeEgress == nil && cfg.EgressSocketPath == "" {
		_ = unix.Close(cfg.TunFD)
		return nil, errors.New("either ServeEgress or EgressSocketPath is required")
	}
	if cfg.MTU <= 0 {
		cfg.MTU = 1500
	}

	tunFD := cfg.TunFD
	closeTunOnErr := true
	defer func() {
		if closeTunOnErr {
			_ = unix.Close(tunFD)
		}
	}()

	wp, err := m.ensureWorker(cfg.PodID)
	if err != nil {
		return nil, err
	}

	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		m.cleanupUnusedPerPodWorker(wp)
		return nil, errors.New("host-tun worker manager is closed")
	}
	prev := m.pods[cfg.PodID]
	delete(m.pods, cfg.PodID)
	m.mu.Unlock()

	if prev != nil {
		_ = prev.Close()
	}

	brokerHost, brokerWorker, err := newSeqPacketPair("hosttun-broker-host-"+cfg.PodID, "hosttun-broker-worker-"+cfg.PodID)
	if err != nil {
		m.cleanupUnusedPerPodWorker(wp)
		return nil, err
	}

	ap := &attachedPod{
		mgr:        m,
		cfg:        cfg,
		worker:     wp,
		brokerHost: brokerHost,
	}
	ap.startBroker(brokerHost)

	// Send [tunFD, brokerWorker] to the worker and immediately close both FDs in the parent.
	req := ControlRequest{
		Op:             OpAdd,
		PodID:          cfg.PodID,
		MTU:            cfg.MTU,
		MaxConnections: cfg.MaxConnections,
		EnableUDP:      cfg.EnableUDP,
		DNSMode:        cfg.DNSMode,
	}
	sendErr := wp.call(req, tunFD, int(brokerWorker.Fd()))
	_ = brokerWorker.Close()
	_ = unix.Close(tunFD)
	closeTunOnErr = false

	if sendErr != nil {
		ap.stopBroker()
		m.cleanupUnusedPerPodWorker(wp)
		return nil, fmt.Errorf("attach pod %s to host-tun worker: %w", cfg.PodID, sendErr)
	}

	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		_ = ap.Close()
		return nil, errors.New("host-tun worker manager closed during attach")
	}
	m.pods[cfg.PodID] = ap
	m.mu.Unlock()
	return ap, nil
}

// WorkerPID returns the OS PID of the unprivileged worker currently serving
// podID, or 0 if podID is not attached.
func (m *Manager) WorkerPID(podID string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	ap := m.pods[podID]
	if ap == nil || ap.worker == nil {
		return 0
	}
	return ap.worker.pid
}

// Close detaches all sandboxes and terminates all supervised worker processes.
func (m *Manager) Close() error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true
	close(m.closeCh)
	type podStop struct {
		ap *attachedPod
		wp *workerProcess
	}
	pods := make([]podStop, 0, len(m.pods))
	for id, ap := range m.pods {
		pods = append(pods, podStop{ap: ap, wp: ap.worker})
		delete(m.pods, id)
	}
	shared := m.sharedWorker
	m.sharedWorker = nil
	m.mu.Unlock()

	for _, item := range pods {
		item.ap.closeLocal(true, item.wp)
	}
	if shared != nil {
		shared.stop()
	}
	m.recoverWG.Wait()
	return nil
}

func (m *Manager) isPerPodChildMode() bool {
	return m.cfg.WorkerSocket == "" && m.cfg.Isolation == IsolationPerPod
}

func (m *Manager) ensureWorker(podID string) (*workerProcess, error) {
	if m.isPerPodChildMode() {
		m.mu.Lock()
		closed := m.closed
		m.mu.Unlock()
		if closed {
			return nil, errors.New("host-tun worker manager is closed")
		}
		return m.spawnWorker("pod-" + podID)
	}

	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil, errors.New("host-tun worker manager is closed")
	}
	if m.sharedWorker != nil && !m.sharedWorker.isDead() {
		wp := m.sharedWorker
		m.mu.Unlock()
		return wp, nil
	}
	m.mu.Unlock()

	m.connectMu.Lock()
	defer m.connectMu.Unlock()

	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil, errors.New("host-tun worker manager is closed")
	}
	if m.sharedWorker != nil && !m.sharedWorker.isDead() {
		wp := m.sharedWorker
		m.mu.Unlock()
		return wp, nil
	}
	m.mu.Unlock()

	var (
		wp  *workerProcess
		err error
	)
	if m.cfg.WorkerSocket != "" {
		wp, err = m.connectWorkerSocket()
	} else {
		wp, err = m.spawnWorker("shared")
	}
	if err != nil {
		return nil, err
	}

	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		wp.stop()
		return nil, errors.New("host-tun worker manager is closed")
	}
	m.sharedWorker = wp
	m.mu.Unlock()
	return wp, nil
}

func (m *Manager) cleanupUnusedPerPodWorker(wp *workerProcess) {
	if m.isPerPodChildMode() && wp != nil {
		wp.stop()
	}
}

func (m *Manager) connectWorkerSocket() (*workerProcess, error) {
	deadline := time.Now().Add(workerSocketConnectTimeout)
	backoff := 50 * time.Millisecond
	var lastErr error

	for {
		fd, err := dialSeqPacket(m.cfg.WorkerSocket)
		if err == nil {
			stopR, stopW, pipeErr := os.Pipe()
			if pipeErr != nil {
				_ = unix.Close(fd)
				return nil, fmt.Errorf("create socket watcher pipe: %w", pipeErr)
			}
			pid := 0
			if ucred, credErr := unix.GetsockoptUcred(fd, unix.SOL_SOCKET, unix.SO_PEERCRED); credErr == nil {
				pid = int(ucred.Pid)
			}
			wp := &workerProcess{
				mgr:        m,
				scope:      "socket",
				pid:        pid,
				ctrlParent: os.NewFile(uintptr(fd), "hosttun-ctrl-socket"),
				stopR:      stopR,
				stopW:      stopW,
				done:       make(chan struct{}),
			}
			go wp.watchSocket()
			klog.InfoS("connected to unprivileged host-tun stack socket",
				"socket", m.cfg.WorkerSocket, "peerPID", wp.pid)
			return wp, nil
		}
		lastErr = err
		if !time.Now().Before(deadline) {
			return nil, fmt.Errorf("connect to host-tun stack socket %q: %w", m.cfg.WorkerSocket, lastErr)
		}
		timer := time.NewTimer(backoff)
		select {
		case <-m.closeCh:
			timer.Stop()
			return nil, errors.New("host-tun worker manager closed while connecting to stack socket")
		case <-timer.C:
		}
		if backoff < 250*time.Millisecond {
			backoff *= 2
			if backoff > 250*time.Millisecond {
				backoff = 250 * time.Millisecond
			}
		}
	}
}

func dialSeqPacket(socketPath string) (int, error) {
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	if err := unix.Connect(fd, &unix.SockaddrUnix{Name: socketPath}); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

func (m *Manager) spawnWorker(scope string) (*workerProcess, error) {
	bin := m.cfg.WorkerBin
	args := append([]string(nil), m.cfg.WorkerArgs...)
	env := []string{fmt.Sprintf("%s=%d", EnvCtrlFD, DefaultCtrlFD)}
	if bin == "" {
		exe, err := os.Executable()
		if err != nil {
			return nil, fmt.Errorf("resolve executable for host-tun worker: %w", err)
		}
		bin = exe
		if len(args) == 0 {
			args = []string{"--host-tun-worker"}
		}
		env = append(env, EnvWorkerMode+"=1")
	}

	ctrlParent, ctrlWorker, err := newSeqPacketPair("hosttun-ctrl-parent-"+scope, "hosttun-ctrl-worker-"+scope)
	if err != nil {
		return nil, err
	}

	cmd := exec.Command(bin, args...)
	cmd.Env = env
	cmd.Dir = "/"
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	cmd.ExtraFiles = []*os.File{ctrlWorker}
	cmd.SysProcAttr = buildWorkerSysProcAttr()

	if err := cmd.Start(); err != nil {
		_ = ctrlParent.Close()
		_ = ctrlWorker.Close()
		return nil, fmt.Errorf("start unprivileged host-tun worker (%s): %w", bin, err)
	}
	_ = ctrlWorker.Close()

	wp := &workerProcess{
		mgr:        m,
		scope:      scope,
		cmd:        cmd,
		pid:        cmd.Process.Pid,
		ctrlParent: ctrlParent,
		done:       make(chan struct{}),
	}
	go wp.watch()
	klog.InfoS("started unprivileged host-tun worker",
		"scope", scope, "pid", wp.pid, "isolation", string(m.cfg.Isolation), "bin", bin)
	return wp, nil
}

func (m *Manager) onWorkerExit(wp *workerProcess, waitErr error) {
	m.mu.Lock()
	if m.closed || wp.isStopping() {
		if m.sharedWorker == wp {
			m.sharedWorker = nil
		}
		m.mu.Unlock()
		return
	}
	if m.sharedWorker == wp {
		m.sharedWorker = nil
	}
	var affected []*attachedPod
	for _, ap := range m.pods {
		if ap.worker == wp {
			affected = append(affected, ap)
		}
	}
	if len(affected) == 0 {
		m.mu.Unlock()
		return
	}
	m.recoverWG.Add(1)
	m.mu.Unlock()
	defer m.recoverWG.Done()

	klog.ErrorS(waitErr, "unprivileged host-tun worker exited unexpectedly; recovering attached sandboxes",
		"scope", wp.scope, "pid", wp.pid, "sandboxes", len(affected))

	for _, ap := range affected {
		if err := m.recoverPod(ap, wp); err != nil {
			klog.ErrorS(err, "failed to recover sandbox after host-tun worker crash", "podID", ap.cfg.PodID)
		}
	}
}

func (m *Manager) recoverPod(ap *attachedPod, crashed *workerProcess) error {
	if ap.cfg.ReopenTun == nil {
		return errors.New("no ReopenTun hook configured for crash recovery")
	}

	m.mu.Lock()
	if m.closed || ap.isClosed() || m.pods[ap.cfg.PodID] != ap || ap.worker != crashed {
		m.mu.Unlock()
		return nil
	}
	m.mu.Unlock()

	newWP, err := m.ensureWorker(ap.cfg.PodID)
	if err != nil {
		return fmt.Errorf("respawn host-tun worker: %w", err)
	}

	tunFD, err := ap.cfg.ReopenTun()
	if err != nil {
		m.cleanupUnusedPerPodWorker(newWP)
		return fmt.Errorf("reopen persistent tun0: %w", err)
	}

	brokerHost, brokerWorker, err := newSeqPacketPair("hosttun-broker-host-"+ap.cfg.PodID, "hosttun-broker-worker-"+ap.cfg.PodID)
	if err != nil {
		_ = unix.Close(tunFD)
		m.cleanupUnusedPerPodWorker(newWP)
		return err
	}

	ap.swapBroker(brokerHost)

	req := ControlRequest{
		Op:             OpAdd,
		PodID:          ap.cfg.PodID,
		MTU:            ap.cfg.MTU,
		MaxConnections: ap.cfg.MaxConnections,
		EnableUDP:      ap.cfg.EnableUDP,
		DNSMode:        ap.cfg.DNSMode,
	}
	sendErr := newWP.call(req, tunFD, int(brokerWorker.Fd()))
	_ = brokerWorker.Close()
	_ = unix.Close(tunFD)
	if sendErr != nil {
		m.cleanupUnusedPerPodWorker(newWP)
		return fmt.Errorf("re-attach pod %s to recovered worker: %w", ap.cfg.PodID, sendErr)
	}

	m.mu.Lock()
	if m.closed || ap.isClosed() || m.pods[ap.cfg.PodID] != ap {
		m.mu.Unlock()
		_ = newWP.call(ControlRequest{Op: OpRemove, PodID: ap.cfg.PodID})
		m.cleanupUnusedPerPodWorker(newWP)
		return nil
	}
	ap.worker = newWP
	m.mu.Unlock()

	klog.InfoS("recovered sandbox on new unprivileged host-tun worker",
		"podID", ap.cfg.PodID, "oldPID", crashed.pid, "newPID", newWP.pid)
	return nil
}

type workerProcess struct {
	mgr        *Manager
	scope      string
	cmd        *exec.Cmd
	pid        int
	ctrlParent *os.File
	stopR      *os.File
	stopW      *os.File
	stopWOnce  sync.Once

	callMu   sync.Mutex
	stateMu  sync.Mutex
	stopping bool
	dead     bool
	done     chan struct{}
}

func (w *workerProcess) isDead() bool {
	w.stateMu.Lock()
	defer w.stateMu.Unlock()
	return w.dead || w.stopping
}

func (w *workerProcess) isStopping() bool {
	w.stateMu.Lock()
	defer w.stateMu.Unlock()
	return w.stopping
}

func (w *workerProcess) signalStopPipe() {
	w.stopWOnce.Do(func() {
		if w.stopW != nil {
			_ = w.stopW.Close()
		}
	})
}

func (w *workerProcess) watch() {
	err := w.cmd.Wait()
	w.stateMu.Lock()
	w.dead = true
	w.stateMu.Unlock()
	_ = w.ctrlParent.Close()
	close(w.done)
	w.mgr.onWorkerExit(w, err)
}

func (w *workerProcess) watchSocket() {
	pfds := []unix.PollFd{
		{Fd: int32(w.ctrlParent.Fd()), Events: unix.POLLRDHUP},
		{Fd: int32(w.stopR.Fd()), Events: unix.POLLIN},
	}
	for {
		_, err := unix.Poll(pfds, -1)
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		break
	}

	w.stateMu.Lock()
	w.dead = true
	stopping := w.stopping
	w.stateMu.Unlock()

	_ = w.ctrlParent.SetDeadline(time.Now())
	w.callMu.Lock()
	_ = w.ctrlParent.Close()
	w.callMu.Unlock()
	w.signalStopPipe()
	_ = w.stopR.Close()
	close(w.done)

	if !stopping {
		w.mgr.onWorkerExit(w, errors.New("host-tun stack socket closed"))
	}
}

func (w *workerProcess) call(req ControlRequest, fds ...int) error {
	raw, err := json.Marshal(req)
	if err != nil {
		return err
	}
	w.callMu.Lock()
	defer w.callMu.Unlock()

	_ = w.ctrlParent.SetDeadline(time.Now().Add(workerControlTimeout))
	defer func() { _ = w.ctrlParent.SetDeadline(time.Time{}) }()

	if err := sendMsgWithFDs(w.ctrlParent, raw, fds...); err != nil {
		return err
	}
	respBytes, respFDs, err := recvMsgWithFDs(w.ctrlParent, maxControlMsgBytes, 0)
	closeFDs(respFDs)
	if err != nil {
		return err
	}
	var resp ControlResponse
	if err := json.Unmarshal(respBytes, &resp); err != nil {
		return fmt.Errorf("decode worker response: %w", err)
	}
	if !resp.OK {
		return fmt.Errorf("worker rejected %s: %s", req.Op, resp.Error)
	}
	return nil
}

func (w *workerProcess) stop() {
	w.stateMu.Lock()
	if w.stopping {
		w.stateMu.Unlock()
		<-w.done
		return
	}
	w.stopping = true
	w.stateMu.Unlock()

	if w.cmd == nil {
		_ = w.ctrlParent.SetDeadline(time.Now())
		w.signalStopPipe()
		<-w.done
		return
	}

	_ = w.ctrlParent.Close()
	select {
	case <-w.done:
		return
	case <-time.After(workerStopTimeout):
	}
	if w.cmd.Process != nil {
		_ = w.cmd.Process.Kill()
	}
	<-w.done
}

type attachedPod struct {
	mgr    *Manager
	cfg    AttachConfig
	worker *workerProcess

	mu         sync.Mutex
	closed     bool
	brokerHost *os.File
	brokerDone chan struct{}
	closeOnce  sync.Once
}

func (a *attachedPod) isClosed() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.closed
}

func (a *attachedPod) startBroker(hostFile *os.File) {
	done := make(chan struct{})
	a.mu.Lock()
	a.brokerHost = hostFile
	a.brokerDone = done
	a.mu.Unlock()

	go func() {
		defer close(done)
		a.serveBroker(hostFile)
	}()
}

func (a *attachedPod) swapBroker(newHostFile *os.File) {
	a.mu.Lock()
	oldFile := a.brokerHost
	oldDone := a.brokerDone
	newDone := make(chan struct{})
	a.brokerHost = newHostFile
	a.brokerDone = newDone
	a.mu.Unlock()

	if oldFile != nil {
		_ = oldFile.Close()
	}
	if oldDone != nil {
		<-oldDone
	}
	go func() {
		defer close(newDone)
		a.serveBroker(newHostFile)
	}()
}

func (a *attachedPod) stopBroker() {
	a.mu.Lock()
	f := a.brokerHost
	done := a.brokerDone
	a.brokerHost = nil
	a.brokerDone = nil
	a.mu.Unlock()
	if f != nil {
		_ = f.Close()
	}
	if done != nil {
		<-done
	}
}

func (a *attachedPod) serveBroker(hostFile *os.File) {
	for {
		req, fds, err := recvMsgWithFDs(hostFile, 64, 0)
		closeFDs(fds)
		if err != nil {
			return
		}
		if len(req) == 0 || req[0] != brokerReqDial {
			_ = sendMsgWithFDs(hostFile, []byte{brokerRespDeny})
			continue
		}
		workerFD, err := a.openEgressStreamFD()
		if err != nil {
			_ = sendMsgWithFDs(hostFile, []byte{brokerRespDeny})
			continue
		}
		sendErr := sendMsgWithFDs(hostFile, []byte{brokerRespOK}, workerFD)
		_ = unix.Close(workerFD)
		if sendErr != nil {
			return
		}
	}
}

func (a *attachedPod) openEgressStreamFD() (int, error) {
	if a.cfg.ServeEgress != nil {
		fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			return -1, fmt.Errorf("socketpair(SOCK_STREAM): %w", err)
		}
		hostFile := os.NewFile(uintptr(fds[0]), "hosttun-egress-host-"+a.cfg.PodID)
		hostConn, err := net.FileConn(hostFile)
		_ = hostFile.Close()
		if err != nil {
			_ = unix.Close(fds[1])
			return -1, fmt.Errorf("wrap host egress socketpair: %w", err)
		}
		if err := a.cfg.ServeEgress(hostConn); err != nil {
			_ = unix.Close(fds[1])
			return -1, err
		}
		return fds[1], nil
	}

	conn, err := net.DialTimeout("unix", a.cfg.EgressSocketPath, 5*time.Second)
	if err != nil {
		return -1, err
	}
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		_ = conn.Close()
		return -1, errors.New("unexpected non-unix connection")
	}
	dupFile, err := uc.File()
	_ = uc.Close()
	if err != nil {
		return -1, err
	}
	rawFD, err := unix.FcntlInt(dupFile.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	_ = dupFile.Close()
	if err != nil {
		return -1, err
	}
	return rawFD, nil
}

func (a *attachedPod) Close() error {
	a.closeLocal(false, nil)
	return nil
}

func (a *attachedPod) closeLocal(managerClosing bool, snapshotWP *workerProcess) {
	a.closeOnce.Do(func() {
		a.mu.Lock()
		a.closed = true
		a.mu.Unlock()

		wp := snapshotWP
		if !managerClosing {
			a.mgr.mu.Lock()
			if a.mgr.pods[a.cfg.PodID] == a {
				delete(a.mgr.pods, a.cfg.PodID)
			}
			wp = a.worker
			a.mgr.mu.Unlock()
		}

		a.stopBroker()
		if wp != nil {
			if a.mgr.isPerPodChildMode() {
				wp.stop()
			} else if !wp.isDead() {
				_ = wp.call(ControlRequest{Op: OpRemove, PodID: a.cfg.PodID})
			}
		}
	})
}

func buildWorkerSysProcAttr() *syscall.SysProcAttr {
	// Workers exit cleanly when the parent closes (or crashes and the kernel
	// closes) the control SOCK_SEQPACKET descriptor. Avoid Pdeathsig here
	// because Go's scheduler can terminate the OS thread that called Start
	// while the parent process is still alive (go.dev/issue/27505).
	attr := &syscall.SysProcAttr{
		Cloneflags: unix.CLONE_NEWNET,
	}
	// Drop to nobody:nogroup before execve whenever 65534 is mapped in the
	// current user namespace (always true in real root containers and on hosts;
	// skipped only in single-UID unprivileged test user namespaces).
	if os.Geteuid() == 0 && idMappedInProc("/proc/self/uid_map", DefaultWorkerUID) && idMappedInProc("/proc/self/gid_map", DefaultWorkerGID) {
		attr.Credential = &syscall.Credential{
			Uid:    DefaultWorkerUID,
			Gid:    DefaultWorkerGID,
			Groups: []uint32{},
		}
	}
	return attr
}

func idMappedInProc(path string, target uint32) bool {
	raw, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	for line := range strings.SplitSeq(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 3 {
			continue
		}
		start, err1 := strconv.ParseUint(fields[0], 10, 32)
		length, err2 := strconv.ParseUint(fields[2], 10, 32)
		if err1 != nil || err2 != nil {
			continue
		}
		if uint64(target) >= start && uint64(target) < start+length {
			return true
		}
	}
	return false
}
