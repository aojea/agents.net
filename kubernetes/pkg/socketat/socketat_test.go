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

package socketat

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const helperEnvVar = "AGENTS_NET_SOCKETAT_HELPER"

func TestListenAtAcrossRealNetworkNamespace(t *testing.T) {
	if os.Getenv(helperEnvVar) == "1" {
		runCrossNetNSHelper(t)
		return
	}

	// Re-exec inside a fresh unprivileged user+net namespace so CAP_SYS_ADMIN is
	// available to create a second child netns and exercise unix.Setns + ListenAtPath
	// against a real isolated loopback namespace without requiring host root.
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	cmd := exec.Command(exe, "-test.run=^TestListenAtAcrossRealNetworkNamespace$", "-test.v")
	cmd.Env = append(os.Environ(), helperEnvVar+"=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET,
		UidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: os.Getuid(), Size: 1},
		},
		GidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: os.Getgid(), Size: 1},
		},
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("cross-netns socketat helper failed: %v\n%s", err, string(out))
	}
}

func runCrossNetNSHelper(t *testing.T) {
	t.Helper()

	// Create a second isolated network namespace on a locked thread (simulating a Pod netns),
	// bring its loopback interface UP, and keep an open FD to it while switching back.
	runtime.LockOSThread()
	hostNSPath := fmt.Sprintf("/proc/%d/task/%d/ns/net", os.Getpid(), unix.Gettid())
	hostNS, err := os.Open(hostNSPath)
	if err != nil {
		runtime.UnlockOSThread()
		t.Fatalf("open host netns: %v", err)
	}
	defer func() { _ = hostNS.Close() }()

	if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
		runtime.UnlockOSThread()
		t.Fatalf("unshare pod netns: %v", err)
	}
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		_ = unix.Setns(int(hostNS.Fd()), unix.CLONE_NEWNET)
		runtime.UnlockOSThread()
		t.Fatalf("find lo in pod netns: %v", err)
	}
	if err := netlink.LinkSetUp(lo); err != nil {
		_ = unix.Setns(int(hostNS.Fd()), unix.CLONE_NEWNET)
		runtime.UnlockOSThread()
		t.Fatalf("bring up lo in pod netns: %v", err)
	}
	podNSPath := fmt.Sprintf("/proc/%d/task/%d/ns/net", os.Getpid(), unix.Gettid())
	podNS, err := os.Open(podNSPath)
	if err != nil {
		_ = unix.Setns(int(hostNS.Fd()), unix.CLONE_NEWNET)
		runtime.UnlockOSThread()
		t.Fatalf("open pod netns fd: %v", err)
	}
	defer func() { _ = podNS.Close() }()

	if err := unix.Setns(int(hostNS.Fd()), unix.CLONE_NEWNET); err != nil {
		runtime.UnlockOSThread()
		t.Fatalf("restore host netns: %v", err)
	}
	runtime.UnlockOSThread()

	// Bind 127.0.0.1:0 INSIDE the pod netns via socketat.ListenAt, then accept on a host goroutine.
	ln, err := ListenAt(int(podNS.Fd()), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenAt pod netns: %v", err)
	}
	defer func() { _ = ln.Close() }()

	accepted := make(chan struct{})
	go func() {
		defer close(accepted)
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		_, _ = io.Copy(c, c)
	}()

	// Confirm host netns CANNOT connect to the Pod loopback listener directly (namespace isolation).
	if hc, err := net.DialTimeout("tcp", ln.Addr().String(), 200*time.Millisecond); err == nil {
		_ = hc.Close()
		t.Fatalf("host netns unexpectedly connected to pod loopback %s", ln.Addr())
	}

	// Dial from host into the pod netns via DialAt and verify round-trip echo!
	conn, err := DialAt(int(podNS.Fd()), "tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("DialAt pod loopback: %v", err)
	}
	if _, err := io.WriteString(conn, "socketat-cross-netns-ok"); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = conn.(*net.TCPConn).CloseWrite()
	got, err := io.ReadAll(conn)
	_ = conn.Close()
	if err != nil || string(got) != "socketat-cross-netns-ok" {
		t.Fatalf("echo = %q err=%v, want socketat-cross-netns-ok", string(got), err)
	}
	<-accepted

	// DialAt must reject non-IP hostnames so DNS resolution never spawns goroutines across netns.
	if _, err := DialAt(int(podNS.Fd()), "tcp", "localhost:80", time.Second); err == nil {
		t.Fatalf("expected error for non-IP address in DialAt")
	}
}

func TestListenAtAndDialAtPathMissingNetNSReturnsError(t *testing.T) {
	if _, err := ListenAtPath("/nonexistent/dra-agents-net/ns", "tcp", "127.0.0.1:0"); err == nil {
		t.Fatalf("expected error for missing netns path in ListenAtPath")
	}
	if _, err := DialAtPath("/nonexistent/dra-agents-net/ns", "tcp", "127.0.0.1:80", time.Second); err == nil {
		t.Fatalf("expected error for missing netns path in DialAtPath")
	}
}
