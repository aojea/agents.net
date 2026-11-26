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

// Package testutils provides unprivileged Linux user-namespace execution helpers
// (modeled on sigs.k8s.io/dranet/internal/testutils) so integration tests can
// create real network namespaces, veth pairs, and routing tables without root.
package testutils

import (
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"testing"
)

var (
	isSupported bool
	checkOnce   sync.Once
)

// IsSupported reports whether unprivileged Linux user namespaces are enabled on the host.
func IsSupported() bool {
	checkOnce.Do(func() {
		cmd := exec.Command("true")
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Cloneflags:  syscall.CLONE_NEWUSER,
			UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
			GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
		}
		if err := cmd.Run(); err != nil {
			return
		}
		isSupported = true
	})
	return isSupported
}

// Run executes f inside a re-exec'd subprocess with CLONE_NEWUSER (mapping the current
// user to root) plus extraCloneflags (such as syscall.CLONE_NEWNET and syscall.CLONE_NEWNS).
//
// When syscall.CLONE_NEWNS is requested, Run mounts a fresh private tmpfs on /run so
// tests can create named network namespaces under /run/netns without touching the host.
func Run(t *testing.T, f func(t *testing.T), extraCloneflags ...uintptr) {
	t.Helper()
	const subprocessEnvKey = "DRA_AGENTS_NET_USERNS_SUBPROCESS"

	cloneflags := uintptr(syscall.CLONE_NEWUSER)
	for _, flag := range extraCloneflags {
		cloneflags |= flag
	}

	if os.Getenv(subprocessEnvKey) == "1" {
		if cloneflags&syscall.CLONE_NEWNS != 0 {
			if err := syscall.Mount("tmpfs", "/run", "tmpfs", 0, ""); err != nil {
				t.Fatalf("mount private tmpfs on /run: %v", err)
			}
		}
		t.Run("subprocess", f)
		return
	}

	if !IsSupported() {
		t.Skip("unprivileged user namespaces are not supported on this host")
	}

	cmd := exec.Command(os.Args[0], "-test.run=^"+t.Name()+"$", "-test.v=true")
	for _, arg := range os.Args {
		if strings.HasPrefix(arg, "-test.testlogfile=") {
			cmd.Args = append(cmd.Args, arg)
		}
	}
	cmd.Env = append(os.Environ(),
		subprocessEnvKey+"=1",
		"PATH=/usr/local/sbin:/usr/sbin:/sbin:"+os.Getenv("PATH"),
	)
	cmd.Stdin = os.Stdin
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  cloneflags,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
	}

	out, err := cmd.CombinedOutput()
	t.Logf("\n%s", out)
	if err != nil {
		t.Fatalf("userns subprocess failed: %v", err)
	}
}
