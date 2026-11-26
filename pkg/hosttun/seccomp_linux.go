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
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

// installUnixOnlySocketSeccomp installs an irreversible seccomp-BPF filter
// across all OS threads (SECCOMP_FILTER_FLAG_TSYNC) that rejects socket(2) and
// socketpair(2) calls for any address family other than AF_UNIX with EPERM.
//
// A HostTun userspace network stack reads raw IP packets exclusively from
// passed TUN descriptors and communicates with the parent exclusively over
// AF_UNIX sockets. Blocking AF_INET, AF_INET6, AF_NETLINK, and AF_PACKET
// ensures the stack container cannot contact host services (such as 127.0.0.1
// kubelet or metadata endpoints) even when sharing a hostNetwork: true
// DaemonSet Pod.
func installUnixOnlySocketSeccomp() error {
	var auditArch uint32
	switch runtime.GOARCH {
	case "amd64":
		auditArch = unix.AUDIT_ARCH_X86_64
	case "arm64":
		auditArch = unix.AUDIT_ARCH_AARCH64
	default:
		// Skip arch-specific BPF offsets on untested architectures rather than
		// risking a wrong syscall number or endianness mismatch.
		return nil
	}

	// struct seccomp_data layout on little-endian 64-bit Linux:
	//   offset  0: nr   (uint32)
	//   offset  4: arch (uint32)
	//   offset 16: args[0] low  32 bits (domain)
	//   offset 20: args[0] high 32 bits (domain)
	const (
		offNR        = 0
		offArch      = 4
		offArg0Low   = 16
		offArg0High  = 20
		retAllow     = unix.SECCOMP_RET_ALLOW
		retDenyEPERM = unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)
	)

	filter := []unix.SockFilter{
		// 0: load seccomp_data.arch
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: offArch},
		// 1: if arch != auditArch -> jump to 10 (DENY) to prevent compat syscall bypass
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: auditArch, Jt: 0, Jf: 8},
		// 2: load seccomp_data.nr
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: offNR},
		// 3: if nr == SYS_SOCKET -> jump to 5 (check domain)
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: uint32(unix.SYS_SOCKET), Jt: 1, Jf: 0},
		// 4: if nr == SYS_SOCKETPAIR -> fallthrough to 5; else jump to 9 (ALLOW)
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: uint32(unix.SYS_SOCKETPAIR), Jt: 0, Jf: 4},
		// 5: load high 32 bits of args[0] (domain)
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: offArg0High},
		// 6: if high32 != 0 -> jump to 10 (DENY)
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: 0, Jt: 0, Jf: 3},
		// 7: load low 32 bits of args[0] (domain)
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: offArg0Low},
		// 8: if domain == AF_UNIX -> fallthrough to 9 (ALLOW); else jump to 10 (DENY)
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: unix.AF_UNIX, Jt: 0, Jf: 1},
		// 9: ALLOW
		{Code: unix.BPF_RET | unix.BPF_K, K: retAllow},
		// 10: DENY (EPERM)
		{Code: unix.BPF_RET | unix.BPF_K, K: retDenyEPERM},
	}

	prog := unix.SockFprog{
		Len:    uint16(len(filter)),
		Filter: &filter[0],
	}

	r1, _, errno := unix.Syscall(
		unix.SYS_SECCOMP,
		unix.SECCOMP_SET_MODE_FILTER,
		unix.SECCOMP_FILTER_FLAG_TSYNC,
		uintptr(unsafe.Pointer(&prog)),
	)
	if errno != 0 {
		return fmt.Errorf("seccomp(SECCOMP_SET_MODE_FILTER|TSYNC): %w", errno)
	}
	if r1 != 0 {
		return fmt.Errorf("seccomp TSYNC failed on thread %d", r1)
	}
	return nil
}
