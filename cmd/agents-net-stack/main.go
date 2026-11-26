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

// Command agents-net-stack runs the unprivileged host-side userspace network
// stack container paired with dra-agents-net in the two-container DaemonSet.
//
// It listens on an AF_UNIX SOCK_SEQPACKET socket (shared over an emptyDir
// volume), receives per-Pod TUN and dial-broker file descriptors via
// SCM_RIGHTS, terminates Virtual DNS (198.18.0.0/15, 100::/64) and TCP/UDP in
// userspace (gVisor netstack), and forwards egress flows back to dra-agents-net
// over parent-brokered kernel socketpairs. It holds zero Linux capabilities,
// zero Kubernetes credentials, zero mTLS private keys, and installs a seccomp
// filter denying all non-AF_UNIX socket creation.
package main

import (
	"context"
	"flag"
	"os/signal"
	"syscall"

	"k8s.io/klog/v2"

	"github.com/aojea/agents.net/pkg/hosttun"
)

func main() {
	var socketPath string
	klog.InitFlags(nil)
	flag.StringVar(&socketPath, "socket", hosttun.DefaultWorkerSocket, "AF_UNIX SOCK_SEQPACKET socket path shared with dra-agents-net")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := hosttun.ServeSocket(ctx, socketPath); err != nil {
		klog.Fatalf("agents-net-stack failed: %v", err)
	}
}
