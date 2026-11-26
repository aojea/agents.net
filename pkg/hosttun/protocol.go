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

// Package hosttun isolates host-side userspace packet processing (Virtual DNS
// and PEP forwarding over TUN file descriptors) into unprivileged child worker
// processes fed over SCM_RIGHTS file-descriptor handoff.
//
// The minimal wire protocol lets operators run either the built-in Go/gVisor
// netstack worker (--host-tun-worker) or an external userspace network stack
// binary (--host-tun-worker-bin) in shared (multi-tenant) or per-pod
// (multi-single-tenant) isolation modes.
package hosttun

import (
	"fmt"
	"net"
)

const (
	// EnvCtrlFD is the environment variable carrying the inherited control
	// SOCK_SEQPACKET file descriptor number inside a worker process (default 3).
	EnvCtrlFD = "AGENTS_NET_CTRL_FD"

	// EnvWorkerMode triggers the built-in worker entrypoint when self-reexec'd
	// (including inside Go test binaries via TestMain).
	EnvWorkerMode = "AGENTS_NET_HOST_TUN_WORKER"

	// DefaultCtrlFD is the standard inherited descriptor index (first ExtraFile).
	DefaultCtrlFD = 3

	// DefaultWorkerSocket is the default emptyDir AF_UNIX SOCK_SEQPACKET socket
	// path shared between dra-agents-net and agents-net-stack in the two-container
	// DaemonSet deployment.
	DefaultWorkerSocket = "/run/hosttun/worker.sock"

	// OpAdd attaches a sandbox's TUN or L2 TAP and dial-broker file descriptors to the worker.
	OpAdd = "add"
	// OpRemove detaches a sandbox and closes its TUN/TAP and dial-broker descriptors.
	OpRemove = "remove"
	// OpDialInbound asks the worker to open an inbound TCP connection into the
	// guest (for example an L2 microVM over virtio-net/TAP) and bridge it to the
	// parent-supplied AF_UNIX SOCK_STREAM descriptor sent via SCM_RIGHTS.
	OpDialInbound = "dial_inbound"

	// LinkModeTUN wraps raw L3 IP packets (no Ethernet header, default for container tun0).
	LinkModeTUN = "tun"
	// LinkModeTAP wraps L2 Ethernet frames with ARP (for microVM virtio-net / TAP / QEMU dgram).
	LinkModeTAP = "tap"

	// DNSModeSynthetic answers guest DNS queries locally with synthetic IPs.
	DNSModeSynthetic = "synthetic"
	// DNSModeDoH forwards guest DNS queries via RFC 8484 DoH over the Pod's
	// brokered egress channel while rewriting positive answers to synthetic IPs.
	DNSModeDoH = "doh"

	// DefaultWorkerUID and DefaultWorkerGID drop unprivileged workers to nobody:nogroup
	// whenever that ID is mapped in the current user namespace.
	DefaultWorkerUID = 65534
	DefaultWorkerGID = 65534

	brokerReqDial  byte = 1
	brokerRespOK   byte = 0
	brokerRespDeny byte = 1

	maxControlMsgBytes = 16 * 1024
)

// IsolationMode controls how sandboxes map onto unprivileged worker processes.
type IsolationMode string

const (
	// IsolationShared runs a single unprivileged worker process on the node for
	// all confined sandboxes (multi-tenant, lowest memory overhead).
	IsolationShared IsolationMode = "shared"

	// IsolationPerPod runs a dedicated unprivileged worker process for each
	// sandbox Pod (multi-single-tenant, strict process blast-radius isolation).
	IsolationPerPod IsolationMode = "per-pod"
)

// ParseIsolationMode validates and normalizes a CLI isolation mode flag.
func ParseIsolationMode(raw string) (IsolationMode, error) {
	switch IsolationMode(raw) {
	case "", IsolationShared:
		return IsolationShared, nil
	case IsolationPerPod:
		return IsolationPerPod, nil
	default:
		return "", fmt.Errorf("invalid host-tun isolation mode %q (want %q or %q)", raw, IsolationShared, IsolationPerPod)
	}
}

// ControlRequest is one JSON datagram sent from the plumbing parent to a worker
// on the control SOCK_SEQPACKET socket (FD 3). OpAdd accompanies 2 SCM_RIGHTS
// file descriptors: [tunFD, brokerFD]. OpDialInbound accompanies 1 SCM_RIGHTS
// file descriptor: [streamFD].
type ControlRequest struct {
	Op             string   `json:"op"`
	PodID          string   `json:"pod_id"`
	MTU            int      `json:"mtu,omitempty"`
	MaxConnections int      `json:"max_connections,omitempty"`
	EnableUDP      bool     `json:"enable_udp,omitempty"`
	DNSMode        string   `json:"dns_mode,omitempty"`
	LinkMode       string   `json:"link_mode,omitempty"`
	MAC            string   `json:"mac,omitempty"`
	Addresses      []string `json:"addresses,omitempty"`
	Addr           string   `json:"addr,omitempty"`
	Port           uint16   `json:"port,omitempty"`
}

// ControlResponse is the worker's JSON reply datagram for one ControlRequest.
type ControlResponse struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	Stack string `json:"stack,omitempty"`
}

// ManagerConfig configures the host-side unprivileged worker Manager.
type ManagerConfig struct {
	// WorkerSocket connects Manager to an external unprivileged userspace stack
	// container (such as cmd/agents-net-stack) listening on an AF_UNIX
	// SOCK_SEQPACKET socket (for example over a shared emptyDir volume).
	// When set, Manager dials WorkerSocket instead of spawning child processes.
	WorkerSocket string
	// Isolation selects shared (multi-tenant) or per-pod (multi-single-tenant)
	// child workers when WorkerSocket is empty.
	Isolation IsolationMode
	// WorkerBin optionally overrides the child worker executable path when
	// WorkerSocket is empty. When empty, Manager self-reexecs os.Executable()
	// with --host-tun-worker.
	WorkerBin string
	// WorkerArgs optionally specifies arguments for WorkerBin.
	WorkerArgs []string
}

// AttachConfig supplies one sandbox's TUN/TAP file descriptor and egress callback
// for attachment to an unprivileged worker. Manager takes ownership of TunFD
// and closes it in the parent immediately after SCM_RIGHTS handoff.
type AttachConfig struct {
	PodID          string
	TunFD          int
	MTU            int
	MaxConnections int
	EnableUDP      bool
	DNSMode        string
	LinkMode       string
	MAC            string
	Addresses      []string

	// ServeEgress admits a parent-side kernel socketpair directly into the Pod's
	// tunnel listener so the worker needs zero filesystem access.
	ServeEgress func(net.Conn) error
	// EgressSocketPath is an optional fallback Unix socket dialed by the parent
	// when ServeEgress is nil.
	EgressSocketPath string
	// ReopenTun optionally re-opens the persistent tun0 descriptor in the Pod
	// netns when recovering from an unexpected worker crash.
	ReopenTun func() (int, error)
}
