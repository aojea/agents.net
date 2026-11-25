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

// Package metrics defines Prometheus instrumentation for the dra-agents-net
// node plumbing DaemonSet using strictly bounded-cardinality enum labels.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const subsystem = "dra_agents_net"

const (
	// StatusSuccess indicates a DRA or NRI hook handled an agents.net Pod/claim successfully.
	StatusSuccess = "success"
	// StatusFailed indicates a DRA or NRI hook returned an error.
	StatusFailed = "failed"
	// StatusNoop indicates a DRA or NRI hook saw a Pod or claim not managed by dra-agents-net.
	StatusNoop = "noop"
)

var (
	// TunnelsTotal counts intercepted agents.net CONNECT and connect-udp requests
	// forwarded to the upstream proxy.
	// Labels are strictly bounded enums:
	//   transport: tcp | udp
	//   auth_mode: none | mtls | spiffe | pod_certificate | service_account_token
	//   decision:  allow | deny | error
	//   reason:    allowed | malformed | upstream_denied | upstream_auth_failed |
	//              upstream_unavailable | listener_revoked | max_connections
	TunnelsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Subsystem: subsystem,
			Name:      "tunnels_total",
			Help:      "Total agents.net tunnel requests processed by dra-agents-net.",
		},
		[]string{"transport", "auth_mode", "decision", "reason"},
	)

	// ActiveTunnels tracks the number of currently open upstream tunnels on this node.
	ActiveTunnels = promauto.NewGauge(
		prometheus.GaugeOpts{
			Subsystem: subsystem,
			Name:      "active_tunnels",
			Help:      "Current number of active agents.net tunnels forwarded by this node.",
		},
	)

	// ActiveSandboxes tracks the number of sandbox Pods currently plumbed on this node.
	ActiveSandboxes = promauto.NewGauge(
		prometheus.GaugeOpts{
			Subsystem: subsystem,
			Name:      "active_sandboxes",
			Help:      "Current number of sandbox Pods with an active agents.net listener on this node.",
		},
	)

	// DRAPluginRequestsTotal counts DRA kubeletplugin calls.
	// Labels: method (PrepareResourceClaims | UnprepareResourceClaims),
	// status (success | failed | noop).
	DRAPluginRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Subsystem: subsystem,
			Name:      "dra_plugin_requests_total",
			Help:      "Total number of DRA plugin requests processed by dra-agents-net.",
		},
		[]string{"method", "status"},
	)

	// DRAPluginRequestsLatencySeconds measures DRA kubeletplugin call latency.
	DRAPluginRequestsLatencySeconds = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Subsystem: subsystem,
			Name:      "dra_plugin_requests_latency_seconds",
			Help:      "DRA plugin request latency in seconds.",
		},
		[]string{"method"},
	)

	// NRIPluginRequestsTotal counts NRI runtime hook calls.
	// Labels: method (Synchronize | RunPodSandbox | CreateContainer |
	//   StopPodSandbox | RemovePodSandbox),
	// status (success | failed | noop).
	NRIPluginRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Subsystem: subsystem,
			Name:      "nri_plugin_requests_total",
			Help:      "Total number of NRI plugin requests processed by dra-agents-net.",
		},
		[]string{"method", "status"},
	)

	// NRIPluginRequestsLatencySeconds measures NRI runtime hook latency.
	// Buckets align with NRI plugin_request_timeout defaults (2s default, 5s recommended)
	// so operators can spot hooks approaching containerd/CRI-O timeout limits.
	NRIPluginRequestsLatencySeconds = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Subsystem: subsystem,
			Name:      "nri_plugin_requests_latency_seconds",
			Help:      "NRI plugin request latency in seconds.",
			Buckets:   []float64{0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 1.5, 2, 3, 5, 10, 30},
		},
		[]string{"method", "status"},
	)

	// PublishedDevicesTotal tracks the number of DRA devices currently published
	// by this node's ResourceSlice(s) (drops to 0 when unhealthy/withdrawn).
	PublishedDevicesTotal = promauto.NewGauge(
		prometheus.GaugeOpts{
			Subsystem: subsystem,
			Name:      "published_devices_total",
			Help:      "Total number of DRA devices currently published by this node.",
		},
	)

	// LastPublishedTimeSeconds records the Unix timestamp of the last successful
	// ResourceSlice publication by this node.
	LastPublishedTimeSeconds = promauto.NewGauge(
		prometheus.GaugeOpts{
			Subsystem: subsystem,
			Name:      "last_published_time_seconds",
			Help:      "Unix timestamp of the last successful DRA ResourceSlice publication.",
		},
	)

	// NRIPluginDisconnectsTotal counts container runtime closes of an active NRI
	// connection (stub.WithOnClose), such as containerd restarts or request timeouts
	// on runtimes without NRI FailurePolicy support.
	NRIPluginDisconnectsTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Subsystem: subsystem,
			Name:      "nri_plugin_disconnects_total",
			Help:      "Total number of times the container runtime closed its NRI connection to dra-agents-net.",
		},
	)

	// NRIPluginReconnectAttemptsTotal counts retries of the NRI supervision loop.
	// Consecutive failures cap at maxNRIAttempts before exiting, resetting after each
	// successful connection so routine runtime restarts do not crash the driver.
	NRIPluginReconnectAttemptsTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Subsystem: subsystem,
			Name:      "nri_plugin_reconnect_attempts_total",
			Help:      "Total number of times the NRI plugin connection loop has been retried.",
		},
	)

	// PodsMissingPlumbingTotal counts running prepared Pods found during NRI Synchronize
	// without required agents.net mounts or network namespace isolation.
	PodsMissingPlumbingTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Subsystem: subsystem,
			Name:      "pods_missing_plumbing_total",
			Help:      "Total number of times dra-agents-net found a running prepared Pod without required agents.net plumbing or isolation.",
		},
	)

	// TunnelDialDurationSeconds measures upstream tunnel establishment latency.
	TunnelDialDurationSeconds = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Subsystem: subsystem,
			Name:      "tunnel_dial_duration_seconds",
			Help:      "Latency of establishing an authenticated tunnel to the upstream agents.net proxy.",
			Buckets:   []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5},
		},
		[]string{"protocol", "auth_mode"},
	)

	// IngressConnectionsTotal counts host-side HTTP CONNECT ingress attempts into sandbox Pods.
	// Labels are strictly bounded enums:
	//   decision: allow | deny | error
	//   reason:   allowed | malformed | unknown_sandbox | port_denied | not_ready | dial_failed
	IngressConnectionsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Subsystem: subsystem,
			Name:      "ingress_connections_total",
			Help:      "Total dra-agents-net host ingress CONNECT attempts.",
		},
		[]string{"decision", "reason"},
	)
)
