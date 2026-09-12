# Capsule Networking Scenarios & Empirical Benchmarks

This directory contains executable testbeds and statistical benchmark runners for evaluating AI Agent sandboxing technologies across the three network interception horizons. It produces demonstrable, empirical performance and security data to inform the `agents.net` specification.

- **Detailed Empirical Results:** [data/results.md](data/results.md)

---

## 1. Directory Structure

```
scenarios/
├── 01-container-in-capsule/    # Horizon 1: Container + tun2connect + Unix Domain Socket
│   ├── run.sh                  # 500-sample percentile latency & throughput benchmark inside Docker (--network none)
│   └── test_lpe.sh             # Root privilege escalation, route flush, & header spoofing test
├── 02-container-boundary/      # Horizon 2: Boundary Intercept (Zero TCP math / Direct UDS stream)
│   └── run.sh                  # 500-sample percentile latency & throughput benchmark measuring direct memory stream
├── 03-container-out-capsule/   # Horizon 3: Traditional host CNI (routed veth + bridge)
│   └── run.sh                  # Demonstrates host IPAM allocation, conntrack count, & domain erasure
├── 04-microvm-vsock/           # Horizon 1 (MicroVM): virtio-vsock shared memory virtqueues
│   ├── run.sh                  # AF_VSOCK 500-sample percentile latency & throughput benchmark
│   └── test_vsock_cid.sh       # Hardware hypervisor Context ID (CID) un-spoofable mapping test
├── common/
│   ├── boundary_proxy.go       # High-performance reference boundary proxy with SO_PEERCRED auth
│   └── target_server.go        # Benchmark target server (/ping and /stream?mb=...)
├── benchmark.sh                # Master automated runner executing all scenarios and generating data
└── data/
    └── results.md              # Measured empirical benchmark results with percentiles and CV%
```

---

## 2. Running the Benchmarks

To execute all scenarios and generate the data report:

```bash
./scenarios/benchmark.sh
```

Individual scenarios can also be run independently:

```bash
# 1. Container In-Capsule (tun2connect over UDS)
./scenarios/01-container-in-capsule/run.sh
./scenarios/01-container-in-capsule/test_lpe.sh

# 2. Container Boundary Intercept (Direct Stream)
./scenarios/02-container-boundary/run.sh

# 3. Container Out-of-Capsule (Routed veth / Bridge)
./scenarios/03-container-out-capsule/run.sh

# 4. MicroVM VSOCK (virtio-vsock)
./scenarios/04-microvm-vsock/run.sh
./scenarios/04-microvm-vsock/test_vsock_cid.sh
```

---

## 3. Empirical Findings Summary

The automated benchmark suite executes 500 requests per scenario across 5 independent rounds (with a 10-request warmup) and 3 throughput trials (50 MB streams):

| Scenario | Interception Horizon | Transport Channel | p50 (Median) | p90 | p95 | p99 (Tail) | Mean ± StdDev | Throughput (MB/s) | Host IPAM Needed? | Wire Identity |
|---|---|---|---|---|---|---|---|---|:---:|---|
| **1. Container In-Capsule** | In-Capsule (tun2connect) | Unix Domain Socket | **0.96 ms** | 1.13 ms | 1.26 ms | 2.66 ms | 1.01 ± 0.28 ms | **165.17 MB/s** | 🟢 None (0 IPs) | 🟢 Named `CONNECT` |
| **2. Container Boundary** | At Boundary (Direct Stream) | Unix Domain Socket | **0.21 ms** | 0.27 ms | 0.31 ms | 0.57 ms | 0.23 ± 0.14 ms | **3645.47 MB/s** | 🟢 None (0 IPs) | 🟢 Named `CONNECT` |
| **3. Container Out-Capsule** | Out-of-Capsule (Host CNI) | Routed veth + Bridge | **0.25 ms** | 0.31 ms | 0.34 ms | 0.37 ms | 0.26 ± 0.09 ms | **936.06 MB/s** | ❌ 1 IP/Capsule | ❌ Raw IP (DNS erased) |
| **4. MicroVM VSOCK** | In-Capsule (VSOCK IPC) | virtio-vsock | **0.31 ms** | 0.37 ms | 0.39 ms | 0.47 ms | 0.32 ± 0.05 ms | **4071.61 MB/s** | 🟢 None (0 IPs) | 🟢 Named `CONNECT` |

### Key Architectural Takeaways:

1. **The In-Guest Packetization Tax (Horizon 1 vs Horizon 2):**
   - Eliminating guest-side TCP checksumming and TUN buffer copy yields a **4.6x median latency reduction** (0.96 ms → 0.21 ms) and a **22.1x throughput increase** (165 MB/s → 3645 MB/s).
   - Tail latency ($p_{99}$) drops from 2.66 ms to 0.57 ms (**4.7x tail reduction**).
   - This empirically confirms that for Containers and gVisor, **Horizon 2 (Boundary Intercept) is the ultimate performance end-state**.

2. **Why MicroVMs Favor VSOCK Over Boundary `vhost-user-net`:**
   - MicroVMs over `virtio-vsock` achieve **4071.61 MB/s** with **0.31 ms** latency.
   - VSOCK streams directly over shared memory virtqueues. In contrast, `vhost-user-net` forces the guest kernel to construct full Ethernet/IP/TCP frames and the host daemon to unpack them (imposing a double TCP tax on host CPU).

3. **Why Horizon 3 (Host Routed CNI) Must Be Abandoned:**
   - **Loss of Domain Identity:** DNS resolution inside the guest translates names to raw IPs (`104.20.23.154`) before crossing the veth interface, making host firewall domain allowlists impossible without fragile DNS snooping.
   - **Host IPAM & Conntrack Exhaustion:** Requires active IP allocations and bloats host netfilter conntrack tables.
   - **Fail-Open Risk:** Misconfiguring host iptables rules exposes host network routes directly.

4. **Security & LPE Verification:**
   - **Route Tampering:** Flushing routes inside an In-Capsule container (`ip route flush dev tun0`) results in immediate `FAIL-CLOSED` connection refusal. With no external NIC, there is no escape path.
   - **Header Spoofing:** When a compromised guest sends forged headers (`X-Capsule-ID: attacker-compromised-agent`), the boundary proxy ignores them and extracts verified identity directly from `SO_PEERCRED` (PID/UID) or hypervisor Context ID (CID).

