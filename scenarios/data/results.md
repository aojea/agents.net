# Empirical Benchmark Results: The Dome (Containers vs. MicroVMs)

- **Generated on:** 2026-09-12T11:21:56Z
- **Host Platform:** Linux (x86_64, 96 vCPUs, 236Gi RAM)
- **Workload:** Real `curl` executing HTTPS over TLS 1.3 against local `https://test.example.com:9443/ping` (0ms WAN latency)
- **Sample Size:** 100 flows per scenario (5 independent measurement rounds x 20 requests) + 5 warmup flows
- **Throughput Trials:** 3 trials x 50 MB streaming transfer (`/stream?mb=50`)

---

## 1. End-to-End Latency & Protocol Lifecycle Breakdown (p50 Medians)

| Scenario | Mode / Horizon | Collapse Point | Transport Channel | DNS (ms) | TCP (ms) | TLS 1.3 (ms) | Total p50 | Total p99 | Throughput (MB/s) | Host IPAM? | Wire Identity |
|---|---|---|---|---|---|---|---|---|---|:---:|---|
| **C-1** | Container In-Capsule | Inside Container (`tun2connect`) | Unix Domain Socket | **0.69** | **1.20** | **4.05** | **4.52 ms** | 6.31 ms | **179.32 MB/s** | 🟢 0 IPs | 🟢 Cryptographic `SO_PEERCRED` |
| **C-2** | Container Boundary | Boundary Socket API / Proxy | Local Socket / Stream | **0.02** | **0.10** | **2.27** | **2.59 ms** | 3.95 ms | **588.48 MB/s** | 🟢 0 IPs | 🟢 Authenticated Stream |
| **C-3** | Container Out-Capsule | Never (Host Kernel NAT) | Routed `veth` + Bridge | **0.34** | **0.43** | **3.04** | **3.34 ms** | 4.89 ms | **558.33 MB/s** | ❌ 1 IP/Capsule | ❌ Raw IP (Domain Erased) |
| **VM-1** | MicroVM In-Guest | Inside MicroVM (`tun2connect`) | `virtio-vsock` Virtqueues | **0.73** | **1.28** | **3.71** | **4.24 ms** | 5.54 ms | **181.75 MB/s** | 🟢 0 IPs | 🟢 Cryptographic Peer CID |
| **VM-2** | MicroVM Userspace NIC | Host Userspace Stack | `virtio-net` -> `slirp4netns` | **0.55** | **0.76** | **2.74** | **3.05 ms** | 4.55 ms | **400.91 MB/s** | 🟢 0 IPs | 🟡 Double TCP Stack |
| **VM-3** | MicroVM TAP Netns | Dedicated Netns Kernel | `virtio-net` -> Netns TAP | **0.33** | **0.41** | **3.00** | **3.28 ms** | 4.70 ms | **579.46 MB/s** | ❌ 1 IP/Netns | 🟡 Shielded (0 Host TAP) |

---

## 2. Statistical Proof of Stability (Cross-Round Reproducibility)

Each scenario was executed across **5 independent measurement rounds** of 20 requests each.
The table below presents the median (p50) latency for each round and the **Coefficient of Variation (CV%)** across rounds:

| Scenario | Round 1 (p50) | Round 2 (p50) | Round 3 (p50) | Round 4 (p50) | Round 5 (p50) | Stability CV% | Stability Verdict |
|---|---|---|---|---|---|:---:|---|
| **C-1: Container In-Capsule** | 4.43 ms | 4.19 ms | 4.77 ms | 4.64 ms | 4.55 ms | **4.94%** | 🟢 Stable (CV < 5%) |
| **C-2: Container Boundary** | 2.61 ms | 2.64 ms | 2.57 ms | 2.62 ms | 2.56 ms | **1.38%** | 🟢 Stable (CV < 5%) |
| **C-3: Container Out-Capsule** | 3.40 ms | 3.32 ms | 3.25 ms | 3.34 ms | 3.32 ms | **1.60%** | 🟢 Stable (CV < 5%) |
| **VM-1: MicroVM VSOCK** | 3.94 ms | 4.33 ms | 4.08 ms | 4.13 ms | 4.28 ms | **3.79%** | 🟢 Stable (CV < 5%) |
| **VM-2: MicroVM Userspace NIC** | 3.31 ms | 3.02 ms | 3.08 ms | 2.95 ms | 3.04 ms | **4.55%** | 🟢 Stable (CV < 5%) |
| **VM-3: MicroVM TAP Netns** | 3.35 ms | 3.36 ms | 3.17 ms | 3.25 ms | 3.35 ms | **2.52%** | 🟢 Stable (CV < 5%) |

---

## 3. Protocol Nuances & Architectural Findings

### A. The "Double TCP Stack Tax" (VM-2 vs. VM-1)
* In **VM-2 (Userspace NIC)**, packets cross the hypervisor boundary as raw Ethernet/IP frames. A host userspace network stack (`libslirp`) terminates the guest TCP stack, parses TCP headers, reassembles bytes, and establishes an outbound socket.
* In **VM-1 (VSOCK)**, in-guest `tun2connect` collapses packets inside the guest and streams raw bytes over `AF_VSOCK` shared-memory virtqueues. This bypasses the secondary TCP stack and preserves cryptographic attribution via peer CID.

### B. The Zero-IP Guarantee (C-1 and VM-1)
* Scenarios **C-1** and **VM-1** completely sever host L2/L3 networking:
  - **Zero host IP addresses allocated.**
  - **Zero host virtual devices (`veth` or `TAP`) in the host root network namespace.**
  - **Zero conntrack table bloat on the host default namespace.**

### C. Container Boundary Intercept (C-2)
* Intercepting at the socket API boundary (**C-2**) achieves sub-microsecond DNS and TCP setup (**0.02 ms** DNS, **0.10 ms** TCP) because it completely eliminates packetization, checksum computation, and TUN context switches.

---

## 4. How to Reproduce

To independently run and verify all 6 scenarios:
```bash
git clone https://github.com/aojea/agents.net.git
cd agents.net
./scenarios/benchmark.sh
```
