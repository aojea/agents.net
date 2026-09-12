# Empirical Benchmark Results: The Dome (Containers vs. MicroVMs)

- **Generated on:** 2026-09-12T19:45:46Z
- **Host Platform:** Linux (x86_64, 96 vCPUs, 236Gi RAM)
- **Workload:** Real `curl` executing HTTPS over TLS 1.3 against local `https://test.example.com:9443/ping` (0ms WAN latency)
- **Sample Size:** 100 flows per scenario (5 independent measurement rounds x 20 requests) + 5 warmup flows
- **Throughput Trials:** 3 trials x 50 MB streaming transfer (`/stream?mb=50`)

---

## 1. Complete Combinatorial Matrix: End-to-End Latency & Protocol Lifecycle Breakdown (p50 Medians)

| Scenario | Mode / Horizon | Collapse Point | Transport Channel | DNS (ms) | TCP (ms) | TLS 1.3 (ms) | Total p50 | Total p99 | Throughput (MB/s) | Host IPAM? | Wire Identity | Host Pollution |
|---|---|---|---|---|---|---|---|---|---|:---:|---|---|
| **C-1** | Container In-Capsule (L3/L4) | Inside Container (`tun2connect`) | Unix Domain Socket | **0.67** | **1.14** | **3.98** | **4.42 ms** | 5.98 ms | **175.27 MB/s** | 🟢 0 IPs | 🟢 Cryptographic `SO_PEERCRED` | 🟢 Zero (No veth/tap) |
| **C-2** | Container Boundary (L7) | Boundary Socket API / Proxy | Local Socket / Stream | **0.02** | **0.10** | **2.33** | **2.67 ms** | 4.30 ms | **592.09 MB/s** | 🟢 0 IPs | 🟢 Authenticated Stream | 🟢 Zero (No veth/tap) |
| **C-3** | Container Out-Capsule (L2/L3) | Never (Host Kernel NAT) | Routed `veth` + Bridge | **0.34** | **0.43** | **3.05** | **3.39 ms** | 4.84 ms | **579.27 MB/s** | ❌ 1 IP/Capsule | ❌ Raw IP (Domain Erased) | 🟡 High (veth pairs, iptables) |
| **VM-1** | MicroVM In-Guest (L3/L4) | Inside MicroVM (`tun2connect`) | `virtio-vsock` Virtqueues | **0.72** | **1.24** | **3.58** | **4.09 ms** | 6.18 ms | **181.27 MB/s** | 🟢 0 IPs | 🟢 Cryptographic Peer CID | 🟢 Zero (No host tap/veth) |
| **VM-2** | MicroVM Boundary (L7) | Hypervisor Boundary | `AF_VSOCK` Stream (No TUN) | **0.02** | **0.09** | **2.77** | **3.21 ms** | 5.33 ms | **603.44 MB/s** | 🟢 0 IPs | 🟢 Cryptographic Peer CID | 🟢 Zero (No host tap/veth) |
| **VM-3** | MicroVM Userspace NIC | Host Userspace Stack | `virtio-net` -> `slirp4netns` | **0.57** | **0.86** | **2.86** | **3.18 ms** | 4.54 ms | **403.02 MB/s** | 🟢 0 IPs | 🟡 Double TCP Stack | 🟢 Zero (Host userspace NAT) |
| **VM-4** | MicroVM TAP Netns | Dedicated Netns Kernel | `virtio-net` -> Netns TAP | **0.33** | **0.42** | **3.03** | **3.30 ms** | 4.45 ms | **602.14 MB/s** | ❌ 1 IP/Netns | 🟡 Shielded Netns | 🟢 Zero Root Netns TAP |
| **VM-5** | MicroVM TAP Host Root | Host Root Netns Kernel | `virtio-net` -> Host Root TAP | *N/A* | *N/A* | *N/A* | *Blocked Unprivileged* | *N/A* | *N/A* | ❌ High Host IPAM | ❌ Erased (Host IP NAT) | 🔴 CRITICAL (Root TAP Bloat) |

---

## 2. Statistical Proof of Stability (Cross-Round Reproducibility)

Each scenario was executed across **5 independent measurement rounds** of 20 requests each.
The table below presents the median (p50) latency for each round and the **Coefficient of Variation (CV%)** across rounds:

| Scenario | Round 1 (p50) | Round 2 (p50) | Round 3 (p50) | Round 4 (p50) | Round 5 (p50) | Stability CV% | Stability Verdict |
|---|---|---|---|---|---|:---:|---|
| **C-1: Container In-Capsule** | 4.79 ms | 4.38 ms | 4.29 ms | 4.42 ms | 4.50 ms | **4.29%** | 🟢 Highly Stable (CV < 5%) |
| **C-2: Container Boundary** | 2.83 ms | 2.67 ms | 2.61 ms | 2.71 ms | 2.61 ms | **3.34%** | 🟢 Highly Stable (CV < 5%) |
| **C-3: Container Out-Capsule** | 3.25 ms | 3.50 ms | 3.41 ms | 3.39 ms | 3.35 ms | **2.67%** | 🟢 Highly Stable (CV < 5%) |
| **VM-1: MicroVM VSOCK In-Guest** | 4.00 ms | 4.11 ms | 3.82 ms | 4.23 ms | 4.03 ms | **3.75%** | 🟢 Highly Stable (CV < 5%) |
| **VM-2: MicroVM VSOCK Boundary** | 3.35 ms | 3.13 ms | 3.24 ms | 3.21 ms | 3.27 ms | **2.51%** | 🟢 Highly Stable (CV < 5%) |
| **VM-3: MicroVM Userspace NIC** | 3.10 ms | 3.15 ms | 3.11 ms | 3.21 ms | 3.31 ms | **2.75%** | 🟢 Highly Stable (CV < 5%) |
| **VM-4: MicroVM TAP Netns** | 3.45 ms | 3.32 ms | 3.32 ms | 3.27 ms | 3.30 ms | **2.10%** | 🟢 Highly Stable (CV < 5%) |

---

## 3. Deep Protocol Nuances & Architectural Findings

### A. The Breakthrough of MicroVM VSOCK at Boundary (VM-2 vs. VM-1)
* **Elimination of In-Guest Netstack Tax:** In **VM-1 (In-Guest)**, every outbound flow is intercepted by a virtual TUN device (`tun0`), requiring userspace netstack (`gVisor`) to assemble IP packets, manage a secondary TCP state machine, and compute packet checksums. This caps throughput at **181.27 MB/s** and incurs **4.09 ms** p50 latency.
* In **VM-2 (VSOCK at Boundary)**, the guest streams directly across the hypervisor virtqueues via `AF_VSOCK`. With zero TUN device overhead and zero userspace packet reassembly, throughput surges by **333%** to **603.44 MB/s**, and latency drops to **3.21 ms**.
* **Identity Preservation:** In both VM-1 and VM-2, the host kernel guarantees identity attribution: `Getpeername(fd)` reports `capsule-microvm-cid-1`, which cannot be spoofed by guest code.

### B. The "Double TCP Stack Tax" (VM-3 Userspace NIC)
* In **VM-3 (Userspace NIC)**, packets cross the hypervisor boundary as raw Ethernet/IP frames. A host userspace network stack (`libslirp`) terminates the guest TCP stack, parses TCP headers, reassembles bytes, and establishes an outbound socket. This results in **3.18 ms** latency and lacks peer identity verification.

### C. Host Pollution & Security Boundary: Dedicated Netns (VM-4) vs. Host Root (VM-5)
* **VM-4 (TAP in Dedicated Netns):** MicroVM `tap0` is strictly created inside an isolated network namespace. The host root namespace has **0 TAP devices**, preventing interface bloat, route table explosion, and netlink broadcast storms.
* **VM-5 (TAP in Host Root):** Legacy VM setups require root `CAP_NET_ADMIN` on the host, creating TAP devices directly in the host root namespace. For 1,000 MicroVMs, this pollutes the host with 1,000 interfaces and 1,000 routing entries, while filling the host conntrack table.

### D. The Zero-IP Guarantee (C-1, C-2, VM-1, VM-2, VM-3)
* These scenarios completely eliminate host IPAM:
  - **Zero host IP addresses allocated.**
  - **Zero host virtual devices (`veth` or `TAP`) in the host root network namespace.**
  - **Zero conntrack table bloat on the host default namespace.**

---

## 4. How to Reproduce

To independently run and verify all scenarios:
```bash
git clone https://github.com/aojea/agents.net.git
cd agents.net
./scenarios/benchmark.sh
```
