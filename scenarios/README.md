# The Dome: Comprehensive Due Diligence Benchmarks (Containers vs. MicroVMs)

This directory contains executable testbeds, network topologies, and reproducible statistical benchmarks evaluating AI agent isolation technologies across the entire combinatorial space of sandboxes and network interception horizons.

Every scenario executes **real `curl` commands** measuring the complete protocol lifecycle—**DNS lookup, TCP 3-way handshake, TLS 1.3 handshake, and HTTP payload transfer**—against a hermetic, local HTTPS target (`https://test.example.com:9443/ping`). This **eliminates external WAN transit jitter (0ms internet latency)** and isolates the pure architectural cost of the sandboxing primitive.

- **Detailed Empirical Benchmark Data:** [data/results.md](data/results.md)
- **Architectural RFC & Specification:** [RFC-CAPSULES.md](RFC-CAPSULES.md)

---

## 1. Architectural Matrix: Complete Due Diligence Combinations

```
+----------------------------------------------------------------------------------------------------+
|                                    SANDBOX EGRESS TAXONOMY                                         |
+------------------------------------+---------------------------------------------------------------+
| CONTAINER SANDBOXES                | MICROVM SANDBOXES                                             |
+------------------------------------+---------------------------------------------------------------+
| C-1: In-Capsule (tun2connect + UDS)| VM-1: In-Guest (tun2connect + AF_VSOCK)                       |
| C-2: Boundary Intercept (Socket API)| VM-2: Boundary Intercept (AF_VSOCK Stream, Zero Guest TUN)   |
| C-3: Out-of-Capsule (Routed Bridge)| VM-3: Userspace NIC (slirp4netns / gVisor netstack)           |
| C-4: Out-of-Capsule (eBPF Sockmap) | VM-4: Kernel TAP NIC (Dedicated Network Namespace)            |
|                                    | VM-5: Kernel TAP NIC (Host Root Netns - Legacy Pollution)     |
+------------------------------------+---------------------------------------------------------------+
```

### Complete Due Diligence Matrix

| Scenario | Mode / Horizon | Collapse Point | Transport Channel | Host Kernel Exposure | Conntrack Footprint | Wire Identity | Host Pollution Risk |
|:---|:---|:---|:---|:---|:---|:---|:---|
| **C-1** | Container In-Capsule (L3/L4) | Inside Container (`tun2connect`) | Unix Domain Socket | Zero (no veth, no host IP) | 0 entries | Cryptographic `SO_PEERCRED` | 🟢 Zero |
| **C-2** | Container Boundary (L7) | Boundary / libc (pre-packets) | Local Socket Stream | Zero (no packetization) | 0 entries | Authenticated Stream | 🟢 Zero |
| **C-3** | Container Out-Capsule (L2/L3) | Never (Host Kernel NAT) | Routed `veth` + `docker0` | High (kernel netfilter, routing) | >0 (every flow) | Raw IP (Domain Erased) | 🟡 High (veth, IPAM) |
| **C-4** | Container eBPF Sockmap | Kernel Socket Layer | eBPF `sock_ops` / `sk_msg` | Medium (cgroup BPF attached) | 0 entries | Socket attribution | 🟢 Zero (Bypasses IP) |
| **VM-1** | MicroVM In-Guest (L3/L4) | Inside MicroVM (`tun2connect`) | `virtio-vsock` Virtqueues | Zero (no TAP, no host IP) | 0 entries | Cryptographic Peer CID | 🟢 Zero |
| **VM-2** | MicroVM Boundary (L7) | Hypervisor Boundary | `AF_VSOCK` (Zero Guest TUN) | Zero (no TAP, no host IP) | 0 entries | Cryptographic Peer CID | 🟢 Zero |
| **VM-3** | MicroVM Userspace NIC | Host Userspace (`libslirp`) | `virtio-net` -> Userspace | Low kernel, Double TCP Stack | 0 on host kernel | Double TCP Stack | 🟢 Zero Host IPAM |
| **VM-4** | MicroVM TAP Netns | Dedicated Netns Kernel | `virtio-net` -> Netns TAP | Shielded (0 host root TAP) | Isolated in Netns | Shielded TAP | 🟢 Zero Root Netns TAP |
| **VM-5** | MicroVM TAP Host Root | Host Root Netns Kernel | `virtio-net` -> Host Root TAP | Maximum (Host Root TAP) | >0 (Host Conntrack Bloat) | Raw IP (Domain Erased) | 🔴 CRITICAL (Root Bloat) |

---

## 2. Network Topologies & Interception Mechanics

### Container Sandboxes

#### Mode C-1: In-Capsule `tun2connect` (`--network none`)
```
[Agent (curl)] ---> [tun0 (kernel)] ---> [tun2connect (In-Capsule)] ---> (AF_UNIX UDS) ---> [Boundary Proxy] ---> [Target]
      |                    |                         |
      +-- DNS UDP:53 ------+                         |
      |   (Synthetic IP returned: 100.127.255.253)   |
      +-- TCP SYN: 100.127.255.253:9443 -------------+
          (Terminated locally, translated to CONNECT test.example.com:9443)
```
- **Under Test:** Full in-capsule transparent interception without container network interface (`--network none`).
- **Collapse Point:** Inside the container via userspace netstack (`gVisor`).
- **Identity:** Boundary proxy verifies caller UID and PID via Linux `SO_PEERCRED`.

#### Mode C-2: Boundary Intercept (Socket API / Proxy)
```
[Agent (curl)] ---> [Socket API / Proxy Intercept] ---------------------> (Local Stream) ---> [Boundary Proxy] ---> [Target]
(Zero packetization, zero TUN device, direct HTTP CONNECT tunnel)
```
- **Under Test:** Direct stream interception eliminating kernel packetization and netstack translation.
- **Collapse Point:** At the container boundary (socket layer).
- **Identity:** Authenticated boundary proxy channel.

#### Mode C-3: Traditional Routed Bridge (`--network bridge`)
```
[Agent (curl)] ---> [eth0] ---> [veth pair] ---> [docker0 bridge] ---> [Host iptables SNAT] ---> [Target]
(Raw IP packets on host, domain erased at DNS, host conntrack state created)
```
- **Under Test:** Traditional container network interfaces (CNI).
- **Collapse Point:** Never collapsed; routed as IP packets with host NAT.
- **Identity:** Raw IP address. Destination domain is erased on the wire after DNS lookup.

#### Mode C-4: Container eBPF Sockmap (`sock_ops` + `sk_msg`)
```
[Agent (curl)] ---> [Socket connect()] ---> [eBPF sock_ops] ---> [BPF SOCKMAP]
                          |                                             |
                          +---> [sendmsg()] ---> [eBPF sk_msg redirect] +---> [Host Boundary Proxy Socket]
```
- **Under Test:** Kernel socket-level redirection bypassing TCP/IP packetization, veth pairs, and iptables.
- **Collapse Point:** Inside host kernel socket buffers (`sk_buff`).
- **Prerequisites:** Requires root host capabilities (`CAP_BPF`, `CAP_SYS_ADMIN`) and cgroup v2.

---

### MicroVM Sandboxes

#### Mode VM-1: In-Guest `tun2connect` over `virtio-vsock`
```
[Guest Agent (curl)] ---> [Guest tun0] ---> [In-Guest tun2connect] ---> (virtio-vsock) ---> [Host Boundary Proxy] ---> [Target]
                                                     |
                                            [gVisor Netstack]
                                            (Packet -> Stream)
```
- **Under Test:** MicroVM running in-guest `tun2connect` collapsing IP packets into byte streams over `AF_VSOCK`.
- **Collapse Point:** Inside the MicroVM guest.
- **Identity:** Unforgeable hypervisor Context ID (CID) verified by host kernel via `Getpeername(fd)`.

#### Mode VM-2: MicroVM VSOCK at Boundary (Direct Stream / Zero Guest TUN)
```
[Guest Agent (curl)] ---> [Guest VSOCK Forwarder / Client] -------------> (virtio-vsock) ---> [Host Boundary Proxy] ---> [Target]
(Zero in-guest TUN device, zero in-guest netstack packetization, zero synthetic DNS)
```
- **Under Test:** Guest application streaming directly across hypervisor boundary virtqueues without in-guest TUN or userspace netstack.
- **Collapse Point:** At the hypervisor boundary via `AF_VSOCK`.
- **Identity:** Unforgeable hypervisor Context ID (CID) verified by host kernel via `Getpeername(fd)`.
- **Advantage:** Surges throughput to **>600 MB/s** (3.3x over VM-1) and cuts latency to **3.21 ms**.

#### Mode VM-3: Userspace NIC (`slirp4netns` / `libslirp`)
```
[Guest Agent] ---> [virtio-net] ---> (Hypervisor Ring Buffer) ---> [slirp4netns (Host Ring 3)] ---> [Target]
                                                                            |
                                                                   [Double TCP Stack Tax]
                                                                   (Reassembles TCP frames)
```
- **Under Test:** Raw Ethernet frames emitted by guest kernel `virtio-net`, terminated by host userspace TCP/IP stack.
- **Collapse Point:** On host in userspace. Incurs the Double TCP Stack Tax.

#### Mode VM-4: Kernel TAP NIC in Dedicated Network Namespace
```
[Guest Agent] ---> [virtio-net] ---> [Host TAP tap0 (in Dedicated Netns)] ---> [Netns Kernel Routing] ---> [Target]
                                                       |
                                    [Host Root Netns: 0 TAP Devices]
```
- **Under Test:** MicroVM attached to TAP device strictly isolated inside a dedicated network namespace.
- **Collapse Point:** Never (routed kernel IP packets).
- **Host Isolation:** Host root namespace retains **0 TAP devices and 0 host route bloat**.

#### Mode VM-5: Kernel TAP NIC in Host Root Netns (Legacy Architecture)
```
[Guest Agent] ---> [virtio-net] ---> [Host Root TAP (tap0)] ---> [Host Root Routing / iptables] ---> [Target]
                                              |
                          [CRITICAL HOST POLLUTION: TAP Bloat + Conntrack]
```
- **Under Test:** Legacy hypervisors creating TAP interfaces directly in host root namespace.
- **Security & Privilege:** Requires host root `CAP_NET_ADMIN`. Fails for unprivileged users.
- **Host Pollution:** Every VM adds a TAP interface, host routing entry, and tracks flows in host root conntrack.

---

## 3. Empirical Benchmark Results

Measured on Linux (x86_64, 96 vCPUs, 236 GiB RAM).
Workload: Real `curl` executing HTTPS over TLS 1.3 against local `https://test.example.com:9443/ping` (100 flows per scenario across 5 rounds):

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

## 4. Key Architectural Insights

1. **The In-Guest Netstack Tax (VM-1 vs. VM-2 & C-1 vs. C-2):**
   - Running userspace netstack (`tun2connect`) inside the guest or container adds **~1.5 ms** of setup latency (DNS + TCP) and caps streaming throughput to **~180 MB/s** due to packet fragmentation, packet parsing, and TUN context switches.
   - Moving interception to the **Boundary (VM-2 and C-2)** streams raw bytes directly over `AF_VSOCK` or UDS, eliminating TUN device and userspace netstack overhead. Throughput surges to **>600 MB/s (a 3.3x speedup)** and latency drops to **~3.2 ms** (MicroVM) and **~2.6 ms** (Container).
2. **Cryptographic Identity Attribution:**
   - Both **VM-1 and VM-2** preserve unforgeable identity attribution via the hypervisor kernel: `Getpeername(fd)` returns the hardware Context ID (CID). Guest userspace headers cannot spoof this identity.
   - For containers, **C-1 and C-2** leverage Linux kernel `SO_PEERCRED` to authenticate caller UID/PID.
   - By contrast, routed L2/L3 modes (**C-3, VM-4, VM-5**) erase domain identity on the wire, exposing only bare IP addresses.
3. **Host Root Namespace Pollution & Security Boundary:**
   - **VM-4 (Dedicated Netns)** completely shields the host: TAP devices are confined to a private netns, keeping host root TAP count at **0**.
   - **VM-5 (Host Root TAP)** requires full host root `CAP_NET_ADMIN`, risking host interface table explosion, route table churn, and conntrack table exhaustion.

---

## 5. How to Reproduce

To independently run and verify all scenarios:
```bash
git clone https://github.com/aojea/agents.net.git
cd agents.net
./scenarios/benchmark.sh
```
