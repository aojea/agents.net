# The Dome: Empirical Network Interception Benchmarks (Containers vs. MicroVMs)

This directory contains executable testbeds and reproducible statistical benchmarks evaluating AI agent isolation technologies across the spectrum of network interception horizons.

Every scenario runs **real `curl` commands** executing the complete protocol lifecycle—**DNS lookup, TCP 3-way handshake, TLS 1.3 handshake, and HTTP payload transfer**—against a hermetic, local HTTPS target (`https://test.example.com:9443/ping`). This **eliminates external WAN transit jitter (0ms internet latency)** and isolates the pure architectural cost of the sandboxing primitive.

- **Detailed Empirical Benchmark Data:** [data/results.md](data/results.md)
- **Architectural RFC & Specification:** [RFC-CAPSULES.md](RFC-CAPSULES.md)

---

## 1. Architectural Matrix: The 6 Dome Scenarios

```
+----------------------------------------------------------------------------------------------------+
|                                    SANDBOX EGRESS TAXONOMY                                         |
+------------------------------------+---------------------------------------------------------------+
| CONTAINER SANDBOXES (3 MODES)      | MICROVM SANDBOXES (3 MODES)                                   |
+------------------------------------+---------------------------------------------------------------+
| C-1: In-Capsule (tun2connect + UDS)| VM-1: In-Guest (tun2connect + AF_VSOCK)                       |
| C-2: Boundary Intercept (Socket API)| VM-2: Userspace NIC (slirp4netns / gVisor netstack)           |
| C-3: Out-of-Capsule (Routed Bridge)| VM-3: Kernel TAP NIC (Dedicated Network Namespace)            |
+------------------------------------+---------------------------------------------------------------+
```

### Comparative Summary

| Scenario | Mode | Collapse Point | Transport Channel | Host Kernel Exposure | Conntrack Footprint | Wire Identity |
|:---|:---|:---|:---|:---|:---|:---|
| **C-1** | Container In-Capsule | Inside Container (`tun2connect`) | Unix Domain Socket | Zero (no veth, no host IP) | 0 entries | Cryptographic `SO_PEERCRED` |
| **C-2** | Container Boundary | Boundary / libc (pre-packets) | Local Socket Stream | Zero (no packetization) | 0 entries | Authenticated Stream |
| **C-3** | Container Out-Capsule | Never (Host Kernel NAT) | Routed `veth` + `docker0` | High (kernel netfilter, routing) | >0 (every flow) | Raw IP (Domain Erased) |
| **VM-1** | MicroVM In-Guest | Inside MicroVM (`tun2connect`) | `virtio-vsock` Virtqueues | Zero (no TAP, no host IP) | 0 entries | Cryptographic Peer CID |
| **VM-2** | MicroVM Userspace NIC| Host Userspace (`libslirp`) | `virtio-net` -> Userspace | Low kernel, Double TCP Stack | 0 on host kernel | Double TCP Stack |
| **VM-3** | MicroVM TAP Netns | Dedicated Netns Kernel | `virtio-net` -> Netns TAP | Shielded (0 host root TAP) | Isolated in Netns | Shielded TAP |

---

## 2. Directory Structure

```
scenarios/
├── 01-container-in-capsule/    # C-1: Container + tun2connect + Unix Domain Socket
│   ├── run.sh                  # 100-flow real HTTPS curl benchmark inside Docker (--network none)
│   └── test_lpe.sh             # Privilege escalation, route flush, & header spoofing test
├── 02-container-boundary/      # C-2: Boundary Intercept (Socket API / HTTP CONNECT Proxy)
│   └── run.sh                  # 100-flow real HTTPS curl benchmark via direct stream socket
├── 03-container-out-capsule/   # C-3: Traditional host CNI (routed veth + bridge)
│   └── run.sh                  # Demonstrates host IPAM allocation, conntrack delta, & domain erasure
├── 04-microvm-vsock/           # VM-1: MicroVM in-guest tun2connect + virtio-vsock
│   ├── run.sh                  # 100-flow real HTTPS curl benchmark over AF_VSOCK
│   └── test_vsock_cid.sh       # Hardware hypervisor Context ID (CID) un-spoofable mapping test
├── 05-microvm-userspace-nic/   # VM-2: MicroVM Userspace NIC (slirp4netns / libslirp)
│   └── run.sh                  # Demonstrates double TCP stack tax and userspace frame parsing
├── 06-microvm-tap-netns/       # VM-3: MicroVM TAP NIC in Dedicated Network Namespace
│   └── run.sh                  # Encloses TAP device strictly in dedicated netns (0 host pollution)
├── common/
│   ├── boundary_proxy.go       # Boundary proxy supporting UDS, TCP, and AF_VSOCK listeners
│   ├── target_server.go        # Local TLS 1.3 server with automatic self-signed certs (/ping, /stream)
│   └── benchmark_client.py     # Standardized curl runner computing DNS, TCP, TLS, and total percentiles
├── benchmark.sh                # Master automated runner executing all 6 scenarios
└── data/
    └── results.md              # Measured empirical benchmark results with percentiles and CV%
```

---

## 3. Network Topologies & Interception Mechanics

### Container Modes

#### Mode C-1: In-Capsule `tun2connect` (`--network none`)
```
[Agent (curl)] ---> [tun0 (kernel)] ---> [tun2connect (In-Capsule)] ---> (AF_UNIX UDS) ---> [Boundary Proxy] ---> [Target]
      |                    |                         |
      +-- DNS UDP:53 ------+                         |
      |   (Synthetic IP returned: 100.64.0.1)        |
      +-- TCP SYN: 100.64.0.1:9443 ------------------+
          (Terminated locally, translated to CONNECT test.example.com:9443)
```

#### Mode C-2: Boundary Intercept (Socket API / eBPF / Proxy)
```
[Agent (curl)] ---> [Socket API / Proxy Intercept] ---------------------> (Local Stream) ---> [Boundary Proxy] ---> [Target]
(Zero packetization, zero TUN device, direct HTTP CONNECT tunnel)
```

#### Mode C-3: Traditional Routed Bridge (`--network bridge`)
```
[Agent (curl)] ---> [eth0] ---> [veth pair] ---> [docker0 bridge] ---> [Host iptables SNAT] ---> [Target]
(Raw IP packets on host, domain erased at DNS, host conntrack state created)
```

### MicroVM Modes

#### Mode VM-1: In-Guest `tun2connect` over `virtio-vsock`
```
[Guest Agent] ---> [Guest tun0] ---> [In-Guest tun2connect] ---> (AF_VSOCK Virtqueue) ---> [Host Boundary Proxy] ---> [Target]
(Zero raw IP packets cross the hypervisor boundary. Boundary proxy attributes identity via kernel Peer CID)
```

#### Mode VM-2: Userspace NIC (`slirp4netns` / `gvisor-tap-vsock`)
```
[Guest Agent] ---> [virtio-net] ---> (Hypervisor Ring Buffer) ---> [slirp4netns (Host Ring 3)] ---> [Target]
                                                                            |
                                                                   [Double TCP Stack Tax]
                                                                   (Reassembles TCP frames)
```

#### Mode VM-3: Kernel TAP NIC in Dedicated Network Namespace
```
[Guest Agent] ---> [virtio-net] ---> [Host TAP tap0 (in Dedicated Netns)] ---> [Netns Kernel Routing] ---> [Target]
                                                       |
                                    [Host Root Netns: 0 TAP Devices]
```

---

## 4. Empirical Benchmark Results

Measured on Linux (x86_64, 96 vCPUs, 236 GiB RAM).
Workload: Real `curl` executing HTTPS over TLS 1.3 against local `https://test.example.com:9443/ping`:

| Scenario | Mode / Horizon | Collapse Point | Transport Channel | DNS (ms) | TCP (ms) | TLS 1.3 (ms) | Total p50 | Total p99 | Throughput (MB/s) | Host IPAM? | Wire Identity |
|---|---|---|---|---|---|---|---|---|---|:---:|---|
| **C-1** | Container In-Capsule | Inside Container (`tun2connect`) | Unix Domain Socket | **0.69** | **1.20** | **4.05** | **4.52 ms** | 6.31 ms | **179.32 MB/s** | 🟢 0 IPs | 🟢 Cryptographic `SO_PEERCRED` |
| **C-2** | Container Boundary | Boundary Socket API / Proxy | Local Socket / Stream | **0.02** | **0.10** | **2.27** | **2.59 ms** | 3.95 ms | **588.48 MB/s** | 🟢 0 IPs | 🟢 Authenticated Stream |
| **C-3** | Container Out-Capsule | Never (Host Kernel NAT) | Routed `veth` + Bridge | **0.34** | **0.43** | **3.04** | **3.34 ms** | 4.89 ms | **558.33 MB/s** | ❌ 1 IP/Capsule | ❌ Raw IP (Domain Erased) |
| **VM-1** | MicroVM In-Guest | Inside MicroVM (`tun2connect`) | `virtio-vsock` Virtqueues | **0.73** | **1.28** | **3.71** | **4.24 ms** | 5.54 ms | **181.75 MB/s** | 🟢 0 IPs | 🟢 Cryptographic Peer CID |
| **VM-2** | MicroVM Userspace NIC | Host Userspace Stack | `virtio-net` -> `slirp4netns` | **0.55** | **0.76** | **2.74** | **3.05 ms** | 4.55 ms | **400.91 MB/s** | 🟢 0 IPs | 🟡 Double TCP Stack |
| **VM-3** | MicroVM TAP Netns | Dedicated Netns Kernel | `virtio-net` -> Netns TAP | **0.33** | **0.41** | **3.00** | **3.28 ms** | 4.70 ms | **579.46 MB/s** | ❌ 1 IP/Netns | 🟡 Shielded (0 Host TAP) |

### Key Architectural Takeaways:
1. **The In-Guest Packetization Tax (C-1 vs. C-2):**
   - Intercepting at the socket API layer (C-2) achieves **2.59 ms** p50 latency vs **4.52 ms** for C-1.
   - Eliminating in-guest TCP packetization, checksumming, and TUN buffer context switches yields a **1.7x latency improvement** and a **3.3x throughput increase** (179 MB/s → 588 MB/s).
2. **MicroVM VSOCK vs. Userspace NIC (VM-1 vs. VM-2):**
   - In VM-2 (`slirp4netns`), raw Ethernet frames cross the hypervisor boundary, incurring the **Double TCP Stack Tax** where host userspace must parse TCP headers and reassemble streams.
   - In VM-1, in-guest `tun2connect` collapses traffic inside the guest and streams raw bytes over `AF_VSOCK` virtqueues, guaranteeing zero host L2/L3 exposure and unforgeable peer CID attribution.
3. **MicroVM Host Pollution Shielding (VM-3):**
   - In VM-3, TAP devices and kernel routes are strictly confined to a dedicated, isolated network namespace. The host root network namespace retains **0 TAP devices and 0 route bloat**.

---

## 5. How to Reproduce

```bash
# Clone repository
git clone https://github.com/aojea/agents.net.git
cd agents.net

# Run automated master benchmark across all 6 scenarios
./scenarios/benchmark.sh
```
