# agents.net — Kubernetes Networking for the Agentic Era

Kubernetes needs to evolve for agentic workloads. Spinning out of the cross-SIG discussion in [CNCF Maintainer Summit #126](https://github.com/cncf/maintainer-summit/discussions/126) (*Evolving Kubernetes for Agentic Workloads: Rethinking the Pod and Node Boundary*), `agents.net` is the standalone reference implementation exploring what Kubernetes networking should look like for autonomous AI agents: Pod plumbing without a CNI dependency, a host-side userspace network stack wired through file descriptors, Virtual DNS and forwarding hooks to Policy Enforcement Points (PEPs), mandatory mTLS on network hops, and IP-less inbound delivery aligned with **GAIA** (Gateway API), [`agent-sandbox`](https://github.com/kubernetes-sigs/agent-sandbox), **Agent Substrate**, and **OpenShell**.

Read the full architecture vision in [docs/architecture.md](docs/architecture.md).

---

## Why This Exists

Kubernetes was built around a simple premise: every Pod attaches to a flat cluster network through a CNI plugin and gets a routable Pod IP. That worked well for microservices, but autonomous agents run untrusted generated code, churn at high density, and spend most of their time idle waiting on models or tools. Pushing that traffic through host-kernel `veth` interfaces exposes Linux TCP/IP and `nf_tables` to untrusted packets (forcing node reboots for kernel fixes), burns cluster IPAM space, breaks IP-based firewalls behind CDNs, and leaves credentials exposed whenever a sandbox is compromised.

After several years of industry experimentation, low-level agent networking is settling on **HTTP `CONNECT` proxies talking to Policy Enforcement Points (PEPs)**. We split the architecture cleanly into two tiers kept in sync over that standard, mesh-compatible interface:

- **Tier 1 — Agent Low-Level Networking (SIG Network core):** Accommodates existing Pod networking so less demanding platforms can adopt `agent-sandbox` and GAIA right away, while letting the optimized confined userspace stack evolve free of legacy Pod-IP, IPAM, `Service`, and `EndpointSlice` constraints (DRA + NRI + KEP-6313 `spec.podNetwork: Isolated`, file descriptors as capability and privilege boundaries, unprivileged pluggable userspace stack, and Virtual DNS / PEP forwarding / IP-less inbound hooks).
- **Tier 2 — Policy Enforcement Points and Agentic Gateways (delegated to GAIA under Gateway API):** Off-sandbox DNS and anti-SSRF, L7/MCP/A2A policy, inference routing, credential injection, auditing, and inbound routing — compatible with existing meshes (Envoy, Istio HBONE) and agent platforms ([Agent Substrate](https://github.com/agent-substrate/substrate), [OpenShell](https://github.com/NVIDIA/OpenShell), `agent-sandbox`).

Rather than bending the core Kubernetes network model, SIG Network has built these composable primitives step by step: starting the **Kubernetes Network Driver** effort at the **Contributor Summit in Paris (2024)**, proving DRA + NRI with [DRANET](https://github.com/kubernetes-sigs/dranet) and [KEP-4817](https://github.com/kubernetes/enhancements/issues/4817) for AI/ML fabrics, and adding [KEP-6313 (`spec.podNetwork: Isolated`)](https://github.com/kubernetes/enhancements/issues/6313) so Pods can opt out of the default cluster network completely.

This project follows the same SIG Network philosophy behind `kube-proxy`, `kindnet`, [`kube-network-policies`](https://github.com/kubernetes-sigs/kube-network-policies), and [`DRANET`](https://github.com/kubernetes-sigs/dranet): keep core small, define clean interfaces for the ecosystem to build on, and back them with a lean upstream reference implementation so developers can iterate fast, users can try the architecture today, and foundational plumbing does not fracture into incompatible proprietary stacks.

---

## Evolution of the Thinking

The full git history is kept intact so you can follow how earlier experiments led to this Kubernetes architecture (all earlier standalone prototypes remain browsable at commit [`11d845b`](https://github.com/aojea/agents.net/tree/11d845b)):

1. **Capability channels outside Kubernetes (`demo/`, `scenarios/`, `conformance/` in [`11d845b`](https://github.com/aojea/agents.net/tree/11d845b)):** We started by stripping direct networking out of `--network none` containers and Firecracker/QEMU microVMs, replacing raw routes with Unix socket / `vsock` channels and standard HTTP `CONNECT` framing to a PEP (`connect-proxy`, Envoy). That proved fail-closed hostname policy, PEP-side DNS, and off-sandbox credentials end to end.
2. **Standalone Kubernetes driver without CNI ([PR #18](https://github.com/aojea/agents.net/pull/18)–[PR #21](https://github.com/aojea/agents.net/pull/21)):** We brought the model into Kubernetes as a DRA (`DRAConsumableCapacity`) + NRI node driver (`dra-agents-net`) with mandatory mTLS (`SPIFFE`, KEP-4317 `PodCertificate`, X.509) and IP-less ingress discovery. Running real agent workloads quickly showed the limits of both explicit proxies (unmodified tools ignore `HTTP_PROXY`) and in-Pod TUN sidecars (privileged network code and extra containers inside every tenant Pod).
3. **Host-side TUN without sidecars ([PR #22](https://github.com/aojea/agents.net/pull/22)):** Moving the userspace TCP/IP stack (`tun2connect`) and synthetic DNS (`198.18.0.0/15`, `100::/64`) onto the host left only a persistent `tun0` interface and a read-only `/etc/resolv.conf` inside the Pod. Sandboxes run non-root with `capabilities.drop: ["ALL"]`, zero sidecars, and zero direct network access while unmodified TCP, UDP, and DNS apps work transparently.
4. **Holistic agentic networking for SIG Network and GAIA (current direction):** Pulling those pieces together in [docs/architecture.md](docs/architecture.md): standalone CNI-less Pod plumbing paired with `spec.podNetwork: Isolated`, strict host privilege separation passing `tunFD` and egress FDs (`SCM_RIGHTS`) to an unprivileged pluggable userspace network stack (supporting both multi-tenant and multi-single-tenant workers), explicit Virtual DNS and PEP forwarding hooks, and direct compatibility with **GAIA** (Gateway API), **`agent-sandbox`**, **Agent Substrate**, and **OpenShell**.

---

## Architecture at a Glance

```text
+-------------------------------------------------------------------+
| 1. Isolated Sandbox Pod (Zero Caps, No Sidecar, No Secrets)       |
|    No direct route out (KEP-6313 PodNetworkIsolated or CNI).      |
|    Only lo + persistent tun0 + ro /etc/resolv.conf.               |
+-------------------------------------------------------------------+
                                 |
                    raw L3 packets via tunFD
                    (off host kernel TCP/IP)
                                 v
+-------------------------------------------------------------------+
| 2. Standalone Node Driver (dra-agents-net: DRA + NRI, No CNI)     |
|    - Userspace Network Stack + Virtual DNS & Forwarding hooks     |
|      (gVisor netstack built-in; pluggable BYOS worker model)      |
|    - Strips untrusted headers, attaches node-attested identity,   |
|      and forwards over mandatory mTLS (SPIFFE / PodCert / X.509)  |
+-------------------------------------------------------------------+
                                 |
      Mandatory mTLS + HTTP CONNECT / RFC 9298 connect-udp
                                 v
+-------------------------------------------------------------------+
| 3. Policy Enforcement Point & Gateways (GAIA / Gateway API / PEP) |
|    GAIA, Envoy, cmd/connect-proxy, or cloud SWG                   |
|    Off-sandbox DNS, anti-SSRF, L7/MCP/A2A policy, credential      |
|    injection, audit logging, and IP-less inbound delivery.        |
+-------------------------------------------------------------------+
```

---

## Repository Layout

| Path | Contents |
| --- | --- |
| [docs/architecture.md](docs/architecture.md) | SIG Network architecture vision: building blocks, hooks, privilege separation, BYOS, tenancy, and GAIA / ecosystem integration |
| [install.yaml](install.yaml) | Standalone Kubernetes manifest (`ServiceAccount`, minimal RBAC with zero `secrets` access, `DeviceClass`, `DaemonSet` in `kube-system`) |
| [cmd/dra-agents-net](cmd/dra-agents-net) | Per-node Kubernetes Network Driver (DRA + NRI DaemonSet, `dra.agents.net`), mandatory mTLS egress forwarding, and opt-in mTLS ingress bridge |
| [cmd/agents-net-ingress-gateway](cmd/agents-net-ingress-gateway) | Stateless mTLS inbound gateway routing external HTTP traffic to IP-less sandboxes |
| [cmd/connect-proxy](cmd/connect-proxy) | Reference mTLS HTTP `CONNECT` / `connect-udp` Policy Enforcement Point (used by tests and demos) |
| [cmd/tun2connect](cmd/tun2connect) | Optional standalone TUN adapter binary (for `TunSidecar` or microVM `vsock` runtimes) |
| [pkg/driver](pkg/driver) | DRA plugin (`DRAConsumableCapacity`), NRI hooks, `HostTun` / `ExplicitProxy` / `TunSidecar`, netlink confinement, and Pod informer |
| [pkg/hosttun](pkg/hosttun) | Unprivileged `HostTun` userspace worker supervisor and built-in worker over `SCM_RIGHTS` (`--host-tun-isolation=shared\|per-pod`, pluggable `--host-tun-worker-bin`, automatic crash recovery) |
| [pkg/tun2connect](pkg/tun2connect) | Built-in Go userspace TCP/IP stack (gVisor `netstack`), Virtual DNS (`198.18.0.0/15`, `100::/64`), and `CONNECT` / `connect-udp` forwarding hooks |
| [pkg/tunnel](pkg/tunnel) | Per-Pod UDS / `socketat` listener manager and mandatory mTLS HTTP/2 + HTTP/1.1 `CONNECT` / `connect-udp` dialer |
| [pkg/apis](pkg/apis), [pkg/params](pkg/params) | `dra.agents.net/v1alpha1` `DriverConfig` & `DeviceStatus` and strict `FromClass` / `FromClaim` decoding |
| [pkg/auth](pkg/auth), [pkg/catrust](pkg/catrust) | Mandatory mTLS (`MTLS`, `SPIFFE`, KEP-4317 `PodCertificate`), RFC 8941 attested identity headers, and CA bundle materialization |
| [pkg/ingress](pkg/ingress), [pkg/gateway](pkg/gateway) | Node-side mTLS `CONNECT <podUID>:<port>` ingress bridge and reference ingress gateway |
| [pkg/socketat](pkg/socketat), [pkg/store](pkg/store), [pkg/metrics](pkg/metrics), [pkg/proxyenv](pkg/proxyenv) | Cross-netns helpers, BoltDB checkpoint store, Prometheus metrics, and explicit-proxy env helpers |
| [test/smoke.sh](test/smoke.sh) | End-to-end `kind` v1.36 smoke test with full mTLS on both egress PEP and `LoadBalancer` ingress |

---

## Install and Quick Start

Requires Kubernetes 1.36+ (`DRAConsumableCapacity` Beta enabled by default) and containerd/CRI-O with NRI enabled.

```bash
kubectl apply -f https://raw.githubusercontent.com/aojea/agents.net/main/install.yaml
```

### Cluster-Admin `DeviceClass` (`FromClass`)

Cluster administrators configure confinement, adapter mode, PEP endpoint, mandatory mTLS authentication, and attested attributes in a `DeviceClass`:

```yaml
apiVersion: resource.k8s.io/v1
kind: DeviceClass
metadata:
  name: dra.agents.net-team-a
spec:
  selectors:
    - cel:
        expression: device.driver == "dra.agents.net"
  config:
    - opaque:
        driver: dra.agents.net
        parameters:
          apiVersion: dra.agents.net/v1alpha1
          kind: DriverConfig
          confinementMode: PodNetworkIsolated
          adapterMode: HostTun
          policyEnforcementPoint:
            url: https://egress-gateway.system.svc:8443
            tls:
              trustDomain: cluster.local
            auth:
              type: SPIFFE
          custom:
            tenant: team-a
```

### Workload `ResourceClaimTemplate` and `Pod`

Any `Pod`, `Deployment`, or `kubernetes-sigs/agent-sandbox` `Sandbox` / `SandboxWarmPool` attaches via standard `resourceClaims` with zero sidecars and zero Pod capabilities:

```yaml
apiVersion: resource.k8s.io/v1
kind: ResourceClaimTemplate
metadata:
  name: agent-egress
  namespace: default
spec:
  spec:
    devices:
      requests:
        - name: agents-net
          exactly:
            deviceClassName: dra.agents.net-team-a
            allocationMode: ExactCount
            count: 1
---
apiVersion: v1
kind: Pod
metadata:
  name: my-agent
  namespace: default
spec:
  automountServiceAccountToken: false
  resourceClaims:
    - name: agents-net
      resourceClaimTemplateName: agent-egress
  containers:
    - name: agent
      image: python:3.14-slim
      command: ["python3", "-c", "import time; time.sleep(3600)"]
      resources:
        claims:
          - name: agents-net
      securityContext:
        runAsNonRoot: true
        allowPrivilegeEscalation: false
        capabilities:
          drop: ["ALL"]
```

---

## Adapter & Confinement Modes

### Adapters (`adapterMode`, configured in `DeviceClass`)

- **`HostTun` (default):** Creates a persistent `tun0` inside the Pod netns during NRI `RunPodSandbox`, hands `tunFD` and a per-Pod dial-broker FD over `SCM_RIGHTS` to an unprivileged host worker process (UID/GID `65534`, zero Linux capabilities, `NoNewPrivs=1`, isolated empty netns) that terminates TCP/UDP/DNS (`198.18.0.0/15`, `100::/64`), and replaces `/etc/resolv.conf` with a read-only bind mount to `198.19.255.253`. Supports `--host-tun-isolation=shared` (default, one multi-tenant worker per node) or `--host-tun-isolation=per-pod` (one dedicated worker per Pod), custom bring-your-own userspace stacks via `--host-tun-worker-bin`, and automatic crash recovery over persistent `tun0`. Zero sidecar, zero Pod capabilities, zero `egress.sock` exposed inside containers.
- **`ExplicitProxy`:** Binds `127.0.0.1:15001` inside the Pod netns via `socketat` and injects `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY` without creating a TUN device or synthetic IPs.
- **`TunSidecar`:** Attaches `/dev/net/tun` and UDS sockets to an `agents-net-tun2connect` native sidecar when in-guest conversion is needed.

### Confinement (`confinementMode`, configured in `DeviceClass`)

- **`PodNetworkIsolated` (default):** Pairs with [KEP-6313](https://github.com/kubernetes/enhancements/issues/6313) (`spec.podNetwork: Isolated` — loopback-only Pod netns, zero CNI, zero Pod IP).
- **`NetworkPolicyDenyAll`:** Standalone fallback for existing CNI clusters:
  - `nicBlockMode: Disabled`: leaves `eth0` to CNI `NetworkPolicy` (Cilium, Calico, etc.) and installs source-IP policy routing in table `100` under `HostTun` so inbound replies (`sandbox-router`, kubelet probes) still exit `eth0`.
  - `nicBlockMode: DropAll` (default): flushes non-loopback routes and attaches `tc clsact` drop filters on `eth0` for clusters without `NetworkPolicy` enforcement (such as `kindnet`).

---

## Health, Metrics, and Ingress

- **Health & metrics (`--metrics-addr`, default `:9102`):** `/healthz`, `/healthz/dra`, `/healthz/nri`, and Prometheus `/metrics` (`dra_agents_net_*`).
- **IP-less ingress (opt-in, off by default):** Enable `--ingress-addr` with mandatory mTLS flags (`--ingress-tls-cert`, `--ingress-tls-key`, `--ingress-client-ca`, optional `--ingress-allowed-client-san`) to serve `CONNECT <podUID>:<port>` tunnels discovered without Pod IPs.

---

## Build and Test

```bash
# Build all binaries (dra-agents-net, agents-net-ingress-gateway, connect-proxy, tun2connect)
make build

# Run unit and Linux cross-netns integration tests with race detector
make test

# Static analysis and formatting
make vet

# End-to-end kind v1.36 smoke test (mTLS egress + LoadBalancer ingress)
USE_CLOUD_PROVIDER_KIND=true ./test/smoke.sh
```

## License

See [LICENSE](LICENSE) and [COPYRIGHT.md](COPYRIGHT.md).
