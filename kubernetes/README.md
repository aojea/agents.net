# `dra-agents-net`: Kubernetes Network Driver for `agents.net`

`dra-agents-net` is a per-node **Kubernetes Network Driver (KND)** built on Dynamic Resource Allocation (DRA) and the Node Resource Interface (NRI) that implements [`agents.net`](../spec/draft/index.md) network plumbing for any isolated Kubernetes `Pod` (raw Pods, Deployments, StatefulSets, or sandbox controllers such as [`kubernetes-sigs/agent-sandbox`](https://github.com/kubernetes-sigs/agent-sandbox)) using standard Kubernetes `DeviceClass`, `ResourceClaimTemplate`, and `ResourceClaim` objects — with zero workload CRD changes.

It follows the **Kubernetes Network Driver (KND) Model** introduced by Antonio Ojea in *"[The Kubernetes Network Driver Model: A Composable Architecture for High-Performance Networking](https://doi.org/10.1109/LCN65610.2025.11146291)"* (2025 IEEE 50th Conference on Local Computer Networks (LCN), preprint [arXiv:2506.23628](https://arxiv.org/abs/2506.23628)) and demonstrated by [DRANET](https://github.com/kubernetes-sigs/dranet) (`dra.net`). Instead of relying on CNI chaining or container-scoped Device Plugins, `dra-agents-net` models `agents.net` network plumbing as a composable, first-class Kubernetes resource: DRA (`driver: dra.agents.net`) handles declarative claiming, opaque parameter push, and slow-path preparation before sandbox creation, while NRI hooks (`RunPodSandbox`, `CreateContainer`, `StopPodSandbox`, `RemovePodSandbox`, `Synchronize`) perform Pod-scoped confinement, loopback/UDS wiring, and container environment adjustments without writing CDI files or calling back to the API server on the critical Pod startup path.

`dra-agents-net` isolates Pod egress from the direct cluster/internet network and forwards all TCP, UDP, and DNS traffic over authenticated `agents.net` tunnels (`HTTP/2` multiplexed `CONNECT`, `HTTP/1.1 CONNECT`, and RFC 9298 `connect-udp`) to an external or in-cluster **Policy Enforcement Point (PEP)** proxy or portal (such as [`connect-proxy`](../sdk/README.md), `gke-labs/service-portals`, Envoy, or a corporate gateway). Policy evaluation, L7 inspection, and credential injection stay in the PEP rather than inside the node driver.

## Reference Architecture: Agentic Networking with a Policy Enforcement Point

Autonomous AI agents run untrusted code, install packages, and call external tools and APIs. Giving an agent Pod a regular CNI Pod IP, direct cluster routing, and in-pod API credentials creates a wide blast radius under prompt injection or compromised tool execution.

This reference architecture splits agent networking into three decoupled layers:

```text
+------------------------------------------------------------------------------+
| 1. Untrusted Agent Sandbox (Zero Direct Network Path, Zero Upstream Secrets) |
|                                                                              |
|  - Loopback-only netns (KEP-6313 Network-Isolated Pod) or deny-all fallback  |
|  - No API keys, cloud tokens, or upstream mTLS private keys inside the Pod   |
|  - Talks only across a sandbox-scoped boundary:                              |
|      * Unix domain socket (/run/agents.net/egress.sock)                      |
|      * Optional local proxy adapter (127.0.0.1:<port>) or hypervisor vsock   |
+------------------------------------------------------------------------------+
                                     |
        aojea/agents.net Boundary Contract (Plugin Interface)
        RFC 9110 HTTP CONNECT + RFC 9298 connect-udp + RFC 9209 Proxy-Status
                                     |
                                     v
+------------------------------------------------------------------------------+
| 2. Pluggable Forwarding Layer (Implementation-Agnostic)                      |
|                                                                              |
|  Enforces confinement, stamps unforgeable platform-attested workload         |
|  identity (Agents-Net-*), authenticates to the PEP, and forwards tunnels.    |
|                                                                              |
|  Any technology can implement this layer:                                    |
|   - DRA + NRI Kubernetes Network Driver (this repo: dra-agents-net)          |
|   - CNI / eBPF dataplanes (OVN-Kubernetes, Calico, Cilium, Antrea)           |
|   - MicroVM / hypervisor transports (virtio-vsock: Firecracker, Kata, QEMU)  |
|   - Service mesh node proxies or cloud-managed dataplanes                    |
+------------------------------------------------------------------------------+
                                     |
        Authenticated Tunnel (mTLS / SPIFFE / PodCertificate / SA JWT)
        HTTP/2 or HTTP/1.1 CONNECT + connect-udp + attested identity headers
                                     |
                                     v
+------------------------------------------------------------------------------+
| 3. Policy Enforcement Point (PEP) (Out-of-Band Policy, DNS, and Secrets)     |
|    e.g., gke-labs/service-portals, Envoy / Agentgateway, corporate SWG       |
|                                                                              |
|  - Evaluates FQDN, L7 HTTP/MCP, SSRF, and workload-identity policies         |
|  - Resolves DNS outside the sandbox and dials approved targets               |
|  - Injects upstream API keys / credentials and optionally terminates TLS     |
|  - Emits structured denials (Proxy-Status / Boundary-Reason) and audit logs  |
+------------------------------------------------------------------------------+
```

### Why `aojea/agents.net` as the Plugin Mechanism?

[`aojea/agents.net`](https://github.com/aojea/agents.net) defines a narrow, vendor-neutral boundary contract between an isolated sandbox and an external Policy Enforcement Point. Using `agents.net` as the forwarding plugin boundary solves five core problems in agentic networking:

- **Non-bypassable confinement instead of advisory proxies:** Standard `HTTP_PROXY` variables are advisory; untrusted code can ignore them and open direct sockets. Cutting off direct egress forces every connection across the boundary socket or adapter.
- **Hostname-level policy without DNS spoofing or IP drift:** Static IP firewalls break when APIs and package registries sit behind dynamic CDNs, and IP-based allowlists suffer from DNS rebinding and TOCTOU drift. Over `agents.net`, the sandbox sends the target hostname inside `HTTP CONNECT` or `connect-udp`, and the PEP resolves DNS and evaluates policy on the canonical name.
- **No secrets inside the untrusted sandbox:** Upstream API tokens, cloud credentials, and gateway mTLS keys stay outside the workload. The forwarding layer attests workload identity out of band (`MTLS`, `SPIFFE`, KEP-4317 `PodCertificate`, or `ServiceAccountToken`), and the PEP injects target credentials only after policy allows the call.
- **Standard wire protocols instead of custom plumbing:** `agents.net` builds on RFC 9110 `HTTP CONNECT`, RFC 9298 `connect-udp`, and RFC 9209 `Proxy-Status`. Workloads, adapters, and PEPs interoperate without proprietary tunneling protocols.
- **No per-Pod proxy sidecar tax:** Moving forwarding out of the Pod removes per-sandbox proxy containers, saving memory per sandbox and avoiding shared-Pod sidecar bypasses.

### Network-Isolated Pods (KEP-6313): Removing the CNI Dependency and Kernel Attack Surface

Pairing `agents.net` with **Kubernetes Network-Isolated Pods** ([KEP-6313](https://github.com/kubernetes/enhancements/issues/6313), [kubernetes#143280](https://github.com/kubernetes/kubernetes/pull/143280)) removes cluster network plumbing from the sandbox Pod completely:

- **Zero CNI dependency and zero Pod IP:** Under `PodNetworkIsolated`, the container runtime creates a loopback-only network namespace without invoking CNI plugins, allocating Pod IPs, attaching `veth` pairs, or relying on asynchronous `NetworkPolicy` propagation.
- **Smaller Linux kernel network attack surface:** Every attached container network interface exposes the host Linux kernel's TCP/IP packet-processing and netfilter/`nftables` code paths to untrusted code or reachable peers. Those kernel subsystems are recurring sources of critical memory-corruption vulnerabilities, including:
  - **CVE-2026-98432** (CVSS 9.8, Linux kernel IPv4 TCP options use-after-free in handshake and request-socket handling, enabling remote code execution and kernel memory corruption).
  - **CVE-2024-1086** (Linux kernel `netfilter: nf_tables` `nft_verdict_init()` double-free, enabling container-to-host escape and local privilege escalation).
  Keeping untrusted sandboxes in a loopback-only network namespace and moving packet forwarding over Unix domain sockets (or hypervisor `vsock`) avoids attaching the workload to the cluster IP stack and eliminates per-Pod `nftables` filtering rules inside or around the sandbox.
- **Graceful adoption on existing clusters:** On clusters that do not yet support KEP-6313, `dra-agents-net` provides a `NetworkPolicyDenyAll` fallback (deny-all `NetworkPolicy` plus NRI non-loopback route flushing) so operators can deploy the same PEP and `agents.net` model today and move to `PodNetworkIsolated` without changing workloads or PEPs.

### Implementation Freedom: DRA as One Reference Mechanism

This reference architecture separates **how a workload requests network plumbing** from **which technology implements forwarding to the PEP**:

- **DRA + NRI (`dra-agents-net`)** is a batteries-included, CNI-agnostic reference implementation (following the Kubernetes Network Driver model, similar in spirit to `kube-network-policies` and `DRANET`). A Pod claims the `dra.agents.net` DRA `DeviceClass`, and `dra-agents-net` wires the Pod to the PEP without modifying the cluster CNI.
- **Alternative forwarding implementations** can satisfy the exact same `agents.net` + PEP architecture using whatever mechanism fits the platform best: native CNI/eBPF dataplanes (OVN-Kubernetes, Calico, Cilium, Antrea), hypervisor `virtio-vsock` bridges (Firecracker, Kata, QEMU, gVisor), service mesh node proxies, or cloud-managed gateways.

## `dra-agents-net` Implementation Architecture

```text
+-----------------------------------------------------------------------+
| Isolated Pod Network Namespace                                        |
|                                                                       |
|  [Untrusted Workload Container]                                       |
|   - automountServiceAccountToken: false, capabilities.drop: ["ALL"]   |
|   - /var/run/agent-ca.pem (+ /var/run/agent-extra-ca.pem)             |
|   - ExplicitProxy (default DeviceClass): 127.0.0.1:<port> (socketat)  |
|     + language proxy env vars (zero sidecar needed)                   |
|   - TunSidecar (driver DeviceClass + webhook/PodTemplate):            |
|     agents-net-tun2connect (tun0)                                     |
+-----------------------------------------------------------------------+
         │  egress: /run/agents.net/egress.sock or 127.0.0.1:<port>
         │  ingress: /run/agents.net/ingress.sock or socketat.DialAtPath
         ▼
+-----------------------------------------------------------------------+
| Node DaemonSet: dra-agents-net (DRA driver: "dra.agents.net" + NRI)   |
|                                                                       |
|  DRA slow path (resource.k8s.io/v1 + DRAConsumableCapacity, K8s 1.36+):|
|   - Publishes 1 shared device ("agents-net", allowMultipleAllocations) |
|     with sandboxes capacity = allocatablePods (default request = 1)    |
|   - PrepareResourceClaims: decodes ordered OpaqueDeviceConfiguration: |
|       1. DeviceClass (FromClass): dra.agents.net/v1alpha1 DriverConfig|
|       2. ResourceClaim (FromClaim): dra.agents.net/v1alpha1           |
|          DriverConfig (per-workload PEP, CA trust, ingress, custom)   |
|     opens egress.sock, materializes CA bundles, resolves PEP auth,    |
|     checkpoints to BoltDB                                             |
|   - Reports readiness via resourceclaims/driver status MergePatch     |
|                                                                       |
|  NRI fast path (zero CDI files):                                      |
|   - RunPodSandbox: verifies loopback-only (PodNetworkIsolated) OR     |
|     flushes non-loopback routes + attaches tc clsact matchall DROP    |
|     on every non-loopback NIC via pure netlink (NetworkPolicyDenyAll; |
|     opt-out via DeviceClass nicBlockMode: Disabled); binds            |
|     127.0.0.1:<port> inside Pod netns via socketat (ExplicitProxy)    |
|   - CreateContainer: injects UDS, /dev/net/tun (TunSidecar only),     |
|     CA mounts, and non-clobbering CA + proxy environment variables    |
|   - StopPodSandbox / RemovePodSandbox: immediate egress+ingress       |
|     revocation; Synchronize recovers live Pods across restarts        |
|                                                                       |
|  Host Ingress Bridge (:15080, optional TLS/mTLS):                     |
|   - Accepts CONNECT <podUID>:<port> from sandbox-router / gateways    |
|   - Enforces ingressPorts allowlist (403/404 + Boundary-Reason)       |
+-----------------------------------------------------------------------+
         │  TLS / mTLS over HTTP/2 (default) or HTTP/1.1
         │  CONNECT + RFC 9298 connect-udp + attested Agents-Net-*
         ▼
+-----------------------------------------------------------------------+
| Policy Enforcement Point (PEP) (policy enforcement + secret injection)|
+-----------------------------------------------------------------------+
```

## Package Layout

| Path | Responsibility |
| --- | --- |
| [cmd/dra-agents-net](cmd/dra-agents-net) | Node DaemonSet entrypoint (`--driver-name=dra.agents.net`, `--ingress-addr=:15080`, `--metrics-addr=:9102`) |
| [cmd/agents-net-ingress-gateway](cmd/agents-net-ingress-gateway) | Stateless Kubernetes ingress gateway that watches `ResourceClaim.status.devices[].data` behind any `LoadBalancer`, `Ingress`, or Gateway API `HTTPRoute` |
| [pkg/gateway](pkg/gateway) | `ResourceClaim` ingress registry and HTTP-over-`CONNECT` reverse proxy for `agents-net-ingress-gateway` |
| [pkg/apis](pkg/apis) | Internal `dra.agents.net/v1alpha1` DRA `DriverConfig` wire schema and constants |
| [pkg/params](pkg/params) | Layered `DeviceClass` + `ResourceClaim` Opaque parameter decoder and merge logic |
| [pkg/socketat](pkg/socketat) | Goroutine-safe cross-netns `DoAtNSPath`, `ListenAtPath`, and `DialAtPath` (following `github.com/aojea/socketat`) |
| [pkg/catrust](pkg/catrust) | Shared PEM CA resolver (`ConfigMap`, `Secret` with strict `CERTIFICATE`-only filtering, `ClusterTrustBundle`, `HostPath`) and CA env map |
| [pkg/proxyenv](pkg/proxyenv) | Language proxy env var matrix (`HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`, `NODE_USE_ENV_PROXY`, `GRPC_PROXY_EXP`, non-clobbering `JAVA_TOOL_OPTIONS`) |
| [pkg/auth](pkg/auth) | All four native upstream auth modes: `MTLS` (hot-reloading `certDir` or `Secret`), `SPIFFE` (`Node` and `DelegatedPod`), `PodCertificate` (KEP-4317), and `ServiceAccountToken` (`Node` and `Pod`) |
| [pkg/tunnel](pkg/tunnel) | Per-Pod UDS and attached `socketat` listener manager, strict RFC 9110/9112/9209/9298 parser, multiplexed HTTP/2 + HTTP/1.1 upstream dialer, immediate revocation, and JSONL audit log |
| [pkg/ingress](pkg/ingress) | Host-side HTTP/1.1 `CONNECT <podUID>:<port>` ingress bridge with `ingressPorts` enforcement, optional TLS/mTLS, `ingress.sock` / `socketat.DialAtPath` delivery, and per-Pod `Revoke` |
| [pkg/store](pkg/store) | Schema-versioned BoltDB tmpfs checkpoint store |
| [pkg/driver](pkg/driver) | GA DRA `kubeletplugin.DRAPlugin`, NRI hooks, netlink confinement helpers, and node-scoped Pod informer for live identity sync |
| [pkg/metrics](pkg/metrics) | Bounded-cardinality Prometheus metrics (`dra_agents_net_*`) |
| [internal/testutils](internal/testutils) | Unprivileged Linux user-namespace (`CLONE_NEWUSER | CLONE_NEWNET | CLONE_NEWNS`) test harness |
| [install.yaml](install.yaml) | All-in-one Kubernetes manifest (`ServiceAccount`, `ClusterRole`, `ClusterRoleBinding`, default `DeviceClass`, and `DaemonSet`) |

## Behavior Highlights

### DRA + NRI Plumbing (`DRAConsumableCapacity`)
- Each node publishes **one** shared `resource.k8s.io/v1` device (`agents-net`, `allowMultipleAllocations: true`) in a single `ResourceSlice` using `DRAConsumableCapacity` (Beta, enabled by default since Kubernetes 1.36). Its `sandboxes` capacity auto-sizes from `node.Status.Allocatable.Pods()` (fallback `110`, overridable via `--max-sandboxes`) with `requestPolicy: {default: 1, validValues: [1]}` so standard `ResourceClaim`s automatically consume 1 unit without declaring driver-specific capacity fields.
- `PrepareResourceClaims` sets up host UDS directories, resolves upstream auth, materializes Pod CA bundles, checkpoints state (including `shareID`) to BoltDB, and patches `ResourceClaim.status.devices` with matching `shareID` and zero CDI files.
- `RunPodSandbox` runs synchronously before any container starts: under `PodNetworkIsolated` it verifies the Pod netns contains only loopback; under `NetworkPolicyDenyAll` it flushes all non-loopback IPv4 and IPv6 routes and (by default, `nicBlockMode: DropAll`) attaches pure-netlink `tc clsact` `matchall` `TC_ACT_SHOT` drop filters on both ingress and egress of every non-loopback NIC inside the Pod netns.

### Confinement & Driver-Configured Adapter Modes
Cluster-admin datapath defaults (`nicBlockMode`, `adapterMode`, `proxy.port`, `proxy.noProxy`, `maxConnections`, `idleTimeoutSeconds`, host-local CA/mTLS/SPIFFE paths, and optional cluster-wide TLS/CA/auth defaults) are configured in `DeviceClass.spec.config[].opaque.parameters` (`FromClass`) using `apiVersion: dra.agents.net/v1alpha1`, `kind: DriverConfig`. Workload `ResourceClaimTemplate` and `ResourceClaim` objects (`FromClaim`) layer per-workload `dra.agents.net/v1alpha1` `DriverConfig` settings (`policyEnforcementPoint`, `caTrust`, `confinementMode`, `ingressPorts`, `custom`); privileged host-node and `nicBlockMode` fields are rejected when supplied from `FromClaim`.

- **`PodNetworkIsolated`** (default): Loopback-only Pod network namespace (KEP-6313) with no CNI attachment or Pod IP.
- **`NetworkPolicyDenyAll`**: Compatible with any existing CNI; combines a deny-all `NetworkPolicy`, NRI non-loopback route flushing, and pure-netlink `tc clsact` ingress+egress `matchall` drop filters on every non-loopback NIC inside the Pod netns (`nicBlockMode: DropAll`, default). Blocking runs strictly inside the Pod netns (without touching host-side CNI hooks such as Cilium's `lxc*`/`netkit` programs) and isolates all primary and secondary NICs independently of CNI `NetworkPolicy` enforcement. Cluster administrators can opt out in `DeviceClass` `DriverConfig` via `nicBlockMode: Disabled` (`FromClass` only; rejected if supplied in a `ResourceClaim`).
- **`ExplicitProxy`** (default): Binds `127.0.0.1:<port>` (default `15001`, parametrizable in `DeviceClass` `DriverConfig`) directly inside the Pod loopback namespace via `socketat.ListenAtPath` with zero sidecar container and injects standard language proxy env vars.
- **`TunSidecar`**: Pairs with a single `agents-net-tun2connect` native sidecar per Pod netns (provided via a driver mutating webhook or `PodTemplate`) that receives `/run/agents.net` and `/dev/net/tun`.
- **`TunVM`**: Exposes per-Pod UDS paths for hypervisor/microVM adapters.

### Declarative Pod CA Trust & PEP TLS
Both `caTrust.sources` and `policyEnforcementPoint.tls.caCertificateRefs` accept the same `CASource` list (`ConfigMap`, `Secret`, `ClusterTrustBundle`, `HostPath`, default key `ca.crt`). Only valid X.509 `CERTIFICATE` PEM blocks are extracted, so `cert-manager` `kubernetes.io/tls` Secrets never expose private keys.

- `AppendSystemRoots` (default) writes system roots + custom CAs to `/var/run/agent-ca.pem` and custom-only CAs to `/var/run/agent-extra-ca.pem` (for `NODE_EXTRA_CA_CERTS`).
- `Replace` writes only custom CAs to `/var/run/agent-ca.pem`.
- `InjectEnv` (default) injects `AGENT_CA_CERT`, `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `PIP_CERT`, `GIT_SSL_CAINFO`, `NODE_EXTRA_CA_CERTS`, and related language trust variables; `MountOnly` mounts the files without injecting env vars.

### PEP Authentication & Attested Metadata
Every `CONNECT` and `connect-udp` request to the Policy Enforcement Point carries unforgeable node-attested `Agents-Net-*` headers (`Sandbox-Namespace`, `Sandbox-Name`, `Pod-Name`, `Pod-Uid`, `Service-Account`, `Node-Name`, `Claim-Uid`, `Claim-Name`, plus sanitized `Agents-Net-Param-*` custom parameters). Supported auth modes:
- **`MTLS`**: Hot-reloaded host `certDir` or `Secret` (`GetClientCertificate` with 30s TTL cache).
- **`SPIFFE`**: `Node` (SPIFFE Workload API) or `DelegatedPod` (SPIRE Delegated Identity v1).
- **`PodCertificate`**: KEP-4317 kubelet-projected credential bundle on `agents-net-tun2connect`.
- **`ServiceAccountToken`**: `Node` (DaemonSet projected token) or `Pod` (sidecar-isolated projected token) sent in `Proxy-Authorization: Bearer <jwt>`.

### Explicit Host-Side Ingress & DRA Status Discovery
Ingress is strictly opt-in and authorized separately from egress: Pods without `ingressPorts` expose no ingress endpoint. When `ingressPorts` lists allowed TCP ports, `dra-agents-net` serves `CONNECT <podUID>:<port>` on `--ingress-addr` (default `:15080`, optional TLS/mTLS), injects `AGENT_INGRESS_PORT` into workload containers per [`spec/draft/ingress.md`](../spec/draft/ingress.md), and publishes a structured `dra.agents.net/v1alpha1` `DeviceStatus` payload in `ResourceClaim.status.devices[].data`:

```json
{
  "apiVersion": "dra.agents.net/v1alpha1",
  "kind": "DeviceStatus",
  "nodeName": "worker-1",
  "podUID": "a1b2c3d4-...",
  "sandboxID": "9f8e7d6c...",
  "ingress": {
    "endpoint": "10.0.0.5:15080",
    "protocol": "http-connect",
    "target": "a1b2c3d4-...",
    "tls": true,
    "serverName": "dra-agents-net.kube-system.svc",
    "ports": [
      { "port": 8080, "protocol": "TCP" }
    ]
  }
}
```

Cluster ingress gateways and routers — including the included stateless [agents-net-ingress-gateway](cmd/agents-net-ingress-gateway) deployed behind a Kubernetes `LoadBalancer` Service, `Ingress`, or Gateway API `HTTPRoute` — watch `ResourceClaim` objects to discover how to attract and tunnel traffic to isolated Pods that have no reachable Pod IP (KEP-6313 `PodNetworkIsolated` or `tc clsact DROP`), dialing `ingress.endpoint` and issuing `CONNECT <ingress.target>:<port> HTTP/1.1`. The bridge dials `ingress.sock` if present or `127.0.0.1:<port>` inside the Pod netns via `socketat.DialAtPath`, denies undeclared ports with `403 ingress-port-denied`, denies unknown Pods with `404 unknown-sandbox`, and immediately revokes active tunnels and clears `ingress` (`Ready=False`, `AgentsNetRevoked`) on `StopPodSandbox` or `UnprepareResourceClaims`. Use `--ingress-advertise-addr` and `--ingress-server-name` to override the advertised host:port or TLS server name.

### DRA / NRI Lifecycle & Race Prevention
Following [DraNet](https://github.com/kubernetes-sigs/dranet) (`#403`, `#426`, `#427`), `dra-agents-net` enforces strict startup, reconnect, shutdown, and auditing invariants so Pods never silently start unconfined:

- **Fail-fast port bind:** `--metrics-addr` binds before `driver.Start` so a port still held by an older DaemonSet Pod fails startup before accepting DRA claims.
- **NRI-before-DRA startup order:** `Start` connects the NRI plugin (with `FailurePolicy{FailRequest: true, KeepConnected: true}`) and waits until `nriConnected` is true **before** starting and registering the DRA kubelet plugin. Once DRA registers, kubelet can create sandboxes for already-prepared claims without calling `PrepareResourceClaims`, so NRI must already be active.
- **Claim gating during NRI outages:** `PrepareResourceClaims` rejects non-empty batches while NRI is disconnected, preventing kubelet from starting unconfined Pods during a container runtime restart.
- **Supervised NRI reconnection:** `runNRI` reconnects with exponential backoff (`1s..16s`), resetting the consecutive failure streak after every successful session so routine `containerd` restarts do not crash the driver. After 5 consecutive failures it exits so kubelet restarts the Pod.
- **Graceful 3-step shutdown drain:** `Stop` halts DRA first, waits for prepared Pods to pass a 10s quiet grace period after their last NRI hook (capped by a 5m fallback), and only then cancels the context and disconnects NRI.
- **Unplumbed Pod auditing on `Synchronize`:** On startup and every NRI reconnect, `Synchronize` inspects live prepared Pods that have at least one `CONTAINER_RUNNING` container (checking live netlink isolation and required `/run/agents.net` and `/var/run/agent-ca.pem` mounts). If a sandbox was created while `dra-agents-net` was killed or disconnected, it logs an error, increments `dra_agents_net_pods_missing_plumbing_total`, and emits a `Warning` `AgentsNetPlumbingMissing` Event on the Pod instructing operators to recreate it.

### Health & Metrics Endpoints (`--metrics-addr`, default `:9102`)

| Path | Description |
| --- | --- |
| `/healthz` | Logical AND of `dra` and `nri` checks (`200 ok` when both pass, `503` with per-check lines otherwise). Supports Kubernetes apiserver-style `?verbose` and `?exclude=<name>`. Used by DaemonSet `startupProbe` and `readinessProbe` (not `livenessProbe`, so brief runtime restarts do not kill live sandboxes). |
| `/healthz/dra` | `200 ok` once the DRA kubelet plugin is registered with kubelet, `503` otherwise. |
| `/healthz/nri` | `200 ok` while the NRI plugin has an active connection to the container runtime, `503` otherwise. |
| `/metrics` | Prometheus metrics (`dra_agents_net_dra_plugin_requests_total`, `dra_agents_net_dra_plugin_requests_latency_seconds`, `dra_agents_net_nri_plugin_requests_total`, `dra_agents_net_nri_plugin_requests_latency_seconds`, `dra_agents_net_published_devices_total`, `dra_agents_net_last_published_time_seconds`, `dra_agents_net_nri_plugin_disconnects_total`, `dra_agents_net_nri_plugin_reconnect_attempts_total`, `dra_agents_net_pods_missing_plumbing_total`, `dra_agents_net_tunnels_total`, `dra_agents_net_active_tunnels`, `dra_agents_net_active_sandboxes`, `dra_agents_net_tunnel_dial_duration_seconds`, `dra_agents_net_ingress_connections_total`). |

## Kubernetes Usage (`ResourceClaimTemplate` + `Pod`)

Install the DaemonSet, RBAC, and default `DeviceClass` into `kube-system` using the single [install.yaml](install.yaml) manifest:

```bash
kubectl apply -f https://raw.githubusercontent.com/aojea/agents.net/main/kubernetes/install.yaml
```

Container images are published to `ghcr.io/aojea/agents.net/dra-agents-net` by [.github/workflows/kubernetes-image.yml](../.github/workflows/kubernetes-image.yml) on release tags (`v*` / `kubernetes/v*`) and on demand via `workflow_dispatch` (tagged with the commit hash).

Any Kubernetes workload (`Pod`, `Deployment`, `StatefulSet`, or `agent-sandbox` `Sandbox` / `SandboxTemplate` via `podTemplate.spec.resourceClaims`) attaches `dra-agents-net` using standard Kubernetes `ResourceClaimTemplate` (recommended — `kube-controller-manager` automatically creates and garbage-collects one `ResourceClaim` per Pod) or a standalone `ResourceClaim`:

```yaml
apiVersion: resource.k8s.io/v1
kind: ResourceClaimTemplate
metadata:
  name: my-agent-net-template
  namespace: default
spec:
  spec:
    devices:
      requests:
        - name: agents-net
          exactly:
            deviceClassName: dra.agents.net
            allocationMode: ExactCount
            count: 1
      config:
        - requests: ["agents-net"]
          opaque:
            driver: dra.agents.net
            parameters:
              apiVersion: dra.agents.net/v1alpha1
              kind: DriverConfig
              confinementMode: NetworkPolicyDenyAll
              policyEnforcementPoint:
                url: https://egress-portal.system.svc:8443
                tls:
                  caCertificateRefs:
                    - type: ConfigMap
                      configMapRef:
                        name: portal-ca
              ingressPorts:
                - port: 8080
                  protocol: TCP
              custom:
                tenant: team-alpha
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
      resourceClaimTemplateName: my-agent-net-template
  containers:
    - name: agent
      image: python:3.14-slim
      command: ["python3", "-c", "import time; time.sleep(3600)"]
      resources:
        claims:
          - name: agents-net
      securityContext:
        allowPrivilegeEscalation: false
        capabilities:
          drop: ["ALL"]
```

## Build & Test

```bash
# Build binary
go -C kubernetes build ./cmd/dra-agents-net

# Run all unit tests AND Linux unprivileged user-namespace integration tests
go -C kubernetes test -race -count=1 -v ./...

# Run end-to-end Kubernetes smoke test (kind v1.36 + agents.net sdk/cmd/connect-proxy PEP)
./kubernetes/test/smoke.sh
```

On Linux hosts with unprivileged user namespaces enabled, `go test` automatically runs the real multi-netns integration tests in [pkg/driver/integration_linux_test.go](pkg/driver/integration_linux_test.go) and [pkg/socketat/socketat_test.go](pkg/socketat/socketat_test.go) without requiring root:

- `TestIntegrationNetworkPolicyDenyAllRouteFlush`: real dual-stack veth pair between host and Pod netns verifying IPv4/IPv6 route flush blocks direct egress while preserving loopback.
- `TestIntegrationTCBlockNonLoopbackNICsPrimaryAndSecondary`: real Pod netns with primary `eth0` and secondary `net1` veth pairs (no `NetworkPolicy`, no `iptables`, no route flush) verifying pure-netlink `tc clsact` `matchall` drop blocks egress TCP and inbound UDP on both NICs idempotently while keeping NICs `UP` and loopback unaffected.
- `TestIntegrationPodNetworkIsolatedNetNSCheck`: verifies loopback-only Pod netns acceptance and non-loopback rejection.
- `TestIntegrationExplicitProxyCrossNetNS`: full DRA + NRI + `socketat.ListenAtPath` cross-netns HTTP/2 multiplexed `CONNECT`, `403 Proxy-Status`, RFC 9298 `connect-udp` datagram relay, and `StopPodSandbox` revocation.
- `TestIntegrationHostIngressBridgeCrossNetNS`: full mTLS host ingress bridge -> `socketat.DialAtPath` into Pod loopback (`200` allowed, `403 ingress-port-denied`, `404 unknown-sandbox`, immediate `Revoke`).
- `TestIntegrationSynchronizeReportsMissingPlumbing`: real netlink route/interface inspection during `Synchronize` verifying `Warning AgentsNetPlumbingMissing` events and `dra_agents_net_pods_missing_plumbing_total` when a prepared Pod runs without confinement or mounts, and zero alerts once plumbed.

## References

- Antonio Ojea, *"The Kubernetes Network Driver Model: A Composable Architecture for High-Performance Networking,"* 2025 IEEE 50th Conference on Local Computer Networks (LCN), DOI: [10.1109/LCN65610.2025.11146291](https://doi.org/10.1109/LCN65610.2025.11146291) (preprint: [arXiv:2506.23628](https://arxiv.org/abs/2506.23628)).
- [`agents.net`](https://github.com/aojea/agents.net) — sandbox network boundary specification.
- [Kubernetes KEP-6313: Network-Isolated Pods](https://github.com/kubernetes/enhancements/issues/6313) (implementation PR: [kubernetes/kubernetes#143280](https://github.com/kubernetes/kubernetes/pull/143280)).
- [DRANET (`kubernetes-sigs/dranet`)](https://github.com/kubernetes-sigs/dranet) — reference Kubernetes Network Driver implementation (`dra.net`).
- [`gke-labs/service-portals`](https://github.com/gke-labs/service-portals) — Policy Enforcement Point egress gateway example.
- Linux kernel network stack CVEs illustrating kernel-stack attack surface: [CVE-2026-98432](https://nvd.nist.gov/vuln/detail/CVE-2026-98432) (IPv4 TCP options use-after-free) and [CVE-2024-1086](https://nvd.nist.gov/vuln/detail/CVE-2024-1086) (`netfilter: nf_tables` double-free).
