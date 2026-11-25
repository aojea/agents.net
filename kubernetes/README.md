# Kubernetes Driver (`dra-agents-net`)

This directory is the Go module `github.com/aojea/agents.net/kubernetes`. It contains two binaries:

- `cmd/dra-agents-net`: a per-node Kubernetes Network Driver (DRA + NRI DaemonSet, driver name `dra.agents.net`) that isolates Pods and forwards egress to a Policy Enforcement Point (PEP) over [`agents.net`](../spec/draft/index.md).
- `cmd/agents-net-ingress-gateway`: a stateless ingress gateway that watches `ResourceClaim` status and delivers inbound HTTP traffic to isolated Pods over the node ingress bridge.

Any Kubernetes Pod (`Pod`, `Deployment`, `StatefulSet`, or sandbox controllers such as [`kubernetes-sigs/agent-sandbox`](https://github.com/kubernetes-sigs/agent-sandbox)) attaches `dra-agents-net` through standard `DeviceClass`, `ResourceClaimTemplate`, and `ResourceClaim` objects, with no changes to workload CRDs.

## Architecture

Agent networking in Kubernetes splits into three parts:

```text
+-------------------------------------------------------------------+
| 1. Isolated Pod                                                   |
|    No direct route out. No upstream API keys or mTLS private keys.|
|    Reaches the boundary through an adapter:                       |
|      - loopback explicit proxy (127.0.0.1:<port>)                 |
|      - in-Pod tun2connect sidecar (tun0 -> egress.sock)           |
|      - out-of-Pod nftables / netns redirect or VM vsock           |
+-------------------------------------------------------------------+
                                 |
      agents.net contract (HTTP CONNECT, connect-udp, Proxy-Status)
                                 v
+-------------------------------------------------------------------+
| 2. Forwarding Layer                                               |
|    Enforces Pod isolation, attaches workload identity headers,    |
|    authenticates to the PEP, and relays tunnels.                  |
|                                                                   |
|    Possible implementations:                                      |
|      - DRA + NRI node driver (dra-agents-net, this directory)     |
|      - Dedicated proxy netns with nftables (sdk/cmd/netnsproxy)   |
|      - CNI / eBPF dataplanes (Cilium, Calico, OVN-Kubernetes)     |
|      - MicroVM vsock / packet backends (Firecracker, QEMU, Kata)  |
+-------------------------------------------------------------------+
                                 |
      TLS/mTLS, SPIFFE, PodCertificate, or ServiceAccount JWT
      HTTP/2 or HTTP/1.1 CONNECT + RFC 9298 connect-udp
                                 v
+-------------------------------------------------------------------+
| 3. Policy Enforcement Point (PEP)                                 |
|    sdk/cmd/connect-proxy, Envoy, gke-labs/service-portals, SWG    |
|    Evaluates hostname/L7/identity policy, resolves DNS outside    |
|    the Pod, dials approved targets, and writes audit records.     |
+-------------------------------------------------------------------+
```

Why put `agents.net` between the Pod and the PEP:

- Direct egress is cut off, so a client that ignores `HTTP_PROXY` fails instead of bypassing policy.
- The Pod sends target hostnames in `CONNECT` or `connect-udp`. The PEP resolves DNS and applies policy to the hostname rather than relying on static IP allowlists that break behind CDNs or DNS rebinding.
- Upstream credentials stay at the PEP. The forwarding layer authenticates to the PEP out of band and attaches node-attested `Agents-Net-*` identity headers.
- The wire protocol is standard RFC 9110 `CONNECT`, RFC 9298 `connect-udp`, and RFC 9209 `Proxy-Status`, so different adapters, drivers, and PEPs interoperate.

### Adapter choices

`agents.net` supports multiple adapter placements ([spec/draft/adapters.md](../spec/draft/adapters.md), [sdk/README.md](../sdk/README.md)):

- **Explicit proxy (`adapterMode: ExplicitProxy`, default in `install.yaml`):** `dra-agents-net` binds `127.0.0.1:15001` (configurable via `proxy.port`) inside the Pod netns using `socketat` and injects `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY`, `NODE_USE_ENV_PROXY`, `GRPC_PROXY_EXP`, and `JAVA_TOOL_OPTIONS`. No sidecar container runs in the Pod. Only proxy-aware clients can reach the PEP; clients that ignore proxy variables fail closed.
- **In-Pod TUN sidecar (`adapterMode: TunSidecar`):** a native sidecar container named `agents-net-tun2connect` (see [sdk/cmd/tun2connect](../sdk/README.md#1-in-guest-networking-with-tun-and-virtual-dns)) runs inside the Pod with `/dev/net/tun` and `/run/agents.net/egress.sock`. It captures TCP, UDP, and DNS transparently, including clients that ignore `HTTP_PROXY`.
- **VM socket (`adapterMode: TunVM`):** `dra-agents-net` opens `/run/dra-agents-net/pods/<podUID>/egress/egress.sock` on the host without bind-mounting it into containers, so a microVM VMM can wire it over vsock or a host socket.
- **Out-of-Pod `nftables` redirect:** an implementation can also terminate the Pod's veth in a dedicated proxy namespace and redirect TCP/UDP/DNS with `nftables` (see [sdk/cmd/netnsproxy](../sdk/README.md#3-network-namespace-proxy)), avoiding a sidecar inside the Pod while still capturing non-proxy-aware clients. `dra-agents-net` does not implement `nftables` redirection itself; it uses `ExplicitProxy`, `TunSidecar`, or `TunVM`.

### Isolation and Network-Isolated Pods (KEP-6313)

`dra-agents-net` supports two confinement modes:

- **`PodNetworkIsolated` (default in `install.yaml`):** pairs with Kubernetes Network-Isolated Pods ([KEP-6313](https://github.com/kubernetes/enhancements/issues/6313), [kubernetes#143280](https://github.com/kubernetes/kubernetes/pull/143280)). The runtime creates a loopback-only network namespace with no CNI plugin, no Pod IP, and no external `veth` interface. `RunPodSandbox` rejects the Pod if any non-loopback interface exists. Removing cluster IP networking and per-Pod `NetworkPolicy` netfilter rules reduces the Linux kernel network attack surface reachable from or to the Pod, such as IPv4 TCP handshake option bugs ([CVE-2026-98432](https://nvd.nist.gov/vuln/detail/CVE-2026-98432)) and `nf_tables` bugs ([CVE-2024-1086](https://nvd.nist.gov/vuln/detail/CVE-2024-1086)).
- **`NetworkPolicyDenyAll`:** works on existing CNI clusters without KEP-6313. During `RunPodSandbox`, `dra-agents-net` flushes all non-loopback IPv4 and IPv6 routes inside the Pod netns. Under the default `nicBlockMode: DropAll`, it also attaches `tc clsact` `matchall` drop filters on ingress and egress of every non-loopback NIC inside the Pod netns via netlink (excluding `tun`/`tap` interfaces in `TunSidecar` mode). Because the filters live inside the Pod netns, they do not touch host-side CNI hooks (such as Cilium `lxc*` or `netkit` programs) and block primary and secondary NICs even when the CNI does not enforce `NetworkPolicy`. Cluster administrators can disable `tc` blocking in `DeviceClass` with `nicBlockMode: Disabled`; `ResourceClaim` parameters cannot set `nicBlockMode`.

## How `dra-agents-net` Works

`dra-agents-net` follows the Kubernetes Network Driver model (Ojea, IEEE LCN 2025, [doi:10.1109/LCN65610.2025.11146291](https://doi.org/10.1109/LCN65610.2025.11146291) / [arXiv:2506.23628](https://arxiv.org/abs/2506.23628)) and [DRANET](https://github.com/kubernetes-sigs/dranet): DRA handles claiming and slow-path setup before sandbox creation, and NRI handles Pod-scoped netns isolation and container adjustments without writing CDI files.

1. **Device advertisement (`DRAConsumableCapacity`):** Each node publishes one shared `resource.k8s.io/v1` device named `agents-net` (`allowMultipleAllocations: true`) with `sandboxes` capacity read from `node.Status.Allocatable.Pods()` (fallback `110`, overridable via `--max-sandboxes`) and `requestPolicy: {default: 1, validValues: [1]}`. Requires Kubernetes 1.36+ (where `DRAConsumableCapacity` is Beta and enabled by default).
2. **`PrepareResourceClaims` (DRA):** Rejects claims if NRI is disconnected. Decodes `dra.agents.net/v1alpha1` `DriverConfig` from `DeviceClass` (`FromClass`) first and `ResourceClaim` (`FromClaim`) second. Privileged host fields (`HostPath` CA sources, `mtls.certDir`, SPIFFE socket paths, `maxConnections`, `idleTimeoutSeconds`, and `nicBlockMode`) are accepted only from `FromClass`. Opens `egress.sock`, resolves PEP auth, writes CA bundles, checkpoints state to BoltDB, and returns zero CDI devices.
3. **`RunPodSandbox` (NRI):** Enforces `PodNetworkIsolated` or `NetworkPolicyDenyAll` confinement before any container starts. In `ExplicitProxy` mode, binds `127.0.0.1:<port>` inside the Pod netns via `socketat`. Patches `ResourceClaim.status.devices` asynchronously with `Ready=True` and a `dra.agents.net/v1alpha1` `DeviceStatus` JSON payload in `data`.
4. **`CreateContainer` (NRI):** Injects read-only bind mounts (`/run/agents.net`, `/var/run/agent-ca.pem`, `/var/run/agent-extra-ca.pem`), `/dev/net/tun` and `/run/agents.net/ingress` (for `agents-net-tun2connect` in `TunSidecar` mode), and non-clobbering environment variables (proxy variables in `ExplicitProxy`, CA variables when `caTrust.mode` is `InjectEnv` or unset, and `AGENT_INGRESS_PORT` when `ingressPorts` is set).
5. **`StopPodSandbox` / `RemovePodSandbox` / `UnprepareResourceClaims`:** Immediately closes active egress and ingress tunnels, patches `ResourceClaim.status.devices` to `Ready=False` (`AgentsNetRevoked`) with `ingress` cleared on `StopPodSandbox`, and removes checkpoints and socket directories on `UnprepareResourceClaims`.
6. **Startup, reconnect, and shutdown:** `--metrics-addr` (default `:9102`) binds before `driver.Start`. NRI connects (with `FailurePolicy{FailRequest: true, KeepConnected: true}`) before DRA registers with kubelet. On startup and every NRI reconnect, `Synchronize` checks running prepared Pods for missing isolation or mounts, logs an error, increments `dra_agents_net_pods_missing_plumbing_total`, and emits a `Warning` `AgentsNetPlumbingMissing` Event. On `SIGTERM`, `Stop` halts DRA first, waits for prepared Pods to finish NRI hooks (10s quiet grace period, 5m cap), then disconnects NRI.

### CA trust and PEP authentication

Both `caTrust.sources` and `policyEnforcementPoint.tls.caCertificateRefs` accept `ConfigMap`, `Secret`, `ClusterTrustBundle`, and `HostPath` (default key `ca.crt`). Only X.509 `CERTIFICATE` PEM blocks are read, so `kubernetes.io/tls` Secrets never expose private keys.

- `caTrust.bundleMode`: `AppendSystemRoots` (default, writes system roots plus custom CAs to `/var/run/agent-ca.pem` and custom-only CAs to `/var/run/agent-extra-ca.pem`) or `Replace` (writes only custom CAs to `/var/run/agent-ca.pem`).
- `caTrust.mode`: `InjectEnv` (default, sets `AGENT_CA_CERT`, `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `PIP_CERT`, `GIT_SSL_CAINFO`, `NODE_EXTRA_CA_CERTS`, and related variables), `MountOnly`, or `None`.
- `policyEnforcementPoint.auth.type`:
  - `MTLS`: host `certDir` (`FromClass` only) or namespace `Secret`.
  - `SPIFFE`: `Node` (SPIFFE Workload API) or `DelegatedPod` (SPIRE Delegated Identity).
  - `PodCertificate`: KEP-4317 projected credential bundle on `agents-net-tun2connect`.
  - `ServiceAccountToken`: `Node` or `Pod` projected JWT sent in `Proxy-Authorization: Bearer <jwt>`.

Every upstream `CONNECT` and `connect-udp` request carries node-attested headers (`Agents-Net-Sandbox-Namespace`, `Agents-Net-Sandbox-Name`, `Agents-Net-Pod-Name`, `Agents-Net-Pod-Uid`, `Agents-Net-Service-Account`, `Agents-Net-Node-Name`, plus `Agents-Net-Claim-Uid` and `Agents-Net-Claim-Name` when present on the Pod, and `Agents-Net-Param-*` from `custom`).

### Ingress discovery and `agents-net-ingress-gateway`

Ingress is separate from egress and off by default. On the CLI, `--ingress-addr` defaults to empty (disabled); [install.yaml](install.yaml) passes `--ingress-addr=:15080`.

When a Pod's `DriverConfig` sets `ingressPorts`, `dra-agents-net` serves `CONNECT <podUID>:<port> HTTP/1.1` on `--ingress-addr` (with optional TLS/mTLS via `--ingress-tls-cert`, `--ingress-tls-key`, `--ingress-client-ca`), sets `AGENT_INGRESS_PORT` in workload containers ([spec/draft/ingress.md](../spec/draft/ingress.md)), and publishes a `dra.agents.net/v1alpha1` `DeviceStatus` in `ResourceClaim.status.devices[].data`:

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

Claims without `ingressPorts` omit `ingress`. `endpoint` uses `--ingress-advertise-addr` if set, otherwise `<nodeIP>:<port>` from `NODE_IP` (`status.hostIP` in `install.yaml`) or `Node.Status.Addresses`.

Because isolated Pods have no reachable Pod IP, an ingress router watches `ResourceClaim` objects instead of `EndpointSlice`s. [cmd/agents-net-ingress-gateway](cmd/agents-net-ingress-gateway) is a stateless gateway that needs only `resourceclaims` `get,list,watch` RBAC and can sit behind a Kubernetes `LoadBalancer` Service, `Ingress`, or Gateway API `HTTPRoute`. It routes requests by path (`/agents/<namespace>/<pod>[:<port>]/<path>`) or headers (`X-Agents-Net-Namespace`, `X-Agents-Net-Pod` / `X-Agents-Net-Pod-Uid`, `X-Agents-Net-Port`), opens `CONNECT <target>:<port>` to `ingress.endpoint`, and proxies HTTP into the Pod's loopback port. `ingressPorts` accepts single ports or inclusive ranges (`port` + `endPort`). The node bridge independently enforces `ingressPorts` (`403` with RFC 9209 `Proxy-Status: ... reason=port-not-permitted`) and revokes tunnels on `StopPodSandbox` (`404` with `Proxy-Status`).

### Health and metrics (`--metrics-addr`, default `:9102`)

| Path | Behavior |
| --- | --- |
| `/healthz` | `200 ok` when both `dra` and `nri` checks pass, `503` otherwise. Supports `?verbose` and `?exclude=<name>`. Used by `startupProbe` and `readinessProbe` in `install.yaml`. |
| `/healthz/dra` | `200 ok` after DRA kubelet registration succeeds. |
| `/healthz/nri` | `200 ok` while NRI is connected and synced. |
| `/metrics` | Prometheus counters, gauges, and histograms under `dra_agents_net_*` (see [pkg/metrics/metrics.go](pkg/metrics/metrics.go)). |

## Package Layout

| Path | Contents |
| --- | --- |
| [cmd/dra-agents-net](cmd/dra-agents-net) | Node DaemonSet entrypoint and `/healthz` handlers |
| [cmd/agents-net-ingress-gateway](cmd/agents-net-ingress-gateway) | Stateless ingress gateway watching `ResourceClaim` status |
| [pkg/apis](pkg/apis) | `dra.agents.net/v1alpha1` `DriverConfig` and `DeviceStatus` types |
| [pkg/params](pkg/params) | `FromClass` + `FromClaim` Opaque config decoder and validation |
| [pkg/driver](pkg/driver) | DRA plugin, NRI hooks, netlink route flush and `tc clsact` blocking, Pod informer |
| [pkg/tunnel](pkg/tunnel) | Per-Pod UDS and `socketat` listener manager, HTTP/2 + HTTP/1.1 `CONNECT` and `connect-udp` dialer |
| [pkg/ingress](pkg/ingress) | Node-side `CONNECT <podUID>:<port>` ingress bridge |
| [pkg/gateway](pkg/gateway) | `ResourceClaim` ingress registry and HTTP-over-`CONNECT` reverse proxy |
| [pkg/auth](pkg/auth) | `MTLS`, `SPIFFE`, `PodCertificate`, and `ServiceAccountToken` resolvers |
| [pkg/catrust](pkg/catrust) | PEM CA resolver and bundle writer |
| [pkg/proxyenv](pkg/proxyenv) | Proxy env var matrix and non-clobbering merge |
| [pkg/socketat](pkg/socketat) | Cross-netns `DoAtNSPath`, `ListenAtPath`, and `DialAtPath` |
| [pkg/store](pkg/store) | BoltDB checkpoint store |
| [pkg/metrics](pkg/metrics) | Prometheus metrics |
| [internal/testutils](internal/testutils) | Unprivileged Linux user-namespace test harness |
| [install.yaml](install.yaml) | All-in-one manifest (`ServiceAccount`, RBAC, `DeviceClass`, `DaemonSet` in `kube-system`) |
| [test/smoke.sh](test/smoke.sh) | End-to-end kind smoke test using `sdk/cmd/connect-proxy` and `cloud-provider-kind` |

## Install and Usage

Install RBAC, the `dra.agents.net` `DeviceClass`, and the `dra-agents-net` DaemonSet into `kube-system`:

```bash
kubectl apply -f https://raw.githubusercontent.com/aojea/agents.net/main/kubernetes/install.yaml
```

Images for `dra-agents-net` and `agents-net-ingress-gateway` are published to `ghcr.io/aojea/agents.net/*` by [.github/workflows/kubernetes-image.yml](../.github/workflows/kubernetes-image.yml) on release tags (`v*`, `kubernetes/v*`) and on demand via `workflow_dispatch` (tagged with the commit hash).

Attach `dra-agents-net` to a Pod using a `ResourceClaimTemplate`:

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

## Build and Test

`kubernetes/` is a standalone Go module outside the root `go.work`, so pass `GOWORK=off` when invoking `go` from the repository root (or use `make -C kubernetes`):

```bash
GOWORK=off go -C kubernetes build ./cmd/...
GOWORK=off go -C kubernetes test -race -count=1 ./...
./kubernetes/test/smoke.sh
```

On Linux hosts with unprivileged user namespaces enabled, `go test` runs the multi-netns integration tests in [pkg/driver/integration_linux_test.go](pkg/driver/integration_linux_test.go) and [pkg/socketat/socketat_test.go](pkg/socketat/socketat_test.go) without root:

- `TestIntegrationNetworkPolicyDenyAllRouteFlush`: dual-stack veth route flush.
- `TestIntegrationTCBlockNonLoopbackNICsPrimaryAndSecondary`: `tc clsact` ingress/egress drop on primary `eth0` and secondary `net1` while keeping loopback working.
- `TestIntegrationPodNetworkIsolatedNetNSCheck`: loopback-only verification.
- `TestIntegrationExplicitProxyCrossNetNS`: cross-netns `socketat` loopback listener, HTTP/2 `CONNECT`, `403 Proxy-Status`, RFC 9298 `connect-udp`, and revocation.
- `TestIntegrationHostIngressBridgeCrossNetNS`: mTLS host ingress bridge to Pod loopback, port pinning, and revocation.
- `TestIntegrationSynchronizeReportsMissingPlumbing`: netlink and mount checks during `Synchronize`.

[test/smoke.sh](test/smoke.sh) creates a kind v1.36 cluster with NRI enabled, builds and installs `dra-agents-net`, `agents-net-ingress-gateway`, and `sdk/cmd/connect-proxy`, and checks direct TCP blocking, mTLS HTTP/2 `CONNECT` allow/block and audit logs against `connect-proxy`, `ResourceClaim` ingress discovery through a `cloud-provider-kind` `LoadBalancer` Service, port pinning, and revocation after Pod deletion.

## References

- Antonio Ojea, *"The Kubernetes Network Driver Model: A Composable Architecture for High-Performance Networking,"* 2025 IEEE 50th Conference on Local Computer Networks (LCN), [doi:10.1109/LCN65610.2025.11146291](https://doi.org/10.1109/LCN65610.2025.11146291) ([arXiv:2506.23628](https://arxiv.org/abs/2506.23628)).
- [agents.net specification](../spec/draft/index.md)
- [Kubernetes KEP-6313: Network-Isolated Pods](https://github.com/kubernetes/enhancements/issues/6313) ([kubernetes#143280](https://github.com/kubernetes/kubernetes/pull/143280))
- [DRANET (`kubernetes-sigs/dranet`)](https://github.com/kubernetes-sigs/dranet)
- [CVE-2026-98432](https://nvd.nist.gov/vuln/detail/CVE-2026-98432) and [CVE-2024-1086](https://nvd.nist.gov/vuln/detail/CVE-2024-1086)
