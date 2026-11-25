# Kubernetes Driver (`dra-agents-net`)

This directory is the Go module `github.com/aojea/agents.net/kubernetes`. It contains two binaries:

- `cmd/dra-agents-net`: a per-node Kubernetes Network Driver (DRA + NRI DaemonSet, driver name `dra.agents.net`) that isolates Pods and forwards egress over mandatory mTLS to a Policy Enforcement Point (PEP) using [`agents.net`](../SPEC.md).
- `cmd/agents-net-ingress-gateway`: a stateless ingress gateway that watches `ResourceClaim` status and delivers inbound HTTP traffic to isolated Pods over mandatory mTLS to the node ingress bridge.

Any Kubernetes Pod (`Pod`, `Deployment`, `StatefulSet`, or sandbox controllers such as [`kubernetes-sigs/agent-sandbox`](https://github.com/kubernetes-sigs/agent-sandbox)) attaches `dra-agents-net` through standard `DeviceClass`, `ResourceClaimTemplate`, and `ResourceClaim` objects, with no changes to workload CRDs.

## Architecture

Agent networking in Kubernetes splits into three parts:

```text
+-------------------------------------------------------------------+
| 1. Isolated Pod                                                   |
|    No direct route out. No upstream API keys or mTLS private keys.|
|    Reaches the boundary through a capability channel:             |
|      - UDS (/run/agents.net/egress.sock) + loopback proxy         |
|      - in-Pod tun2connect sidecar (tun0 -> egress.sock)           |
+-------------------------------------------------------------------+
                                 |
      agents.net contract (HTTP CONNECT, connect-udp, Proxy-Status)
                                 v
+-------------------------------------------------------------------+
| 2. Node Driver (dra-agents-net)                                   |
|    Enforces Pod isolation, attaches node-attested Agents-Net-*    |
|    headers, authenticates to the PEP over mandatory mTLS, and     |
|    relays tunnels.                                                |
+-------------------------------------------------------------------+
                                 |
      Mandatory mTLS (MTLS certDir, SPIFFE, or PodCertificate)
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

- Removing direct routes and using a Unix socket capability channel shrinks the kernel attack surface and lets operators roll out userspace fixes without rebooting the host kernel.
- The Pod sends target hostnames in `CONNECT` or `connect-udp`. The PEP resolves DNS and applies policy to the hostname rather than relying on static IP allowlists that break behind CDNs or DNS rebinding.
- Upstream credentials stay at the PEP. The node driver authenticates to the PEP over mandatory mTLS and attaches node-attested `Agents-Net-Principal`, `Agents-Net-Generation`, and RFC 8941 `Agents-Net-Attributes` headers.
- The wire protocol is standard RFC 9110 `CONNECT`, RFC 9298 `connect-udp`, and RFC 9209 `Proxy-Status`.

### Adapter choices

`dra-agents-net` supports two adapter modes (configured by cluster administrators in `DeviceClass`):

- **Explicit proxy (`adapterMode: ExplicitProxy`, default in `install.yaml`):** `dra-agents-net` mounts `/run/agents.net/egress.sock` read-only, binds `127.0.0.1:15001` (configurable via `proxy.port`) inside the Pod netns using `socketat`, and injects `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY`, `NODE_USE_ENV_PROXY`, `GRPC_PROXY_EXP`, and `JAVA_TOOL_OPTIONS`. Plaintext `http://` proxy requests to the loopback listener are tunneled to the PEP over `CONNECT`. No sidecar container runs in the Pod; clients that ignore proxy variables fail closed.
- **In-Pod TUN sidecar (`adapterMode: TunSidecar`):** a native sidecar container named `agents-net-tun2connect` (see [sdk/cmd/tun2connect](../sdk/README.md#1-in-guest-networking-with-tun-and-virtual-dns)) runs inside the Pod with `/dev/net/tun` and `/run/agents.net/egress.sock`. It captures TCP, UDP, and DNS transparently, including clients that ignore `HTTP_PROXY`.

### Isolation and Network-Isolated Pods (KEP-6313)

`dra-agents-net` supports two confinement modes (driver implementation details, configured in `DeviceClass`):

- **`PodNetworkIsolated` (default in `install.yaml`):** pairs with Kubernetes Network-Isolated Pods ([KEP-6313](https://github.com/kubernetes/enhancements/issues/6313), [kubernetes#143280](https://github.com/kubernetes/kubernetes/pull/143280)). The runtime creates a loopback-only network namespace with no CNI plugin, no Pod IP, and no external `veth` interface. `RunPodSandbox` rejects the Pod if any non-loopback interface exists. Removing cluster IP networking and per-Pod netfilter rules reduces the Linux kernel network attack surface reachable from or to the Pod, such as IPv4 TCP handshake option bugs ([CVE-2026-98432](https://nvd.nist.gov/vuln/detail/CVE-2026-98432)) and `nf_tables` bugs ([CVE-2024-1086](https://nvd.nist.gov/vuln/detail/CVE-2024-1086)).
- **`NetworkPolicyDenyAll`:** works on existing CNI clusters without KEP-6313:
  - Under `nicBlockMode: DropAll` (default, intended for CNIs without `NetworkPolicy` enforcement such as `kindnet`), `dra-agents-net` flushes all non-loopback IPv4/IPv6 routes and attaches `tc clsact` `matchall` drop filters on ingress and egress of every non-loopback NIC inside the Pod netns (excluding `tun`/`tap` in `TunSidecar` mode). Because `eth0` is blocked, use `exec` probes rather than host-originated `httpGet`/`tcpSocket` probes.
  - Under `nicBlockMode: Disabled` (intended for Cilium, Calico, and other `NetworkPolicy`-enforcing CNIs), `dra-agents-net` leaves `eth0` routes and `tc` filters untouched so CNI `NetworkPolicy` isolates the Pod while preserving kubelet probes and CNI flow visibility.

## How `dra-agents-net` Works

`dra-agents-net` follows the Kubernetes Network Driver model (Ojea, IEEE LCN 2025, [doi:10.1109/LCN65610.2025.11146291](https://doi.org/10.1109/LCN65610.2025.11146291) / [arXiv:2506.23628](https://arxiv.org/abs/2506.23628)) and [DRANET](https://github.com/kubernetes-sigs/dranet): DRA handles claiming and slow-path setup before sandbox creation, and NRI handles Pod-scoped netns isolation and container adjustments without writing CDI files.

1. **Device advertisement (`DRAConsumableCapacity`):** Each node publishes one shared `resource.k8s.io/v1` device named `agents-net` (`allowMultipleAllocations: true`) with `sandboxes` capacity read from `node.Status.Allocatable.Pods()` (fallback `110`, overridable via `--max-sandboxes`) and `requestPolicy: {default: 1, validValues: [1]}`. Requires Kubernetes 1.36+ (where `DRAConsumableCapacity` is Beta and enabled by default).
2. **`PrepareResourceClaims` (DRA):** Rejects claims if NRI is disconnected. Decodes `dra.agents.net/v1alpha1` `DriverConfig` strictly (`DisallowUnknownFields`) from `DeviceClass` (`FromClass`) first and `ResourceClaim` (`FromClaim`) second. Cluster-admin settings (`confinementMode`, `nicBlockMode`, `adapterMode`, `policyEnforcementPoint`, `podCertVolumeName`, `maxConnections`, `idleTimeoutSeconds`, `custom`, and `HostPath` CA sources) are accepted only from `DeviceClass`. Namespace `ResourceClaim`s may only configure `ingressPorts`, `proxy`, and `ConfigMap`/`ClusterTrustBundle` `caTrust` sources. Opens `egress.sock`, resolves mandatory mTLS PEP auth, writes CA bundles, checkpoints state to BoltDB, and returns zero CDI devices.
3. **`RunPodSandbox` (NRI):** Enforces confinement before any container starts. In `ExplicitProxy` mode, binds `127.0.0.1:<port>` inside the Pod netns via `socketat`. Atomically updates `ResourceClaim.status.devices` (`UpdateStatus` with conflict retries) with `Ready=True` and a `dra.agents.net/v1alpha1` `DeviceStatus` JSON payload.
4. **`CreateContainer` (NRI):** Injects read-only bind mounts (`/run/agents.net`, `/var/run/agent-ca.pem`, `/var/run/agent-extra-ca.pem`), `/dev/net/tun` and `/run/agents.net/ingress` (for `agents-net-tun2connect` in `TunSidecar` mode), and non-clobbering environment variables (proxy variables in `ExplicitProxy`, CA variables when `caTrust.mode` is `InjectEnv` or unset, and `AGENT_INGRESS_PORT` when `ingressPorts` is set).
5. **`StopPodSandbox` / `RemovePodSandbox` / `UnprepareResourceClaims`:** Immediately closes active egress and ingress tunnels, updates `ResourceClaim.status.devices` to `Ready=False` (`AgentsNetRevoked`) with `ingress` cleared on `StopPodSandbox`, and removes checkpoints and socket directories on `UnprepareResourceClaims`.
6. **Startup, reconnect, and shutdown:** `--metrics-addr` (default `:9102`) binds before `driver.Start`. NRI connects (with `FailurePolicy{FailRequest: true, KeepConnected: true}`) before DRA registers with kubelet. On startup and every NRI reconnect, `Synchronize` checks running prepared Pods for missing isolation or mounts, logs an error, increments `dra_agents_net_pods_missing_plumbing_total`, and emits a `Warning` `AgentsNetPlumbingMissing` Event. On `SIGTERM`, `Stop` halts DRA first, drains prepared Pods through NRI (10s quiet grace period, 5m cap), then shuts down ingress, metrics, tunnels, and store.

### CA trust and mandatory mTLS PEP authentication

`dra-agents-net` has **no** Kubernetes `Secret` RBAC. Public CA bundles in `caTrust.sources` and `policyEnforcementPoint.tls.caCertificateRefs` accept `ConfigMap`, `ClusterTrustBundle`, and `HostPath` (default key `ca.crt`). Only X.509 `CERTIFICATE` PEM blocks are extracted.

- `caTrust.bundleMode`: `AppendSystemRoots` (default, writes system roots plus custom CAs to `/var/run/agent-ca.pem` and custom-only CAs to `/var/run/agent-extra-ca.pem`) or `Replace` (writes only custom CAs to `/var/run/agent-ca.pem`).
- `caTrust.mode`: `InjectEnv` (default, sets `AGENT_CA_CERT`, `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `PIP_CERT`, `GIT_SSL_CAINFO`, `NODE_EXTRA_CA_CERTS`, and related variables), `MountOnly`, or `None`.
- `policyEnforcementPoint.url`: must be `https://` (with mandatory mTLS) or a local node `unix://` socket. Plaintext `http://` is rejected.
- `policyEnforcementPoint.auth.type` (mandatory for `https://`):
  - `MTLS`: rotating PEM client keypair (`tls.crt`, `tls.key`) from a host or DaemonSet-mounted `certDir` (`DeviceClass` only).
  - `SPIFFE`: SPIFFE Workload API X.509-SVID mTLS (`go-spiffe/v2`).
  - `PodCertificate`: KEP-4317 kubelet-projected credential bundle mTLS.

Every upstream `CONNECT` and `connect-udp` request strips guest `Agents-Net-*` headers and attaches the portable [SPEC.md](../SPEC.md#capabilities-and-trust-boundary) headers:

- `Agents-Net-Principal`: `k8s://<namespace>/<serviceAccount>/<podName>` (or `k8s://<namespace>/<podName>`).
- `Agents-Net-Generation`: current CRI `sandboxID` (or `podUID` before sandbox creation).
- `Agents-Net-Attributes`: RFC 8941 dictionary of platform-attested fields (`node`, `ns`, `pod`, `pod_uid`, optional `sa`, plus admin `DeviceClass` `custom` keys).

### Ingress discovery and `agents-net-ingress-gateway`

Ingress is separate from egress and **off by default** (including in [install.yaml](install.yaml)). Enabling `--ingress-addr` requires mandatory mTLS flags: `--ingress-tls-cert`, `--ingress-tls-key`, and `--ingress-client-ca` (plus optional `--ingress-allowed-client-san` to pin allowed gateway DNS or URI/SPIFFE SANs).

When enabled and a Pod's `DriverConfig` sets `ingressPorts`, `dra-agents-net` serves mTLS `CONNECT <podUID>:<port> HTTP/1.1` on `--ingress-addr`, sets `AGENT_INGRESS_PORT` in workload containers, and exposes the inbound details in `ResourceClaim.status.devices[].data` without requiring a Pod IP:

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

[cmd/agents-net-ingress-gateway](cmd/agents-net-ingress-gateway) is a stateless gateway requiring only `resourceclaims` `get,list,watch` RBAC and mandatory mTLS credentials (`--bridge-ca`, `--bridge-client-cert`, `--bridge-client-key`, hot-reloaded on rotation). Place it behind a Kubernetes `LoadBalancer` Service, `Ingress`, or Gateway API `HTTPRoute`. It routes by path (`/agents/<namespace>/<pod>[:<port>]/<path>`) or headers (`X-Agents-Net-Namespace`, `X-Agents-Net-Pod` / `X-Agents-Net-Pod-Uid`, `X-Agents-Net-Port`), refuses plaintext bridge entries, and proxies HTTP over pooled mTLS `CONNECT <target>:<port>` tunnels.

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
| [cmd/dra-agents-net](cmd/dra-agents-net) | Node DaemonSet entrypoint, mandatory ingress mTLS, and `/healthz` handlers |
| [cmd/agents-net-ingress-gateway](cmd/agents-net-ingress-gateway) | Stateless mTLS ingress gateway watching `ResourceClaim` status |
| [pkg/apis](pkg/apis) | `dra.agents.net/v1alpha1` `DriverConfig` and `DeviceStatus` types |
| [pkg/params](pkg/params) | Strict `FromClass` + `FromClaim` Opaque config decoder and trust boundary checks |
| [pkg/driver](pkg/driver) | DRA plugin, NRI hooks, netlink route flush and `tc clsact` blocking, Pod informer |
| [pkg/tunnel](pkg/tunnel) | Per-Pod UDS and `socketat` listener manager, mTLS HTTP/2 + HTTP/1.1 `CONNECT` and `connect-udp` dialer |
| [pkg/ingress](pkg/ingress) | Node-side `CONNECT <podUID>:<port>` ingress bridge |
| [pkg/gateway](pkg/gateway) | `ResourceClaim` ingress registry and pooled mTLS HTTP-over-`CONNECT` reverse proxy |
| [pkg/auth](pkg/auth) | Mandatory mTLS (`MTLS`, `SPIFFE`, `PodCertificate`) resolvers and RFC 8941 attested headers |
| [pkg/catrust](pkg/catrust) | PEM CA resolver and bundle writer (`ConfigMap`, `ClusterTrustBundle`, `HostPath`) |
| [pkg/proxyenv](pkg/proxyenv) | Proxy env var matrix and non-clobbering merge |
| [pkg/socketat](pkg/socketat) | Cross-netns `DoAtNSPath`, `ListenAtPath`, and `DialAtPath` |
| [pkg/store](pkg/store) | BoltDB checkpoint store |
| [pkg/metrics](pkg/metrics) | Prometheus metrics |
| [internal/testutils](internal/testutils) | Unprivileged Linux user-namespace test harness |
| [install.yaml](install.yaml) | All-in-one manifest (`ServiceAccount`, minimal RBAC, `DeviceClass`, `DaemonSet` in `kube-system`) |
| [test/smoke.sh](test/smoke.sh) | End-to-end kind smoke test with full mTLS on both egress PEP and ingress bridge |

## Install and Usage

Install RBAC, the `dra.agents.net` `DeviceClass`, and the `dra-agents-net` DaemonSet into `kube-system`:

```bash
kubectl apply -f https://raw.githubusercontent.com/aojea/agents.net/main/kubernetes/install.yaml
```

Cluster administrators configure the PEP endpoint, mandatory mTLS auth, and confinement mode in a `DeviceClass` (`FromClass`):

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
          adapterMode: ExplicitProxy
          policyEnforcementPoint:
            url: https://egress-portal.system.svc:8443
            tls:
              trustDomain: cluster.local
            auth:
              type: SPIFFE
          custom:
            tenant: team-a
```

Workloads select that `DeviceClass` in a `ResourceClaimTemplate` and optionally declare `ingressPorts`, `proxy`, or namespace `ConfigMap` `caTrust`:

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
            deviceClassName: dra.agents.net-team-a
            allocationMode: ExactCount
            count: 1
      config:
        - requests: ["agents-net"]
          opaque:
            driver: dra.agents.net
            parameters:
              apiVersion: dra.agents.net/v1alpha1
              kind: DriverConfig
              ingressPorts:
                - port: 8080
                  protocol: TCP
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

[test/smoke.sh](test/smoke.sh) creates a kind v1.36 cluster with NRI enabled, builds and installs `dra-agents-net`, `agents-net-ingress-gateway`, and `sdk/cmd/connect-proxy`, mounts mTLS certs for both egress and ingress, and checks direct TCP blocking, mTLS HTTP/2 `CONNECT` and `connect-udp` against `connect-proxy`, mTLS `ResourceClaim` ingress discovery through a `cloud-provider-kind` `LoadBalancer` Service, port pinning, and revocation after Pod deletion.

## References

- Antonio Ojea, *"The Kubernetes Network Driver Model: A Composable Architecture for High-Performance Networking,"* 2025 IEEE 50th Conference on Local Computer Networks (LCN), [doi:10.1109/LCN65610.2025.11146291](https://doi.org/10.1109/LCN65610.2025.11146291) ([arXiv:2506.23628](https://arxiv.org/abs/2506.23628)).
- [agents.net specification](../SPEC.md)
- [Kubernetes KEP-6313: Network-Isolated Pods](https://github.com/kubernetes/enhancements/issues/6313) ([kubernetes#143280](https://github.com/kubernetes/kubernetes/pull/143280))
- [DRANET (`kubernetes-sigs/dranet`)](https://github.com/kubernetes-sigs/dranet)
- [CVE-2026-98432](https://nvd.nist.gov/vuln/detail/CVE-2026-98432) and [CVE-2024-1086](https://nvd.nist.gov/vuln/detail/CVE-2024-1086)
