# agents.net

`agents.net` is a standalone Kubernetes network driver and reference implementation for isolated AI agent sandboxes. It removes direct network access from Pods and sends all TCP, UDP, and DNS traffic through an unprivileged userspace network stack on the host to an external Policy Enforcement Point (PEP) over mTLS HTTP `CONNECT`, `connect-udp`, and DoH.

It does not depend on a CNI plugin, does not inject sidecar containers into workload Pods, and does not rely on `HTTP_PROXY` environment variables. Unmodified applications inside `runc` containers, `gVisor` sandboxes, and KVM microVMs use standard sockets and DNS.

See [docs/architecture.md](docs/architecture.md) for the design background, security model, and how this connects to SIG Network, [KEP-6313](https://github.com/kubernetes/enhancements/issues/6313), [GAIA](https://gateway-api.sigs.k8s.io/), and [agent-sandbox](https://github.com/kubernetes-sigs/agent-sandbox).

## How it works

```text
  Sandbox Pod (non-root, drop ALL caps, no sidecar, no secrets)
    - runc:    lo + tun0 + ro /etc/resolv.conf
    - gVisor:  eth0 (host veth moved to an empty isolated netns)
    - microVM: virtio-net TAP (or AF_VSOCK with kube-tun2connect)
                       |
            tunFD / packetFD / tapFD
                       v
  kube-netstack (unprivileged container, uid 65534, 0 caps, AF_UNIX-only seccomp)
    Terminates guest TCP/IP and Virtual DNS (198.18.0.0/15, 100::/64)
                       |
          emptyDir AF_UNIX socket + SCM_RIGHTS
                       v
  kube-net-driver (DRA + NRI node DaemonSet, no CNI)
    Plumbs sandbox interfaces, closes packet FDs after handoff, attaches
    node-attested workload identity, dials PEP over mTLS, serves opt-in
    mTLS inbound CONNECT <podUID>:<port>
                       |
    mTLS HTTP/2 CONNECT / RFC 9298 connect-udp / RFC 8484 DoH
                       v
  Policy Enforcement Point and Inbound Gateway
    Envoy, GAIA, kube-pep, kube-inbound, or any HTTP CONNECT proxy
```

## Binaries

| Binary | Role |
| --- | --- |
| `kube-net-driver` | Per-node DRA (`dra.agents.net`) and NRI DaemonSet container. Prepares claims, plumbs `tun0` or isolated L2 `veth` peers, handles mTLS egress forwarding, and runs the optional mTLS ingress bridge. |
| `kube-netstack` | Unprivileged companion container in the DaemonSet (`distroless:nonroot`, UID `65534`, zero capabilities, `AF_UNIX`-only seccomp, no K8s token or mTLS keys). Runs the userspace TCP/IP stack and Virtual DNS over file descriptors passed by `kube-net-driver`. |
| `kube-pep` | Reference egress PEP supporting mTLS HTTP/2 `CONNECT`, RFC 9298 `connect-udp`, RFC 8484 DoH, anti-SSRF IP checks, and JSONL audit logs. |
| `kube-inbound` | Reference stateless inbound gateway that watches `ResourceClaim.status` and forwards external HTTP requests to IP-less sandboxes over mTLS `CONNECT`. |
| `kube-tun2connect` | Standalone TUN-to-CONNECT launcher for zero-NIC microVMs (`AF_VSOCK`). |

## Quick start

Requires Kubernetes 1.36+ (`DRAConsumableCapacity` enabled by default) and `containerd` or `CRI-O` with NRI enabled.

Install the DaemonSet and default `DeviceClass`:

```bash
kubectl apply -f https://raw.githubusercontent.com/aojea/agents.net/main/install.yaml
```

Cluster admins configure confinement, DNS mode, and the PEP endpoint in a `DeviceClass`:

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
          dns:
            mode: DoH
          policyEnforcementPoint:
            url: https://kube-pep.system.svc:8443
            tls:
              trustDomain: cluster.local
            auth:
              type: SPIFFE
          custom:
            tenant: team-a
```

Workloads request a claim from that class and run with no extra containers or capabilities:

```yaml
apiVersion: resource.k8s.io/v1
kind: ResourceClaimTemplate
metadata:
  name: agent-net
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
spec:
  automountServiceAccountToken: false
  resourceClaims:
    - name: agents-net
      resourceClaimTemplateName: agent-net
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

## Configuration notes

- `confinementMode` defaults to `PodNetworkIsolated` for [KEP-6313](https://github.com/kubernetes/enhancements/issues/6313) loopback-only Pods (no CNI, no Pod IP). On existing CNI clusters, set `NetworkPolicyDenyAll`: `nicBlockMode: DropAll` (default) blocks `eth0` with `tc clsact`, while `nicBlockMode: Disabled` leaves `eth0` to CNI `NetworkPolicy` and keeps return routing in table `100` for kubelet probes. For `gVisor` (`RuntimeClass` handler `runsc`), the driver moves the host `veth` peer into an isolated empty network namespace and hands an `AF_PACKET` descriptor to `kube-netstack`.
- `dns.mode` defaults to `Synthetic`, which resolves names locally into `198.18.0.0/15` and `100::/64` and works with any HTTP `CONNECT` proxy. Setting `DoH` forwards RFC 8484 `POST /dns-query` over the PEP's mTLS HTTP/2 session (or an optional separate `dns.enforcementPoint`), preserving Kubernetes search domains, `ndots:5`, and real `NXDOMAIN` responses while still rewriting positive answers into the synthetic pool.
- Inbound traffic without Pod IPs is opt-in. Set `--ingress-addr` with `--ingress-tls-cert`, `--ingress-tls-key`, and `--ingress-client-ca` on `kube-net-driver` and declare `ingressPorts` on the claim. Health checks (`/healthz`, `/healthz/dra`, `/healthz/nri`) and Prometheus metrics (`/metrics`) listen on `--metrics-addr` (default `:9102`).

## Build and test

```bash
make build                                # Build all five kube-* binaries
make test                                 # Unit and Linux netns integration tests (-race)
make vet                                  # go vet and formatting checks
USE_CLOUD_PROVIDER_KIND=true ./test/smoke.sh  # kind v1.36 runc E2E (Synthetic + DoH + inbound)
make test-envoy                           # Envoy v1.36 PEP + inbound E2E
make test-gvisor                          # kind v1.36 gVisor (runsc) E2E
make test-microvm                         # KVM microVM E2E (QEMU TAP + Firecracker vsock)
```

Earlier standalone prototypes outside Kubernetes remain in git history at commit [`11d845b`](https://github.com/aojea/agents.net/tree/11d845b).

## License

See [LICENSE](LICENSE) and [COPYRIGHT.md](COPYRIGHT.md).
