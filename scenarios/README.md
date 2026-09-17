# Boundary Networking Experiments

These are component experiments supporting the [agents.net contract](../README.md),
not a complete comparison of production isolation architectures.
The specification defines the target security and interoperability requirements
and records the implementation gaps. Directory names are retained for compatibility;
the table below describes the actual implementation.

## Actual Topologies

| ID | Driver | Executed path | What it does not prove |
| --- | --- | --- | --- |
| 01 | [Container TUN](01-container-in-capsule/run.sh) | Docker `--network none`, guest TUN/netstack, UDS proxy, host HTTPS target | Multi-tenant policy, host-kernel isolation, or density |
| 02 | [Direct proxy](02-container-boundary/run.sh) | Host Python/curl using an explicit TCP loopback proxy | Container boundary interception, UDS performance, or native gVisor |
| 03 | [Docker bridge](03-container-out-capsule/run.sh) | Docker bridge to a host HTTPS target | An equivalently secured production CNI baseline |
| 04 | [TUN and local VSOCK](04-microvm-vsock/run.sh) | User/network namespaces, TUN, VSOCK CID 1 loopback | Booted VM, guest-to-host virtqueues, or hardware attestation |
| 05 | [slirp4netns](05-microvm-userspace-nic/run.sh) | Linux namespace connected by slirp4netns | VM virtio-net or vhost-user-net performance |
| 06 | [Bridge with TAP creation](06-microvm-tap-netns/run.sh) | Docker bridge; an extra TAP is created but not used for the transfer | Traffic through TAP, a VM NIC, or isolation of host-kernel code |
| 07 | [Forwarder and local VSOCK](07-microvm-vsock-boundary/run.sh) | Namespace TCP loopback proxy forwarded to VSOCK CID 1 | Native VM socket interception or elimination of all TCP packetization |
| 08 | [Host TAP permission probe](08-microvm-tap-host/run.sh) | Attempts host TAP creation and reports permissions | Throughput, scaling, or a security violation |
| 09 | [Firecracker vsock](09-firecracker-vsock/run.sh) | Two Firecracker microVMs (KVM, no network device), in-guest TUN launcher as init, boundary per VM on Firecracker's `<uds>_<port>` socket, disjoint port-scoped policies, forged raw CONNECT, unbound port, ingress into the pinned guest loopback port, boundary kill mid-transfer with a replacement policy | Guest attestation, other VMMs, performance, draining, or resistance to a hypervisor escape |
| 10 | [QEMU stream](10-qemu-stream/README.md) | Two QEMU microVMs (KVM, virtio-net), separate confined userspace packet adapters, dedicated CONNECT boundaries, IPv4/IPv6 TCP and DNS, disjoint policies, revocation, adapter-loss supervision | Ingress, DHCP, live UDP, snapshot/migration, performance, or portable conformance |

Scenarios 04 and 07 predate 09 and use VSOCK CID 1 loopback inside namespaces;
they are retained as historical measurements. Scenario 09 boots real guests and
is the executed evidence for the VM channel described in the specification.
It requires `firecracker` on `PATH`, read/write access to `/dev/kvm`,
Docker for the rootfs build, `jq` for the audit assertions, and `mke2fs`
1.47.1 or later with libarchive support (older `mke2fs` works when
passwordless `sudo` is available, as on CI runners). It downloads the
Firecracker CI guest kernel (digest pinned in the driver)
into `~/.cache/agents.net`. It is not part of `benchmark.sh`; it runs in the
[Firecracker workflow](../.github/workflows/firecracker.yml) on GitHub-hosted
runners:

```bash
./scenarios/09-firecracker-vsock/run.sh
```

There is no executable eBPF comparison or native Sentry adapter in
these drivers. VSOCK CID 1 is local communication; the normal host CID is 2.
Firecracker implements virtio-vsock in userspace and maps guest ports to host
Unix sockets; a VMM that exposes host `AF_VSOCK` is a different integration.

## Measurement Limits

The client runs fresh curl transfers to a local HTTPS endpoint. Historical
runs used five rounds of 20 requests and three 50 MiB downloads. Curl timing
fields are cumulative milestones from transfer start, not disjoint DNS/TCP/TLS
durations. Explicit-proxy milestones describe a different setup path from
direct connections. Throughput uses bytes divided by 1024 squared: MiB/s.

Repeated rounds characterize variation on that host, not causality, independent
machines, production p99, or architectural superiority. Host-wide conntrack
snapshots include unrelated activity and expiration; absence of the counter is
unknown, not zero. No routed workload address does not imply no upstream
conntrack. Security and tenant identity must be tested separately from timings.

The [historical record](data/results.md) preserves reported measurements without
claiming they were rerun or that raw per-request samples are available for those
runs. New runs should preserve raw output and never overwrite that record.

## Reproduction

Prerequisites are Linux, the Go version in [go.mod](go.mod), Docker access,
Python 3, curl, iproute2, slirp4netns, `/dev/net/tun`, local VSOCK support,
unprivileged user namespaces, and permitted namespace mounts. Build the demo
image and launcher using [the demo tutorial](../demo/README.md) first. Docker
must be able to bind-mount this checkout and the temporary run directories.

From the repository root:

```bash
./scenarios/benchmark.sh
```

The runner builds scenario helpers and rebuilds the launcher from source.
It writes a timestamped report and raw scenario output to a new directory under
`scenarios/data/`. It stops on failed scenarios and preserves their output;
missing prerequisites are not successful measurements. The tests create
containers/namespaces, bind local ports, and attempt host TAP creation. Do not
run concurrent copies or run on a host where those operations are inappropriate.

Individual drivers use fixed temporary paths and ports. They are development
experiments, not a hardened multi-user benchmark service. The scenario
[boundary helper](cmd/boundary-proxy/main.go) allows every hostname by default,
makes its socket world-connectable, and dials names without checking resolved
addresses; it exists to measure the data path and is not the reference
boundary described in the main specification. The historical
route-flush and CID scripts are limited smoke tests, not security certification.

## Local Validation

```bash
go test -race -count=1 ./tun2connect/... ./scenarios/...
python3 -m unittest discover -s demo -p test_host_proxy.py
python3 -m unittest discover -s scenarios/common -p 'test_*.py'
```

These checks do not start VMs or run the privileged benchmark drivers. Live
Envoy and Docker demonstration tests have separate prerequisite-dependent
scripts described in the main specification.
