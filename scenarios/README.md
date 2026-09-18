# Boundary Networking Experiments

The scenarios in this directory are component experiments that support the
[agents.net specification](../spec/draft/index.md). They aren't a complete
comparison of production isolation architectures; the specification defines
the security and interoperability requirements and records the implementation
gaps. The directory names are kept for compatibility, so read the table below
for what each driver does today.

## Actual Topologies

| ID | Driver | Executed path | What it does not prove |
| --- | --- | --- | --- |
| 01 | [Container TUN](01-container-in-capsule/run.sh) | Docker `--network none`, guest TUN/netstack, UDS proxy, host HTTPS target | Multi-tenant policy, host-kernel isolation, or density |
| 02 | [Direct proxy](02-container-boundary/run.sh) | Host Python/curl using an explicit TCP loopback proxy | Container boundary interception, UDS performance, or native gVisor |
| 03 | [Docker bridge](03-container-out-capsule/run.sh) | Docker bridge to a host HTTPS target | An equivalently secured production CNI baseline |
| 04 | [TUN and local vsock](04-microvm-vsock/run.sh) | User/network namespaces, TUN, vsock CID 1 loopback | Booted VM, guest-to-host virtqueues, or hardware attestation |
| 05 | [slirp4netns](05-microvm-userspace-nic/run.sh) | Linux namespace connected by slirp4netns | VM virtio-net or vhost-user-net performance |
| 06 | [Bridge with TAP creation](06-microvm-tap-netns/run.sh) | Docker bridge; an extra TAP is created but not used for the transfer | Traffic through TAP, a VM NIC, or isolation of host-kernel code |
| 07 | [Forwarder and local vsock](07-microvm-vsock-boundary/run.sh) | Namespace TCP loopback proxy forwarded to vsock CID 1 | Native VM socket interception or elimination of all TCP packetization |
| 08 | [Host TAP permission probe](08-microvm-tap-host/run.sh) | Attempts host TAP creation and reports permissions | Throughput, scaling, or a security violation |
| 09 | [Firecracker vsock](09-firecracker-vsock/run.sh) | Two Firecracker microVMs (KVM, no network device), in-guest TUN launcher as init, boundary per VM on Firecracker's `<uds>_<port>` socket, disjoint port-scoped policies, forged raw CONNECT, unbound port, ingress into the pinned guest loopback port, boundary kill mid-transfer with a replacement policy | Guest attestation, other VMMs, performance, draining, or resistance to a hypervisor escape |
| 10 | [QEMU stream](10-qemu-stream/README.md) | Two QEMU microVMs (KVM, virtio-net), separate confined userspace packet adapters, dedicated CONNECT boundaries, IPv4/IPv6 TCP and DNS, disjoint policies, revocation, adapter-loss supervision | Ingress, DHCP, live UDP, snapshot/migration, performance, or portable conformance |

Scenarios 04 and 07 predate 09. They use vsock CID 1 loopback inside
namespaces and are kept as historical measurements. Scenario 09 boots real
guests and is the executed evidence for the VM channel the specification
describes. It needs `firecracker` on `PATH`, read/write access to `/dev/kvm`,
Docker for the rootfs build, `jq` for the audit assertions, and `mke2fs`
1.47.1 or later with libarchive support (an older `mke2fs` works when
passwordless `sudo` is available, as it is on CI runners). The driver
downloads the Firecracker CI guest kernel, whose digest is pinned in the
script, into `~/.cache/agents.net`. Scenario 09 is not part of `benchmark.sh`;
it runs in the [Firecracker workflow](../.github/workflows/firecracker.yml) on
GitHub-hosted runners, or by hand:

```bash
./scenarios/09-firecracker-vsock/run.sh
```

None of these drivers includes an eBPF comparison or a native Sentry adapter.
vsock CID 1 is the local loopback CID; the host itself is normally CID 2.
Firecracker implements virtio-vsock in userspace and maps guest ports to host
Unix sockets, so a VMM that exposes host `AF_VSOCK` would be a different
integration.

## Measurement Limits

The client runs fresh curl transfers to a local HTTPS endpoint. Historical
runs used five rounds of 20 requests and three 50 MiB downloads. Curl's timing
fields are cumulative milestones measured from the start of the transfer, so
they can't be read as separate DNS, TCP, and TLS durations. With an explicit
proxy the milestones also follow a different setup path than a direct
connection does. Throughput is bytes divided by 1024 squared, in MiB/s.

Repeated rounds show how much the numbers vary on that one host. They don't
establish cause, generalize to other machines, predict a production p99, or
rank architectures. Host-wide conntrack snapshots include unrelated activity
and entry expiry, and when the counter is missing the value is unknown rather
than zero. A workload without a routed address can still create conntrack
entries upstream. Security and tenant identity can't be inferred from timings
and have to be tested separately.

The [historical record](data/results.md) keeps the measurements as they were
reported; it doesn't claim they were rerun or that raw per-request samples
exist for those runs. New runs should keep their raw output and leave that
record untouched.

## Reproduction

You need Linux, the Go version in [go.mod](go.mod), Docker access, Python 3,
curl, iproute2, slirp4netns, `/dev/net/tun`, local vsock support, unprivileged
user namespaces, and permission to mount inside namespaces. Build the demo
image and launcher by following [the demo tutorial](../demo/README.md) first.
Docker must be able to bind-mount this checkout and the temporary run
directories.

From the repository root:

```bash
./scenarios/benchmark.sh
```

The runner builds the scenario helpers and rebuilds the launcher from source,
then writes a timestamped report and the raw output of each scenario to a new
directory under `scenarios/data/`. It stops at the first failed scenario and
keeps that scenario's output; a run that fails on a missing prerequisite
doesn't count as a measurement. The scenarios create containers and
namespaces, bind local ports, and attempt to create a host TAP device, so
don't run two copies at once or run on a host where those operations are
unwelcome.

Individual drivers use fixed temporary paths and ports; they are development
experiments and haven't been hardened as a multi-user benchmark service. The
scenario [boundary helper](cmd/boundary-proxy/main.go) allows every hostname
by default, makes its socket world-connectable, and dials names without
checking the resolved addresses. It exists to measure the data path; the
reference boundary is the one described in [sdk/README.md](../sdk/README.md).
The historical route-flush and CID scripts are small smoke tests and don't
certify anything about security.

## Local Validation

```bash
go test -race -count=1 ./sdk/... ./scenarios/...
python3 -m unittest discover -s demo -p test_host_proxy.py
python3 -m unittest discover -s scenarios/common -p 'test_*.py'
```

These checks don't start VMs or run the privileged benchmark drivers. The live
Envoy and Docker demonstration tests have their own scripts with their own
prerequisites, described in [sdk/README.md](../sdk/README.md) and [demo/README.md](../demo/README.md).

The [conformance suite](../conformance/README.md) runs its HTTP/1.1
boundary fixtures against the reference boundary through a driver script. It
needs only Go, Python 3, and loopback networking:

```bash
python3 conformance/harness/run_boundary.py \
    --driver conformance/harness/drivers/connect-proxy.sh --keep-going
```
