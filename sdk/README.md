# agents.net Reference Implementation (Go)

This directory is the Go module `github.com/aojea/agents.net/sdk`, the
reference implementation of the [specification](../spec/draft/index.md). It
contains a library for the egress wire and for writing adapters, three
adapters (the in-guest TUN launcher, the namespace proxy, and the QEMU packet
backend), and `connect-proxy`, the reference boundary. The code lives in its
own Go module so that the gVisor dependency stays out of other build graphs.

```bash
go -C sdk build ./... && go -C sdk test -race ./...
```

| Path | Role | Contents |
| --- | --- | --- |
| [pkg/tun2connect](pkg/tun2connect) | Library | gVisor netstack engine, virtual DNS, HTTP/1.1 and HTTP/2 boundary clients, capsule framing, shared forwarder |
| [pkg/netnsproxy](pkg/netnsproxy) | Adapter | Namespace redirect adapter (nftables REDIRECT/TPROXY) |
| [pkg/qemuproxy](pkg/qemuproxy) | Adapter | QEMU `-netdev stream` packet backend |
| [cmd/tun2connect](cmd/tun2connect) | Adapter | In-guest TUN daemon and the `run` launcher (PID 1, ingress) |
| [cmd/netnsproxy](cmd/netnsproxy), [cmd/qemuproxy](cmd/qemuproxy) | Adapter | Commands for the two out-of-guest adapters |
| [cmd/connect-proxy](cmd/connect-proxy) | Boundary | Reference boundary: policy descriptor, boundary-side resolution, Proxy-Status, JSON audit, budgets, HTTP/2, connect-udp, mTLS |
| [examples/envoy-boundary.yaml](examples/envoy-boundary.yaml) | Boundary | Envoy configuration terminating CONNECT for the interop test |
| [test_envoy.sh](test_envoy.sh), [test_fuzz.sh](test_fuzz.sh) | Tests | Envoy interop and fuzz presubmits |

## Implementation Patterns

The sections below describe how each adapter attaches to its runtime. The
adapters differ in how packets reach them; all of them speak the same
protocol to the boundary.

## 1. In-Guest Networking with TUN and Virtual DNS

The most portable adapter runs a userspace TCP/IP stack (gVisor `netstack`)
behind a `tun` device inside the sandbox. The launcher creates the device
(for example `tun0`) and makes it the sandbox's default route, so every
packet the agent sends arrives in the userspace stack. That stack answers DNS
queries on port 53 itself. Instead of resolving a name over the network, it
hands back a synthetic address from a private pool (such as IPv4
`100.64.0.0/10` and IPv6 `100::/64`) and remembers which name the address
stands for. When the agent later connects to that address, the adapter looks
the name up again and puts the original hostname in the CONNECT request. A
destination with no synthetic mapping is sent as an IP literal. Both kinds of
destination travel over the same CONNECT channel, and the boundary authorizes
them the same way.

The reference adapter answers every UDP query to port 53 locally, no matter
which destination address the query was sent to, and returns synthetic A and
AAAA records. Queries for other record types get empty answers; the synthetic
resolver does not support DNSSEC or SRV discovery. TCP port 53 is not
intercepted and is tunneled like any other TCP port. If the agent obtains an
address through some other resolver, the adapter forwards it as an IP
literal, and the boundary needs an IP rule to allow it.

While the adapter runs, the synthetic ranges belong to it. A packet-based
adapter cannot distinguish a connection to a literal address inside the pool
from a connection to a DNS answer that happens to be the same address, so
your deployment has to keep the pools from overlapping real destinations.
The top `/24` of the IPv4 pool and the top `/120` of the IPv6 pool are never
allocated; adapters put their own interface and resolver addresses there.

The resolver remembers the 65,536 most recently resolved or dialed names per
address family, so a guest cannot grow the adapter's memory without bound by
resolving new names, and it never hands out the same address twice in one
lifetime. If a guest dials a cached address whose name has been evicted, the
reverse lookup misses, the adapter forwards the destination as a literal
inside the synthetic range, and the boundary denies it. The next resolution
of that name gets a fresh address. After about 4.19 million distinct names
the IPv4 pool runs out and further queries get `SERVFAIL`.

These DNS limits, together with UDP being optional, mean the current adapters
do not yet work with every networking application.

## 2. Process Supervision and Lifecycle Models

How the in-guest networking process is supervised depends on the
virtualization environment. Where the environment allows it, running the
process as PID 1 is recommended, though not required.

In a container, the recommended arrangement is to inject the launcher as the
entrypoint: bind-mount the binary into the container and set `tun2connect
run` as `--entrypoint`. The launcher then runs as PID 1. It creates the
`tun` device, starts the agent as a child, reaps orphans, forwards signals,
and exits with the agent's return code. Because it is PID 1, the sandbox
terminates if the launcher dies. Start the container with `--network none`,
`--cap-add NET_ADMIN`, and `--device /dev/net/tun`. Once the device is
configured, the launcher removes `CAP_NET_ADMIN` from all of its threads and
from the bounding set, so the agent cannot regain it through any executable.
The drop needs `CAP_SETPCAP`, which is in the default container capability
set, and a launcher built without cgo. If the drop fails, the launcher
refuses to start the agent. Other capabilities, the container UID, and
`no_new_privs` are left to the deployment.

Where the container entrypoint has to stay as it is, or in a Kubernetes pod,
the launcher can run instead as a sidecar process that shares the sandbox's
network namespace. If the sidecar terminates, the agent keeps running but
loses its only network path, so it fails closed.

In a microVM (Firecracker, Cloud-Hypervisor), the networking daemon
(`tun2connect` in the reference) runs as the guest init process
(`/sbin/init`) or as a system service and talks to the host over vsock. The
VM is configured with no network device at all; the launcher accepts
`vsock://2:<port>` as the boundary address and `-ingress-socket vsock://<port>`
for the reverse channel. It brings loopback up and, as in the container
case, needs `CAP_NET_ADMIN` only until the TUN exists.
[scenarios/09-firecracker-vsock/init.sh](../scenarios/09-firecracker-vsock/init.sh)
is a minimal guest init built this way.

## 3. Network Namespace Proxy

Instead of a TUN inside the guest, the workload's veth peer or the VM's TAP
can sit in a dedicated network namespace where a userspace socket proxy picks
up its traffic:

```text
workload NIC -> veth/TAP in proxy namespace -> nftables -> kernel socket
                                    |
                                shared Forwarder
                                    |
                             dedicated Unix socket
                                    |
                             boundary policy proxy
```

The namespace has no external network interface. Its workload-facing
interface carries a local IPv4 address and, when IPv6 is enabled, a local
IPv6 address, and the workload uses those addresses as its gateway and DNS
server. Before starting the proxy, the controller creates the namespace,
attaches the interface, installs the workload's routes, and makes the
boundary Unix socket reachable.

TCP is intercepted with nftables REDIRECT and the original destination
recovered with `SO_ORIGINAL_DST`. UDP uses TPROXY and policy routing, which
preserve the destination address and port. DNS returns the same synthetic
addresses as the TUN adapter, and both adapters share `Forwarder` for CONNECT
dialing by hostname or IP and for the socket relays. UDP other than DNS is
disabled unless requested. The namespace drops routed forwarding and
restricts local input from the workload interface; ICMP stays local for
network control traffic.

Build the command and run it inside the prepared namespace:

```bash
go -C sdk build -o /tmp/netnsproxy ./cmd/netnsproxy
ip netns exec sandbox-proxy /tmp/netnsproxy \
    -interface proxy0 -proxy unix:///run/agents.net/boundary.sock -udp -ipv6
```

The command needs `CAP_NET_ADMIN` in the proxy namespace. Don't run it in the
host's root network namespace, and keep untrusted workload processes in a
namespace of their own. `ip netns exec` restricts neither filesystem nor
process access, so the runtime must also confine the proxy to its assigned
socket and protect host files, processes, and management endpoints as
described in [identity.md](../spec/draft/identity.md#2-isolation-and-channel-ownership).
The proxy refuses to start if the namespace has any non-loopback interface
other than the one it was given. It installs its own nftables table
(`agents_net` by default), uses routing table and priority `16666`, and
reserves packet mark `0x616e`; it does not flush other tables.

Stopping the proxy closes its sockets but leaves the nftables rules and
policy routes in place. The controller is expected to stop the workload and
destroy the namespace; restarting the proxy requires a fresh one. Removing
the rules while the workload is still running is not a supported way to shut
down.

A TCP flow the boundary refuses is reset after the kernel has already
accepted the local connection, whereas the TUN adapter can refuse before the
guest handshake completes. Denied UDP sessions are dropped, and the error the
client sees depends on its socket and destination. Neither adapter falls back
to the direct network.

To use the library from a process that is already in the dedicated
namespace:

```go
forwarder := &tun2connect.Forwarder{
        DNS: tun2connect.NewVirtualDNS(),
        Dialer: &tun2connect.BoundaryClient{DialBoundary: func(ctx context.Context) (net.Conn, error) {
                var dialer net.Dialer
                return dialer.DialContext(ctx, "unix", "/run/agents.net/boundary.sock")
        }},
}
proxy, err := netnsproxy.New(netnsproxy.Config{
        Interface: "proxy0", Forwarder: forwarder, EnableUDP: true,
})
if err != nil {
        return err
}
defer proxy.Close()
return proxy.Run(ctx)
```

The forwarder also accepts the HTTP/2 boundary client, or any other
implementation of `tun2connect.Dialer`. The command exposes this as `-h2`,
and `-max-connections` (default 1024) caps the combined number of TCP, UDP,
and DNS sessions. Each UDP session has a bounded packet queue and an idle
timeout.

The live test uses two network namespaces and a real veth pair. It needs
Linux with unprivileged user namespaces, `unshare`, `nsenter`, and kernel
support for nftables REDIRECT and TPROXY, and it changes no rules in the host
namespace:

```bash
NETNS_PROXY_INTEGRATION=1 go -C sdk test -race -count=1 -v \
    ./pkg/netnsproxy -run '^TestNamespaceIntegration$'
```

It covers IPv4 and IPv6 DNS, TCP streaming and half-close, hostname and
literal IP targets, UDP flows to several destinations, refusals, and
shutdown. It does not exercise TAP or VM traffic.

## 4. QEMU Userspace Packet Backend

A VM NIC can also terminate in an isolated userspace adapter, with neither a
host TAP nor a guest TUN. The reference `qemuproxy` command accepts QEMU's
`-netdev stream` Ethernet framing over a dedicated pathname Unix socket,
feeds the frames to gVisor netstack, and uses the shared DNS-aware forwarder
to issue HTTP/1.1 CONNECT requests on a second, dedicated boundary socket.
Application data, including HTTP GET or nested CONNECT bytes, passes through
as opaque tunnel payload; the adapter never chooses the CONNECT authority by
inspecting application headers.

The adapter needs the filesystem, process, and network confinement described
in [identity.md](../spec/draft/identity.md#2-isolation-and-channel-ownership),
and QEMU must have no other external network backend. The packet channel
lives as long as the VM and does not reconnect, so the controller stops the
VM when its adapter fails. A restart, snapshot, or restore must not attach
fresh synthetic DNS state to a guest that still holds old mappings.

The reference uses static gateway addresses, a 1500-byte MTU, disabled
offloads, bounded packet queues, and a combined session limit, and it needs
no networking daemon in the guest. It is an external backend that speaks
QEMU's stream protocol, not a patch to QEMU itself. The
[QEMU integration](../scenarios/10-qemu-stream/README.md) documents the
configuration, its restrictions, and the two-VM IPv4 and IPv6 tests that have
been run. Ingress, DHCP, snapshot/restore, and migration are not implemented
for this path.

## 5. Reference Boundary and Library

The main source files of the module `github.com/aojea/agents.net/sdk`, and
what each one holds:

- [sdk/pkg/tun2connect/engine.go](../sdk/pkg/tun2connect/engine.go): the userspace gVisor netstack engine that connects a TUN device to an HTTP CONNECT dialer.
- [sdk/pkg/tun2connect/dns.go](../sdk/pkg/tun2connect/dns.go): the virtual DNS server, which allocates synthetic addresses and maps them back to names at dial time.
- [sdk/pkg/tun2connect/dialer.go](../sdk/pkg/tun2connect/dialer.go): the `Dialer` interface and its HTTP/1.1 (`BoundaryClient`) and HTTP/2 (`BoundaryClientH2`) implementations.
- [sdk/pkg/tun2connect/forwarder.go](../sdk/pkg/tun2connect/forwarder.go): DNS-aware dialing and the TCP and UDP socket relays shared by all adapters.
- [sdk/pkg/netnsproxy/proxy_linux.go](../sdk/pkg/netnsproxy/proxy_linux.go): the kernel socket adapter and its namespace-local nftables setup.
- [sdk/cmd/netnsproxy/main_linux.go](../sdk/cmd/netnsproxy/main_linux.go): the namespace proxy command, which reaches the boundary over a Unix socket.
- [sdk/cmd/connect-proxy/main.go](../sdk/cmd/connect-proxy/main.go): the reference boundary. It loads a [policy descriptor](../spec/draft/policy.md), resolves names itself and dials only the addresses it has checked, speaks HTTP/1.1 and multiplexed HTTP/2, tunnels UDP capsules, verifies mTLS client certificates, enforces connection and idle budgets, reports failures with `Proxy-Status`, and writes one JSON audit record per decision. [policy.go](../sdk/cmd/connect-proxy/policy.go) holds the descriptor loader and the authorization logic.
- [sdk/cmd/tun2connect/main.go](../sdk/cmd/tun2connect/main.go): the in-guest side. It runs either as a standalone daemon or, with `run`, as the launcher that becomes PID 1, creates the TUN, and supervises the agent.

The boundary reads its whole policy from one file, given as
`-policy descriptor.json`, in the [descriptor format](../spec/draft/policy.md).
A descriptor holds allow rules on exact names, name suffixes, the `*`
wildcard, literal addresses, and prefixes. Each rule may restrict ports
(integers or `"a-b"` ranges) and transports, and a name rule may carry a
static `resolve` list that is used instead of DNS. The descriptor's `sandbox`
and `version` fields label every audit record, and `-generation` adds the
controller's generation label. `features.udp` enables connect-udp.
`-resolver host:port` pins the DNS server the boundary queries instead of
using the system resolver. Policy is not configurable through flags. For
example:

```bash
cat > /run/agents.net/sandbox-a/policy.json <<'EOF'
{"agents_net_policy": 1, "version": "2026-09-17/1", "sandbox": "sandbox-a", "default": "deny",
 "rules": [
   {"id": "api", "name": "api.example.com", "ports": [443]},
   {"id": "pkgs", "suffix": "pkg.github.com", "ports": [443]},
   {"id": "db", "ip": "203.0.113.10", "ports": [5432]},
   {"id": "v6", "cidr": "2001:db8::/64", "ports": [443], "transports": ["tcp", "udp"]}
 ],
 "features": {"udp": true}}
EOF
go -C sdk run ./cmd/connect-proxy \
    -listen unix:///run/agents.net/sandbox-a/boundary.sock \
    -policy /run/agents.net/sandbox-a/policy.json -generation 1
```

For a hostname request the boundary resolves the name itself and keeps only
public unicast results. Loopback, private, link-local, multicast,
shared-address-space, NAT64, documentation, and other special-purpose ranges
([wire.md §5.1](../spec/draft/wire.md#51-special-purpose-addresses)) are
denied unless a `resolve` list, a literal rule for that port, or a
`resolved_addresses` entry admits them. The boundary then dials the checked
address rather than the name, so a rebinding answer cannot change the
destination after the check. As a result, `{"name": "*"}` still cannot reach
`localhost`, a metadata service, or a private network, and it never
authorizes a literal. Names are lowercased, stripped of a trailing dot, and
converted to A-labels before matching. Ports must be numeric and in the range
1-65535. Denials carry `not-on-allowlist`, `port-not-allowed`,
`transport-not-allowed`, `ip-not-on-allowlist`, `resolved-address-denied`,
`scoped-ip` (a zoned IPv6 literal), or `udp-disabled` (a connect-udp
request under a descriptor without `features.udp`) in the `reason`
parameter of `Proxy-Status`, for example
`Proxy-Status: boundary; error=http_request_denied; reason=not-on-allowlist`.
A listener with no descriptor loaded answers 503 `policy-unavailable`, and
the command refuses to start without `-policy`.

The boundary parses the HTTP/1.1 request head itself rather than with
`net/http.ReadRequest`, because that reader discards the `Host` field before
it can be compared with the CONNECT authority. The request line must have
exactly three fields separated by single spaces, with a token method and a
version of HTTP/1.0 or HTTP/1.1. There may be at most one `Host` field (and
HTTP/1.1 requires one), header names may not have whitespace before the
colon, and the whole head may not exceed 64 KiB. For CONNECT, the authority
must be a host and a numeric port with no userinfo, path, or query, and the
`Host` field must name the same destination after case, trailing-dot, and
IP-text normalization. `Content-Length` and `Transfer-Encoding` are ignored
on CONNECT; any bytes after the head are tunnel data and reach the upstream
only after a 200. Malformed requests get 400 (`malformed-request-line`,
`malformed-header`, `duplicate-host`, `missing-host`, `malformed-target`,
`malformed-port`, `authority-mismatch`, `malformed-upgrade`,
`malformed-template`), an unsupported version 505, an oversized head 431, a
non-CONNECT method 405, and a policy denial 403. Names, whether in a request
or in the descriptor, are validated after IDNA conversion as dot-separated
labels of letters, digits, hyphens, and underscores. Before that check
existed, a fuzzer found that `..` normalized to `.` was accepted as a name.

The boundary applies several resource limits. `-max-connections` caps
accepted connections or HTTP/2 sessions (default 1024); connections over the
cap receive 503 `busy` before their request head is read. `-max-streams`
caps concurrent streams per HTTP/2 session (default 256). A request head
must arrive within 15 seconds. `-idle-timeout` (default 1h) closes a tunnel
that has carried no data in either direction for that long; 0 disables it.
When the client sends EOF, the boundary half-closes the upstream.

Every decision is written to standard output as one JSON object in the
[audit record format](../spec/draft/audit.md). The fields are `ts`,
`listener`, `sandbox`, `generation`, `policy`, `wire`, `transport`,
`destination` (as requested, after normalization), `address` (as dialed),
`peer` (the mTLS identity when there is one), `connection` (an id shared by
every record of one accepted connection or HTTP/2 session), `rule` (the
`id` of the rule that allowed the request), `decision` (`allow`, `block`,
or `fail`), and `reason`. Every refused request is recorded, including
non-CONNECT methods and connections turned away for budget. Values supplied
by the guest are encoded as JSON strings, so they cannot inject fields or
lines. The Python demo keeps its hostname-only allowlist as a sample policy
and dials names directly, without a resolved-address or port check.

Incomplete TLS flag combinations are rejected before the boundary listens:
`-tls-client-ca` requires both `-tls-cert` and `-tls-key`, and setting it
makes verified client certificates mandatory. TLS requires at least version
1.2 and gives the handshake 15 seconds. Certificate identities are
audit-only on both HTTP/1.1 and HTTP/2; the command applies one destination
policy to every peer rather than authorizing per identity.

One process with one listener is enough to serve the fixed per-sandbox
policy of the baseline. On its own that is not a complete secure deployment.
The runtime still has to expose the socket exclusively and control the
process lifecycle, revocation means terminating the process without
draining, and HTTP/2 stream validation is left to `golang.org/x/net/http2`.
If unrelated sandboxes shared this listener they would share its policy, and
adding an identity header would not separate them.

## 6. Demo

The demo runs an autonomous ReAct agent inside a Docker container that has no
network of its own, confined by the injected `tun2connect` launcher:

![agents.net terminal demo](../demo/terminal-demo.gif)

- [demo/README.md](../demo/README.md): how to build and run the sandbox, step by step.
- [demo/host_proxy.py](../demo/host_proxy.py): a Python host boundary with a four-tier allowlist (fake responses, a relay to local Ollama, cloud credential injection, and uninspected passthrough). Credential injection rewrites only the first request on each tunnel; later requests on a reused connection pass through unchanged, which a production gateway must not allow ([gateway.md](../spec/draft/gateway.md#2-credential-placement-and-tenant-isolation)).
- [demo/agent.py](../demo/agent.py): a sample ReAct agent that reasons autonomously, runs tools, and handles connection refusals.
- [demo/gen_certs.sh](../demo/gen_certs.sh): generates the demo root CA and multi-SAN leaf certificates.
- [demo/Dockerfile](../demo/Dockerfile): a Debian-based container image for the agent.
- [demo/test_demo.sh](../demo/test_demo.sh): the presubmit, which checks fail-closed isolation, TLS fake responses, and ingress webhooks.
