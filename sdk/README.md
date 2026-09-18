# agents.net Reference Implementation (Go)

Module `github.com/aojea/agents.net/sdk`. It implements the
[specification](../spec/draft/index.md): a library for the egress wire and
adapters, three adapters (in-guest TUN launcher, namespace proxy, QEMU packet
backend), and the reference boundary `connect-proxy`. It is a standalone Go
module so that gVisor stays out of other build graphs.

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

The adapter depends on the runtime. The boundary protocol does not.

## 1. In-Guest Networking with TUN and Virtual DNS

A common and portable implementation pattern uses a userspace TCP/IP stack (such as gVisor `netstack`) attached to a virtual `tun` device:

1. **TUN Interface:** A `tun` interface (e.g. `tun0`) is created inside the sandbox and configured as the default gateway.
2. **Virtual DNS (Name Preservation):** The in-guest stack intercepts local DNS queries on port 53. Instead of resolving them over the network, it returns a synthetic IP address allocated from a private pool (e.g., IPv4 `100.64.0.0/10` and IPv6 `100::/64`).
3. **Dial-Time Lookup:** If the destination has a synthetic DNS mapping, the adapter sends the original hostname to the boundary. Otherwise it sends the IP address. Both forms use the same CONNECT channel and boundary authorization.

The reference adapter answers UDP port 53 locally regardless of its destination,
returning synthetic A/AAAA records. Other record types receive empty answers.
DNSSEC and SRV discovery are not supported by this synthetic resolver. TCP port
53 is tunneled normally. Addresses obtained through other resolver paths are
forwarded as IP literals and require IP policy at the boundary.

The synthetic address ranges are reserved while the adapter is running. If a
literal destination equals an allocated synthetic address, a packet-based
adapter cannot distinguish it from a connection made using that DNS answer.
Deployments must avoid overlap with real destinations. The reference resolver
remembers the 65,536 most recently resolved or dialed names per address
family, so guest-chosen names cannot grow adapter memory without bound. It
never reuses an address within one adapter lifetime: a guest that dials a
cached address whose name has been forgotten produces a reverse miss, the
destination is forwarded as a literal in the synthetic range, and the boundary
denies it, after which re-resolution yields a fresh address. The top `/24`
of the IPv4 pool and `/120` of the IPv6 pool are never allocated; adapters
place their own interface and resolver addresses there. The IPv4 pool is
exhausted, answering `SERVFAIL`, after about 4.19 million distinct names.
These DNS limitations
and optional UDP support mean the current adapters do not yet provide full
compatibility with every networking application.

## 2. Process Supervision and Lifecycle Models

The supervision model for the in-guest networking process depends on the host virtualization environment. Running as **PID 1 is recommended where applicable, but not required**:

- **Container Entrypoint Injection (Recommended for Containers):** The launcher binary (e.g. `tun2connect run`) is bind-mounted into the container and set as `--entrypoint`. It executes as PID 1, initializes the `tun` device, runs the agent process as a child, reaps orphans, forwards signals, and exits with the agent's return code. This provides tight lifecycle coupling: if the launcher dies, the sandbox terminates. The container must be started with `--network none`, `--cap-add NET_ADMIN`, and `--device /dev/net/tun`. After configuring the device the launcher removes `CAP_NET_ADMIN` from all of its threads and from the bounding set, so the agent cannot regain it through any executable; this needs `CAP_SETPCAP` (present in the default container capability set) and a cgo-free launcher build, and the launcher refuses to start the agent if the drop fails. Other capabilities, the container UID, and `no_new_privs` remain deployment choices.
- **Sidecar Process / Shared Network Namespace:** In environments where the container entrypoint must remain untouched (or in Kubernetes pods), the launcher can run as a sidecar process sharing the sandbox network namespace. If the sidecar terminates, the agent simply loses network access (failing closed).
- **MicroVM Guest Init / System Daemon (MicroVMs):** In microVMs (Firecracker, Cloud-Hypervisor), the networking daemon (e.g. `tun2connect`) runs as a standard guest init process (`/sbin/init`) or system service communicating over a vsock channel to the host. The launcher accepts `vsock://2:<port>` as the boundary address and `-ingress-socket vsock://<port>` for the reverse channel; the VM is configured with no network device. It brings loopback up and needs `CAP_NET_ADMIN` only until the TUN exists, as in the container case. [scenarios/09-firecracker-vsock/init.sh](../scenarios/09-firecracker-vsock/init.sh) is a minimal guest init using this arrangement.

## 3. Network Namespace Proxy

The workload's veth peer or VM TAP can instead live in a dedicated network
namespace with a userspace socket proxy:

```text
workload NIC -> veth/TAP in proxy namespace -> nftables -> kernel socket
                                    |
                                shared Forwarder
                                    |
                             dedicated Unix socket
                                    |
                             boundary policy proxy
```

The namespace has no external network interface. Its workload-facing interface
has a local IPv4 address and, when IPv6 is enabled, a local IPv6 address. The
workload uses those addresses as its gateway and DNS server. The controller
creates the namespace, attaches the interface, installs workload routes, and
provides access to the boundary Unix socket before starting the proxy.

TCP uses nftables REDIRECT and `SO_ORIGINAL_DST`. UDP uses TPROXY and policy
routing to preserve its destination address and port. DNS returns the same
synthetic addresses as the TUN adapter. Both adapters use `Forwarder` for
hostname or IP CONNECT dialing and socket relays. Non-DNS UDP is disabled unless requested.
The namespace drops routed forwarding and restricts local input from the
workload interface. ICMP remains local for network control traffic.

Build the command, then execute it inside the prepared namespace:

```bash
go -C sdk build -o /tmp/netnsproxy ./cmd/netnsproxy
ip netns exec sandbox-proxy /tmp/netnsproxy \
    -interface proxy0 -proxy unix:///run/agents.net/boundary.sock -udp -ipv6
```

The command needs `CAP_NET_ADMIN` in the proxy namespace. Do not run it in the
host's root network namespace. Keep untrusted workload processes in a separate
namespace. `ip netns exec` alone does not restrict filesystem or process access:
the runtime must also restrict the proxy to its assigned socket and protect
host files, processes, and management endpoints as described in [identity.md](../spec/draft/identity.md#2-isolation-and-channel-ownership).
The proxy accepts only one non-loopback interface. It installs its
own nftables table (`agents_net` by default), uses routing table and priority
`16666`, and reserves packet mark `0x616e`. It does not flush other tables.

Stopping the proxy closes its sockets but retains the rules and policy routes.
The controller stops the workload and destroys the namespace; restarting the
proxy requires a fresh namespace. Removing rules while the workload runs is not
a supported shutdown procedure.

TCP policy refusal is a reset after the kernel has accepted the local
connection. The TUN adapter can refuse before completing the guest handshake.
Denied UDP sessions are dropped; UDP errors depend on the client
socket and destination. Neither mode provides a direct-network fallback.

Library use, from a process already in the dedicated namespace:

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

The shared forwarder also accepts the HTTP/2 boundary client or another
implementation of `tun2connect.Dialer`. The command supports `-h2` and limits
combined TCP, UDP, and DNS sessions with `-max-connections` (default 1024).
Each UDP session has a bounded packet queue and an idle timeout.

The live test uses two network namespaces and a real veth pair. It requires
Linux with unprivileged user namespaces, `unshare`, `nsenter`, and kernel
nftables REDIRECT/TPROXY support. It changes no rules in the host namespace:

```bash
NETNS_PROXY_INTEGRATION=1 go -C sdk test -race -count=1 -v \
    ./pkg/netnsproxy -run '^TestNamespaceIntegration$'
```

This test covers IPv4/IPv6 DNS, TCP streaming and half-close, hostname and literal
IP targets, UDP flows to multiple destinations, refusals, and shutdown. TAP/VM traffic is not covered by
this test.

## 4. QEMU Userspace Packet Backend

A VM NIC can terminate at an isolated userspace adapter without a host TAP or
guest TUN. The reference `qemuproxy` command accepts QEMU's `-netdev stream`
Ethernet framing over a dedicated pathname Unix socket. It uses gVisor netstack
and the shared DNS-aware forwarder to generate HTTP/1.1 CONNECT requests on a
different, dedicated boundary socket. Application data, including HTTP GET or
nested CONNECT bytes, remains unchanged tunnel payload. The adapter does not
select authority by inspecting application headers.

Each adapter requires the filesystem, process, and network confinement described
in [identity.md](../spec/draft/identity.md#2-isolation-and-channel-ownership). QEMU must have no alternative external network backend. The
packet channel has one VM lifetime and does not reconnect; the controller stops
the VM when its adapter fails. Restart, snapshot, or restore must not attach a
fresh synthetic DNS state to a guest retaining old mappings.

The reference uses static gateway addresses, a 1500-byte MTU, disabled offloads,
bounded packet queues and combined session limits. It needs no guest networking
daemon. The [QEMU integration](../scenarios/10-qemu-stream/README.md) documents
configuration, restrictions, and executed two-VM IPv4/IPv6 tests. This is an
external QEMU-compatible backend, not an in-process QEMU patch. Ingress, DHCP,
snapshot/restore and migration are not implemented for this path.

## 5. Reference Boundary and Library

A modular Go implementation (`github.com/aojea/agents.net/sdk`) of the HTTP CONNECT boundary wire:

- [sdk/pkg/tun2connect/engine.go](../sdk/pkg/tun2connect/engine.go) — Userspace gVisor netstack engine connecting TUN devices to HTTP CONNECT dialers.
- [sdk/pkg/tun2connect/dns.go](../sdk/pkg/tun2connect/dns.go) — Virtual DNS implementation with synthetic IP allocation and dial-time name reversal.
- [sdk/pkg/tun2connect/dialer.go](../sdk/pkg/tun2connect/dialer.go) — `Dialer` interface supporting HTTP/1.1 (`BoundaryClient`) and HTTP/2 (`BoundaryClientH2`).
- [sdk/pkg/tun2connect/forwarder.go](../sdk/pkg/tun2connect/forwarder.go) - Shared DNS-aware dialing and TCP/UDP socket relays.
- [sdk/pkg/netnsproxy/proxy_linux.go](../sdk/pkg/netnsproxy/proxy_linux.go) - Kernel socket adapter and namespace-local nftables setup.
- [sdk/cmd/netnsproxy/main_linux.go](../sdk/cmd/netnsproxy/main_linux.go) - Namespace proxy command using a Unix boundary socket.
- [sdk/cmd/connect-proxy/main.go](../sdk/cmd/connect-proxy/main.go) — Reference boundary: loads a [policy descriptor](../spec/draft/policy.md), resolves names itself and dials only checked addresses, speaks HTTP/1.1 and multiplexed HTTP/2, tunnels UDP capsules, verifies mTLS client certificates, enforces connection and idle budgets, signals failures with `Proxy-Status`, and writes one JSON audit record per decision ([policy.go](../sdk/cmd/connect-proxy/policy.go) holds the descriptor loader and authorization).
- [sdk/cmd/tun2connect/main.go](../sdk/cmd/tun2connect/main.go) — The in-guest side, in two modes: a standalone daemon, or (`run`) the injectable launcher that becomes PID 1, builds the TUN, and supervises the agent.

The boundary takes its policy from one file, `-policy descriptor.json`, in
the [descriptor format](../spec/draft/policy.md): allow rules on exact
names, name suffixes, the `*` wildcard, literal addresses, and prefixes, each
with optional ports (integers or `"a-b"` ranges), transports, and, for names,
a static `resolve` list used instead of DNS. `sandbox` and `version` in the
descriptor label every audit record; `-generation` adds the controller's
generation label. `features.udp` enables connect-udp. There are no
policy flags. For example:

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

For hostname requests the boundary resolves the name itself and keeps only
public unicast results; loopback, private, link-local, multicast,
shared-address-space, NAT64, documentation, and other special-purpose ranges
([wire.md §5.1](../spec/draft/wire.md#51-special-purpose-addresses)) are
denied unless a `resolve` list, a literal rule for that port, or a
`resolved_addresses` entry admits them. It dials the checked address, not
the name, so a rebinding answer cannot change the destination after the
check. `{"name": "*"}` therefore still cannot reach `localhost`, a metadata
service, or a private network, and never authorizes a literal. Names are
lowercased, stripped of a trailing dot, and converted to A-labels before
matching. Ports must be numeric and in the range 1-65535. Denials report
`not-on-allowlist`, `port-not-allowed`, `transport-not-allowed`,
`ip-not-on-allowlist`, or `resolved-address-denied` as the `reason`
parameter of `Proxy-Status`, for example
`Proxy-Status: boundary; error=http_request_denied; reason=not-on-allowlist`.
A listener without a loaded descriptor answers 503 `policy-unavailable`;
the command refuses to start without `-policy`.

The HTTP/1.1 head is parsed by the boundary itself, not by
`net/http.ReadRequest`, because that reader discards the `Host` field before
it can be compared with the CONNECT authority. The boundary requires a
request line of exactly three single-space-separated fields with a token
method, HTTP/1.0 or HTTP/1.1, at most one `Host` field (required for
HTTP/1.1), header names without whitespace before the colon, a head of at
most 64 KiB, and for CONNECT an authority of host and numeric port with no
userinfo, path, or query whose `Host` field names the same destination after
case, trailing-dot, and IP-text normalization. `Content-Length` and
`Transfer-Encoding` are ignored on CONNECT; bytes after the head are tunnel
data and reach the upstream only after a 200. Malformed requests receive
400 (`malformed-request-line`, `malformed-header`, `duplicate-host`,
`missing-host`, `malformed-target`, `malformed-port`, `authority-mismatch`,
`malformed-upgrade`, `malformed-template`), an unsupported version 505, an
oversized head 431, a non-CONNECT method 405, and policy denials 403. Names
in requests and in the descriptor are validated as dot-separated labels of
letters, digits, hyphens, and underscores after IDNA conversion; a fuzzer
found that `..` normalized to `.` was previously accepted as a name.

Resource limits are `-max-connections` (accepted connections or HTTP/2
sessions, default 1024; further connections receive 503 `busy` before their
request head is read), `-max-streams` (concurrent streams per HTTP/2 session,
default 256), a 15-second request-head deadline, and `-idle-timeout` (default
1h; a tunnel with no data in either direction is closed, 0 disables). Client
EOF is propagated to the upstream as a half-close.

Each decision is one JSON object on standard output in the
[audit record format](../spec/draft/audit.md): `ts`, `listener`, `sandbox`,
`generation`, `policy`, `wire`, `transport`, `destination` as requested after
normalization, `address` as dialed, `peer` (mTLS identity when present),
`rule` (the `id` of the rule that allowed), `decision` (`allow`, `block`,
`fail`), and `reason`. Every refused request is recorded, including
non-CONNECT methods and connections refused for budget. Guest-supplied values
are JSON strings and cannot add fields or lines. The Python demo retains its
hostname-only allowlist as a sample policy and dials names directly; it has
no resolved-address or port check.

The Go boundary rejects incomplete TLS flag combinations before listening.
`-tls-client-ca` requires both `-tls-cert` and `-tls-key` and enables required,
verified client certificates. TLS uses a minimum version of 1.2 and a 15-second
handshake timeout. Certificate identities are still audit-only for HTTP/2;
the command applies a global destination policy, not per-identity authorization.

One process with one listener can serve the baseline's fixed sandbox policy.
This does not make the example a complete secure deployment: the runtime must
provide exclusive socket exposure and lifecycle control, revocation is
process termination without draining, and HTTP/2 stream validation relies on
`golang.org/x/net/http2`.
Sharing this listener between unrelated sandboxes would give them the same
policy; adding an identity header would not separate them.

## 6. Demo

A hands-on, runnable demonstration of a zero-network autonomous ReAct agent running inside Docker, confined by the injected `tun2connect` launcher:

![agents.net terminal demo](../demo/terminal-demo.gif)

- [demo/README.md](../demo/README.md) — Step-by-step tutorial for building and running the sandbox.
- [demo/host_proxy.py](../demo/host_proxy.py) — Python host boundary implementing a 4-tier allowlist (fake responses, local Ollama relay, cloud credential injection, and uninspected passthrough). Credential injection rewrites only the first request on each tunnel; later requests on a reused connection are relayed unchanged, which a production gateway must not do ([gateway.md](../spec/draft/gateway.md#2-credential-placement-and-tenant-isolation)).
- [demo/agent.py](../demo/agent.py) — Sample ReAct agent demonstrating autonomous reasoning, tool execution, and handling connection refusals.
- [demo/gen_certs.sh](../demo/gen_certs.sh) — Script to generate demo root CA and multi-SAN leaf certificates.
- [demo/Dockerfile](../demo/Dockerfile) — Standard Debian-based container image definition for the agent.
- [demo/test_demo.sh](../demo/test_demo.sh) — Presubmit script verifying fail-closed isolation, TLS fake responses, and ingress webhooks.
