<!-- Informative. Not part of the specification. -->
# Rationale and Alternatives

**Informative.** The normative specification is [spec/draft](../spec/draft/index.md).

The design answers one question: how does an untrusted workload reach selected
services when neither the workload, its resolver, nor its network stack can be
trusted to enforce the selection? The answer is to give the sandbox no network
path and to replace it with a request naming a destination, which a trusted
component grants or denies before any external connection exists.

## 1. Comparison with Common Alternatives

| Property | CONNECT boundary (this specification) | Explicit proxy in a confined namespace | Routed NIC with default-deny L3/L4 policy | Proxy settings alone (`HTTP_PROXY`, SDK options) |
| --- | --- | --- | --- | --- |
| Arrangement | Sandbox has no external NIC; an adapter turns every supported socket into CONNECT on a controller-assigned channel to a host proxy. | Sandbox runs in its own network namespace with no external NIC, under a syscall filter that limits socket families; the runtime creates a loopback listener inside it, bridged to a host proxy; clients are pointed at it through proxy environment variables. | Sandbox NIC is routed or bridged; a firewall filters packets. | Clients are told about a proxy; nothing prevents direct connections. |
| Enforcement independent of workload cooperation | Yes. Ignoring settings or replacing the adapter changes nothing; there is no other path. | Yes for confinement: a client that ignores the settings fails, it does not connect; the syscall filter also denies Unix sockets the namespace would otherwise leave reachable. Only proxy-aware clients work at all. | Yes, for packets. | No. A client that ignores the settings connects directly. |
| Policy expressed as the destination the application named | Yes. The name is carried in the request; the boundary resolves it and dials the checked address. | Yes. CONNECT carries the name; resolution happens at the proxy. | No. Names must be pre-resolved into address sets. Shared hosting, CDNs, and anycast make address lists stale or broad; DNS-snooping rules race with TTLs and guest-side resolvers. | Yes, for cooperating clients. |
| Resolution performed by a trusted component | Yes. The guest receives synthetic addresses and never resolves the real one; the boundary dials the address it checked. | Yes, at the proxy; whether the checked address is the one dialed depends on the proxy. | No. The guest resolves; the filter sees only the address. | Yes, for cooperating clients. |
| Guest packets processed by the host IP stack | TUN mode: no; the host sees an HTTP stream on a Unix socket. Namespace mode: only a dedicated namespace stack with no external interface. | Only the namespace's loopback; the bridge relays bytes to the host proxy. | Yes. Bridging, routing, connection tracking, and filtering process every guest packet. | Yes. |
| Denial visible to the application | Connection failure, with the requested name, port, and reason in the audit record. | Proxy error (403) for proxy-aware clients; connection failure for others. | Timeout or reset, with an address and port in the record. | Proxy error, for cooperating clients. |
| Per-flow attribution | Listener identity, name or address, port, transport, and decision. | Bridge or token identity, name, port, and decision. | Address, port, and network identity. | Name and port, for cooperating clients. |
| Reusable service credentials kept out of the workload | Yes, through an optional gateway on the same channel. | Yes, through the same proxy with TLS termination. | Requires a separate proxy path. | Same mechanism, but bypassable. |
| Enforcement point | Any CONNECT-capable proxy. | Any CONNECT-capable proxy. | Per-host firewall rules and their lifecycle. | Any HTTP proxy. |
| Protocol coverage | Any TCP client, including ones without proxy support (SSH, database drivers, raw sockets); UDP optional; no raw IP, ICMP, or multicast. | Clients that honor proxy variables for HTTP CONNECT or SOCKS; each tool family needs its own variable; everything else fails. | Everything the kernel routes. | What the client library supports. |
| Platform | Linux TUN or network namespace; Firecracker VM over vsock. | Linux namespaces; equivalent OS sandboxes on other platforms. | Any host with a packet filter. | Any. |
| Additional cost | Userspace translation (TUN) or redirection (namespace), a proxy hop, per-flow proxy state, synthetic DNS limits. | A bridge relay per sandbox and a proxy hop; no packet translation. | Per-workload address policy and its lifecycle. | None, and no guarantee. |

The second column and this specification share the boundary: a dedicated
namespace, a controller-created channel, a host proxy, and HTTP CONNECT. They
differ in what reaches the channel. An explicit proxy carries only the
connections of clients that were configured for it; the adapter here carries
every supported connection, so compatibility does not depend on each tool
honoring its proxy variables. The price is the translation step. A deployment
can combine them: the same boundary can serve proxy-aware clients through an
explicit loopback endpoint and everything else through the adapter.

## 2. What Is and Is Not Gained

The design changes what the guest can request, not what an allowed service
will do. A successful tunnel carries arbitrary bytes to one authorized
destination. The boundary does not see inside end-to-end TLS, and an allowed
service may relay, store, or return hostile data. Destination policy is
necessary but not sufficient; application policy requires the separate gateway
described in [gateway.md](../spec/draft/gateway.md).

The design removes the guest's IP-level reach. Port scans, raw sockets, ICMP or
DNS tunneling, and traffic to addresses that were never named end at the
adapter. The guest-facing attack surface is the boundary's CONNECT parser on an
access-controlled channel rather than the host's routing, bridging, connection
tracking, and filtering paths. [wire.md](../spec/draft/wire.md) states the requirements that keep that
parser bounded.

| Benefit | Description |
| --- | --- |
| External enforcement | Applications cannot bypass destination policy by ignoring proxy settings or replacing the guest adapter while runtime isolation remains intact. |
| Destination preservation | The boundary receives the hostname when known, or the destination IP address, together with the port. |
| Host-held credentials | An optional application gateway attaches service credentials without giving the reusable key to the workload. |
| Standard protocol | Runtime adapters and proxies communicate through HTTP CONNECT rather than a runtime-specific protocol. |
| Separate configuration | Policy, service mappings, credentials, and audit records are managed outside workload images. |

For example, a coding workload can download allowed dependencies and call a
model API through ordinary clients. The boundary rejects other destinations.
An application gateway supplies the model credential. Operators configure the
boundary and gateway without changing the tool's networking code.

## 3. Alternatives

| Approach | Best fit | Trade-off |
| --- | --- | --- |
| Routed NIC with default-deny nftables/eBPF policy | Broad protocol support, existing network integration, bulk traffic | Per-workload network provisioning and policy lifecycle; domain context needs integration |
| Explicit application proxy | Cooperative applications or already isolated workloads | Proxy settings alone do not constrain arbitrary code |
| Host userspace network stack | NIC compatibility without directly routing guest packets through the host | Host packet processing and implementation-specific policy integration |
| Guest TUN to CONNECT | TCP and optional UDP socket compatibility with external authorization | Extra guest packet translation, synthetic DNS limits, proxy resource costs |
| Namespace redirect to CONNECT | Workload veth or TAP terminated by kernel sockets in a dedicated namespace | Requires namespace-local nftables and policy routing; shares host-kernel networking |
| Runtime-native CONNECT adapter | A runtime that can implement socket semantics without packet translation | Runtime engineering and conformance work; no native implementation or benchmark here |

A routed network with default-deny policy is an alternative when applications
need broader protocol support or existing network integration. Both designs
require policy and isolation configuration. In the CONNECT design, the proxy
retains upstream sockets, buffers, and per-workload state.
