<!-- Informative. Not part of the specification. -->
# Rationale and Alternatives

**Informative.** The normative specification is [spec/draft](../spec/draft/index.md).

The problem is to let an untrusted workload reach a chosen set of services
when the workload, its resolver, and its network stack can't be trusted to
respect that choice. The specification's answer is to give the sandbox no
network path at all. In its place, each connection the workload opens becomes
a request that names a destination, and a trusted proxy outside the sandbox
grants or denies that request before any external connection exists.

## 1. Comparison with Common Alternatives

| Property | CONNECT boundary (this specification) | Explicit proxy in a confined namespace | Routed NIC with default-deny L3/L4 policy | Proxy settings alone (`HTTP_PROXY`, SDK options) |
| --- | --- | --- | --- | --- |
| Arrangement | The sandbox has no external NIC. An adapter turns every supported socket into CONNECT on a controller-assigned channel to a host proxy. | The sandbox runs in its own network namespace with no external NIC and under a syscall filter that limits socket families. The runtime creates a loopback listener inside the namespace and bridges it to a host proxy, and proxy environment variables point clients at that listener. | The sandbox NIC is routed or bridged, and a firewall filters packets. | Clients are told about a proxy, and nothing prevents direct connections. |
| Enforcement independent of workload cooperation | Yes. There is no other path, so ignoring the settings or replacing the adapter changes nothing. | Yes. A client that ignores the settings fails rather than connecting, and the syscall filter denies the Unix sockets that the namespace alone would leave reachable. Only proxy-aware clients work at all. | Yes, at the packet level. | No. A client that ignores the settings connects directly. |
| Policy expressed as the destination the application named | Yes. The name is carried in the request; the boundary resolves it and dials the checked address. | Yes. CONNECT carries the name; resolution happens at the proxy. | No. Names must be pre-resolved into address sets. Shared hosting, CDNs, and anycast make address lists stale or broad; DNS-snooping rules race with TTLs and guest-side resolvers. | Yes, for cooperating clients. |
| Resolution performed by a trusted component | Yes. The guest receives synthetic addresses and never resolves the real one; the boundary dials the address it checked. | Yes, at the proxy; whether the checked address is the one dialed depends on the proxy. | No. The guest resolves; the filter sees only the address. | Yes, for cooperating clients. |
| Guest packets processed by the host IP stack | TUN mode: no; the host sees an HTTP stream on a Unix socket. Namespace mode: only a dedicated namespace stack with no external interface. | Only the namespace's loopback; the bridge relays bytes to the host proxy. | Yes. Bridging, routing, connection tracking, and filtering process every guest packet. | Yes. |
| Denial visible to the application | Connection failure, with the requested name, port, and reason in the audit record. | Proxy error (403) for proxy-aware clients; connection failure for others. | Timeout or reset, with an address and port in the record. | Proxy error, for cooperating clients. |
| Per-flow attribution | Listener identity, name or address, port, transport, and decision. | Bridge or token identity, name, port, and decision. | Address, port, and network identity. | Name and port, for cooperating clients. |
| Reusable service credentials kept out of the workload | Yes, through an optional gateway on the same channel. | Yes, through the same proxy with TLS termination. | Requires a separate proxy path. | Same mechanism, but bypassable. |
| Enforcement point | Any CONNECT-capable proxy. | Any CONNECT-capable proxy. | Per-host firewall rules and their lifecycle. | Any HTTP proxy. |
| Protocol coverage | Any TCP client, including ones without proxy support (SSH, database drivers, raw sockets). UDP is optional. Raw IP, ICMP, and multicast are not carried. | Clients that honor proxy variables for HTTP CONNECT or SOCKS, with each tool family needing its own variable. Everything else fails. | Everything the kernel routes. | What the client library supports. |
| Platform | Linux TUN or network namespace; Firecracker VM over vsock. | Linux namespaces; equivalent OS sandboxes on other platforms. | Any host with a packet filter. | Any. |
| Additional cost | Userspace translation (TUN) or redirection (namespace), a proxy hop, per-flow proxy state, synthetic DNS limits. | A bridge relay per sandbox and a proxy hop, with no packet translation. | Per-workload address policy and its lifecycle. | No extra cost, but also no enforcement. |

The explicit proxy in the second column shares most of its boundary with this
specification: a dedicated namespace, a controller-created channel, a host
proxy, and HTTP CONNECT. The difference is what reaches the channel. An
explicit proxy carries only the connections of clients that were configured to
use it. The adapter described here carries every supported connection, so a
tool doesn't have to honor its proxy variables to work, at the cost of the
adapter's translation step. A deployment can combine the two, with one
boundary serving proxy-aware clients through an explicit loopback endpoint and
everything else through the adapter.

## 2. What Is and Is Not Gained

The boundary controls which destinations the guest can reach. It has no say in
what an allowed service does once a tunnel is open. A successful tunnel carries
arbitrary bytes to one authorized destination, the boundary can't see inside
end-to-end TLS, and the service at the other end may relay, store, or return
hostile data. Destination policy on its own therefore isn't enough where the
application layer matters; that takes the separate gateway described in
[gateway.md](../spec/draft/gateway.md).

What the guest loses is IP-level reach. Port scans, raw sockets, ICMP or DNS
tunneling, and traffic to addresses the application never named all stop at
the adapter. The code the guest can attack directly is the boundary's CONNECT
parser, reached over an access-controlled channel, instead of the host's
routing, bridging, connection-tracking, and filtering paths.
[wire.md](../spec/draft/wire.md) states the requirements that keep that parser
bounded.

| Benefit | Description |
| --- | --- |
| External enforcement | As long as runtime isolation holds, an application can't get around destination policy by ignoring proxy settings or replacing the guest adapter. |
| Destination preservation | The boundary receives the hostname when known, or the destination IP address, together with the port. |
| Host-held credentials | An optional application gateway attaches service credentials without giving the reusable key to the workload. |
| Standard protocol | Runtime adapters and proxies communicate through HTTP CONNECT rather than a runtime-specific protocol. |
| Separate configuration | Policy, service mappings, credentials, and audit records are managed outside workload images. |

A coding workload, for example, can download its allowed dependencies and call
a model API through ordinary clients while the boundary rejects every other
destination. An application gateway supplies the model credential, and
operators configure both the boundary and the gateway without touching the
tool's networking code.

## 3. Alternatives

| Approach | Best fit | Trade-off |
| --- | --- | --- |
| Routed NIC with default-deny nftables/eBPF policy | Broad protocol support, existing network integration, bulk traffic | Per-workload network provisioning and policy lifecycle; domain context needs integration |
| Explicit application proxy | Cooperative applications or already isolated workloads | Proxy settings alone do not constrain arbitrary code |
| Host userspace network stack | NIC compatibility without directly routing guest packets through the host | Host packet processing and implementation-specific policy integration |
| Guest TUN to CONNECT | TCP and optional UDP socket compatibility with external authorization | Extra guest packet translation, synthetic DNS limits, proxy resource costs |
| Namespace redirect to CONNECT | Workload veth or TAP terminated by kernel sockets in a dedicated namespace | Requires namespace-local nftables and policy routing; shares host-kernel networking |
| Runtime-native CONNECT adapter | A runtime that can implement socket semantics without packet translation | Runtime engineering and conformance work; no native implementation or benchmark here |

A routed network with default-deny policy is the alternative to consider when
applications need broader protocol support or have to fit into existing
network integration. Both approaches need policy and isolation configuration.
The CONNECT approach also keeps state in the proxy, which holds upstream
sockets, buffers, and per-workload state for the tunnels it serves.
