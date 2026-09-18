<!-- Informative. Not part of the specification. -->
# Implementations and Status

**Informative.** This page records what has been built and how far each part
has been checked. Products appear here only with their validation status. The
normative specification is [spec/draft](../spec/draft/index.md).

None of the products below is a dependency of the protocol. A proxy that
supports CONNECT does not, by that alone, meet this specification's identity,
policy, and isolation requirements.

| Capability | Current status |
| --- | --- |
| TUN, synthetic DNS, named TCP, explicit refusals | Implemented and unit-tested; Docker demo provided |
| Literal IPv4/IPv6 destinations | Forwarded by both adapters; explicit IP/CIDR policy in the Go boundary |
| Namespace socket adapter | Implemented with shared forwarding; live veth tests for IPv4/IPv6 TCP, UDP, DNS, and shutdown |
| HTTP/1.1, HTTP/2 multiplexing, UDP capsules, mTLS client | Library implementations and tests; launcher currently uses HTTP/1.1 |
| TLS handshake inspection | Not implemented by the reference proxies |
| Third-party TCP CONNECT interoperability | Tested over loopback TCP; see Section 1 |
| Dedicated socket with fixed destination policy | Reference command supports one listener and policy per process; exclusive exposure and lifecycle are runtime responsibilities |
| Resolved-address policy for hostnames | Implemented in the Go boundary: names are resolved by the boundary, non-public results are denied unless listed, and the checked address is dialed without a second resolution |
| Per-port policy, complete CONNECT validation | Per-port rules on names, literals, and the wildcard; HTTP/1.1 head parsed by the boundary with request-line, version, Host/authority, userinfo/path, port, header-name, and size checks; a 34-case negative corpus and fuzz targets for the head, policy, template, capsule, and DNS parsers |
| Multiple identities on one listener | Optional extension, not implemented; unnecessary for dedicated endpoints |
| Connection/resource budgets, revocation lifecycle, complete decision audit | Go boundary: connection and HTTP/2 stream budgets, tunnel idle timeout, request-head deadline, one JSON record per decision with listener-bound sandbox identity and policy version; bounded synthetic-name memory with no address reuse; namespace session/queue limits. Revocation is stop/restart of the per-sandbox boundary process, exercised in the Firecracker scenario ([evidence.md](evidence.md#2-firecracker-two-sandbox-test)); no draining or hot handoff |
| Controller-registered connected FDs | Optional extension; registration and handoff are not implemented |
| Software signature verification and launch attestation | Deployment requirements where selected; no verifier is implemented here |
| Authenticated production ingress | Not implemented; demo and Firecracker reverse stream only, without caller authentication. The launcher pins the one loopback port ingress may reach |
| Firecracker VM channel | Executed: two microVMs with no NIC, in-guest TUN over vsock, one boundary listener per VM on Firecracker's per-VM Unix socket prefix, disjoint policies, ingress into guest loopback ([evidence.md](evidence.md#2-firecracker-two-sandbox-test)) |
| QEMU packet backend | Executed: two KVM microVMs with virtio-net and isolated Unix-stream packet adapters, IPv4/IPv6 TCP and DNS, disjoint policies, boundary revocation, and adapter-loss supervision ([sdk/README.md](../sdk/README.md#4-qemu-userspace-packet-backend)) |
| Native runtime interception, other VMMs, attestation | Future work; Cloud Hypervisor's Firecracker-style Unix-backed VSOCK and QEMU host `AF_VSOCK` channels are not tested |

## 1. External Implementations

| Implementation | Support | Validation |
| --- | --- | --- |
| Envoy | HTTP/1.1 and HTTP/2 TCP CONNECT | Live test with the repository's clients on September 15, 2026, using the v1.32 image over loopback TCP. UDP, IPC identity, and workload authorization were not tested. |
| kgateway | Route-level CONNECT termination through `TrafficPolicy.httpUpgrade` with `connect.terminate: true` | API source, translator, and upstream tests inspected at revision `634b53c`. No local interoperability run; release availability and complete boundary behavior are unverified. |
| Apache HTTP Server 2.4 | CONNECT tunneling through `mod_proxy_connect`, with destination-port restrictions | Official documentation checked. No local interoperability run. |
| Codex CLI `codex-network-proxy` | HTTP CONNECT and SOCKS5 forward proxy on host loopback with domain allow/deny lists (`*.example.com`, `**.example.com`), a read-only "limited" mode enforced by TLS termination with a proxy-held CA, and local/private address rejection | Source and README read on September 16, 2026 (`codex-rs/network-proxy`, `codex-rs/linux-sandbox` at `49305d7`). No local interoperability run. |

The Codex CLI arrangement is the second column of the [comparison table](rationale.md#1-comparison-with-common-alternatives). Its Linux
sandbox has two layers. Bubblewrap runs the command with `--unshare-net`. A
helper binds a loopback TCP listener inside that namespace, passes it over a
Unix socket to a bridge process on the host, and rewrites the proxy
environment variables to point at that listener. The bridge relays each
accepted connection to the proxy after sending a per-command attribution
token. On top of that, a seccomp filter on the command denies `ptrace`,
`process_vm_readv`/`writev`, and `io_uring`. In proxy mode the filter permits
`socket()` only for `AF_INET` and `AF_INET6`, so the command cannot open Unix
sockets (only `socketpair`) unless the policy grants them. With networking
disabled it denies `connect`, `bind`, `listen`, `accept`, `sendto`, and every
socket family except `AF_UNIX`. The namespace removes external egress, and
the filter closes the paths a namespace does not cover, which this
specification lists as runtime responsibilities in Section 4.3. Only clients
that honor the proxy variables reach the proxy. The Codex documentation says
that hostnames resolving to local or private addresses are rejected by a
best-effort lookup and that DNS rebinding is not fully prevented. By contrast,
the reference boundary here dials the address it checked. Whether this
repository's clients interoperate with the Codex proxy has not been tested.

The Envoy [example configuration](../sdk/examples/envoy-boundary.yaml) and
[interop test](../sdk/test_envoy.sh) reproduce the Envoy result. A gateway
that uses Envoy internally still needs its own configuration and its own
interoperability run.

Implementation references:

- kgateway: [API definition](https://github.com/kgateway-dev/kgateway/blob/634b53c502168b5a05bd8dd111e5d6b6c6113b9f/api/v1alpha1/kgateway/traffic_policy_types.go), [translator](https://github.com/kgateway-dev/kgateway/blob/634b53c502168b5a05bd8dd111e5d6b6c6113b9f/pkg/kgateway/extensions2/plugins/trafficpolicy/http_upgrade.go), and [upstream tests](https://github.com/kgateway-dev/kgateway/blob/634b53c502168b5a05bd8dd111e5d6b6c6113b9f/pkg/kgateway/extensions2/plugins/trafficpolicy/http_upgrade_test.go). Enabling a listener upgrade alone forwards CONNECT without terminating it.
- Apache: [mod_proxy_connect](https://httpd.apache.org/docs/2.4/mod/mod_proxy_connect.html).
- Codex CLI: [network-proxy README](https://github.com/openai/codex/blob/main/codex-rs/network-proxy/README.md), [bubblewrap network modes](https://github.com/openai/codex/blob/main/codex-rs/linux-sandbox/src/bwrap.rs), [proxy routing bridge](https://github.com/openai/codex/blob/main/codex-rs/linux-sandbox/src/proxy_routing.rs), and [seccomp network filter](https://github.com/openai/codex/blob/main/codex-rs/linux-sandbox/src/landlock.rs).
