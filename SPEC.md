# agents.net Specification

`agents.net` defines how an isolated sandbox communicates with a Policy Enforcement Point (PEP) over two separate paths: **egress** and **ingress**.

Policy itself is out of scope. `agents.net` does not define a policy language, policy schema, or audit log format; those are left to the PEP.

---

## Part 1: Architecture

### Why

Untrusted agent workloads install packages, execute generated code, and call external tools. Ordinary container or VM networking has three failure modes:

- Advisory proxy settings (`HTTP_PROXY`) can be ignored by any client that opens a direct socket.
- IP firewalls break behind CDNs and DNS rebinding.
- Attaching a regular NIC and placing credentials inside the sandbox exposes the host kernel TCP/IP and netfilter stack (for example `CVE-2026-98432` and `CVE-2024-1086`) and leaks secrets if the workload is compromised.

`agents.net` removes direct network access from the sandbox and replaces it with two primitives:

1. **Capabilities for isolation and identity:** Unix domain sockets (or `vsock` for microVMs) replace the sandbox's direct network stack.
2. **HTTP `CONNECT` as the framing protocol:** Traffic to and from the PEP uses standard HTTP `CONNECT` framing, reusing existing HTTP protocols and extensions (HTTP/1.1, HTTP/2 multiplexing, RFC 9298 `connect-udp`, RFC 9209 `Proxy-Status`, TLS/mTLS, and HTTP auth).

### Two Separate Paths

Egress and ingress use separate channels and separate authorization:

```text
Egress (sandbox -> PEP -> upstream):

  sandbox -> [traffic converter] -> egress channel (UDS / vsock) --(HTTP CONNECT / connect-udp)--> PEP -> upstream
  (no direct route out)

Ingress (caller -> inbound proxy -> sandbox):

  caller -> inbound proxy --(published endpoint + sandbox ID + port)--> [bridge] -> ingress channel -> sandbox:<port>
                                  ^
                                  |
                      published by runtime (ID + allowed ports)
```

### Capabilities and Trust Boundary

The sandbox has no direct external route, no extra NICs, and no upstream credentials. If the channel or PEP is unavailable or refuses a request, traffic fails closed.

- **Local host (Unix domain sockets):** The runtime creates one pathname Unix socket per sandbox lifetime inside a protected per-sandbox directory and exposes it only to that sandbox's channel client. Reaching the socket is the capability: identity comes from the listener that accepted the connection, never from guest headers. Do not use abstract Unix sockets because they have no filesystem permissions.
- **MicroVMs (`vsock`):** Because a VM cannot mount a host Unix socket, the runtime binds a per-VM `vsock` channel (one host socket per VM/port, or guest CID mapped through controller state).
- **Network hop to a remote PEP:** When a host/node forwarder connects over a network to an external PEP, the outer hop uses mutually authenticated transport (TLS 1.2+/1.3 with mTLS, SPIFFE, or workload tokens) and platform-attested identity metadata. Guest-supplied identity or routing headers are ignored or stripped.
- **Revocation:** Stopping a sandbox stops admission, closes all active tunnels and pending dials, and removes the channel before any path, CID, or sandbox identifier is reused.

### Egress Path

1. **Conversion to HTTP `CONNECT`:** Outbound connections from the sandbox must be converted into HTTP `CONNECT` (TCP) or `connect-udp` (UDP) requests carrying the destination hostname (when known) or literal IP (`[v6]:port` for IPv6) and port. Where conversion happens (inside the guest or on the host) is an implementation choice; see Part 2.
2. **TCP framing:** RFC 9110 `CONNECT host:port` over HTTP/1.1 (`Host` matching the target) or HTTP/2 (`:authority`, no `:scheme` or `:path`). Any `2xx` response (PEPs normally return `200` with no body; clients skip `1xx`) switches the stream into an opaque byte tunnel.
3. **UDP framing (optional):** RFC 9298 `connect-udp` over HTTP/1.1 (`GET` with `Upgrade: connect-udp`) or HTTP/2 extended `CONNECT` (`:protocol: connect-udp` after `SETTINGS_ENABLE_CONNECT_PROTOCOL = 1`, RFC 8441), carrying RFC 9297 datagram capsules.
4. **Errors and refusals:** Non-2xx responses use standard HTTP status codes (`403` policy denial, `4xx` malformed request, `502` DNS or dial failure, `503` unavailable or busy) with an RFC 9209 `Proxy-Status` header (never reflecting raw guest bytes, denied resolved IPs, or policy internals). Any non-2xx fails the workload connection closed and never falls back to direct networking.
5. **PEP responsibilities (policy is PEP-specific):**
   - Parse and validate requests strictly before dialing; never interpret tunnel payload bytes as further control messages.
   - Authorize destination, port, and transport using the channel-bound identity.
   - Resolve DNS at the PEP, block private, loopback, link-local, metadata, and other special-purpose addresses unless explicitly allowed, and dial only the checked IP with no second unchecked lookup (preventing DNS rebinding and SSRF).
   - Bound request head size, timeouts, concurrent connections/streams, and idle lifetimes per sandbox.
6. **Optional TLS inspection and credential injection:**
   - When a PEP terminates TLS for L7 inspection or credential injection, mount its CA certificate read-only in the sandbox at `/var/run/agent-ca.pem` (`AGENT_CA_CERT` plus language trust variables such as `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, and `NODE_EXTRA_CA_CERTS`).
   - Keep the CA private key unreadable from sandboxes (ideally in memory and ephemeral per gateway start).
   - Select credentials only from the authenticated channel identity, validate upstream TLS independently, strip guest placeholder credentials, refuse with `421` any request whose `Host` or request target disagrees with the `CONNECT` tunnel destination, and re-authorize across reused connections, streams, and redirects.

### Ingress Path

An isolated sandbox has no reachable external IP, so standard IP routing cannot reach services inside it. Ingress splits into **publication** and **forwarding**:

1. **Publication (discovery):** The runtime publishes three pieces of information for authorized inbound proxies:
   - **Bridge endpoint:** Where the inbound proxy connects (a host socket path on a single host, or a reachable node `host:port` plus TLS/mTLS metadata in a cluster).
   - **Sandbox identifier:** An immutable identifier for the live sandbox instance and generation so traffic reaches the right workload and never hits a replacement after restart (for example a Pod UID + sandbox ID in Kubernetes).
   - **Allowed ports:** The controller-pinned port(s) or port ranges authorized for inbound delivery.
2. **Forwarding:**
   - The inbound proxy authenticates the external caller and resolves the target route to one live sandbox identifier and one allowed port from the published state.
   - When crossing a host/node bridge, the inbound proxy sends `CONNECT <sandbox-id>:<port> HTTP/1.1` (with matching `Host`) to the bridge endpoint.
   - On the sandbox ingress channel (a separate ingress Unix socket, `vsock` port, or direct dial into the sandbox network namespace), the host/bridge delivers the stream via `CONNECT 127.0.0.1:<port> HTTP/1.1` (or `[::1]:<port>`) to loopback or, when configured by the controller, to the sandbox's own interface address (keeping loopback-only services unreachable).
   - Unpinned ports fail with `403` and `Proxy-Status`; unknown or stopped sandboxes fail with `404`.
   - Optional `AGENT_INGRESS_PORT` and `AGENT_PUBLIC_URL` environment variables inside the sandbox are hints only and never grant access. Teardown revokes both the published state and active ingress tunnels immediately.

---

## Part 2: Implementation Patterns

The architecture above fixes the capability boundary and HTTP `CONNECT` framing, while leaving **how sandbox traffic is converted to HTTP `CONNECT`** and **how ingress metadata is published** to each platform.

### Converting Sandbox Traffic to HTTP `CONNECT`

Converting ordinary application sockets into HTTP `CONNECT` frames is the trickiest part of a deployment because it has to handle clients that ignore proxy settings and preserve hostnames for DNS-based policy. Platforms choose where that conversion runs:

- **Conversion inside the guest:** An in-sandbox adapter creates a `tun` device with a userspace TCP/IP stack and local virtual DNS (handing out synthetic IPs such as `100.64.0.0/10` / `100::/64` and mapping them back to hostnames on connect). No host NIC or packet-forwarding rules are needed, and clients that ignore `HTTP_PROXY` are captured transparently. Example in this repo: `sdk/cmd/tun2connect` (as PID 1 launcher or Kubernetes sidecar).
- **Forwarding in the guest, conversion on the host:** A platform leaves a restricted guest interface or redirects traffic inside the guest (for example via `iptables`, `nftables`, or routing) to a host-side or dedicated proxy-namespace converter that collapses flows into HTTP `CONNECT` over the egress channel. This keeps the userspace network stack out of the guest while still capturing clients that ignore `HTTP_PROXY`. Examples: `sdk/cmd/netnsproxy` (`nftables` `REDIRECT`/`TPROXY` in a proxy namespace), `sdk/cmd/qemuproxy` (QEMU `-netdev stream` userspace packet backend), or a CNI/eBPF dataplane.
- **Explicit proxy in a confined namespace (no packet conversion):** The host binds a local loopback HTTP proxy (for example `127.0.0.1:15001` via `socketat`) inside a confined network namespace and sets `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY`. No adapter process runs inside the guest; proxy-aware clients work directly, and clients that ignore proxy settings fail closed because direct routes and NICs are blocked. Example: `kubernetes/cmd/dra-agents-net` default `ExplicitProxy` mode.

### Publishing Ingress Reachability

- **Single host / microVM:** The controller hands the sandbox's ingress Unix socket or `vsock` port directly to the local ingress gateway (`demo/host_proxy.py`, `scenarios/09-firecracker-vsock/`).
- **Kubernetes:** A DRA + NRI node driver (`kubernetes/cmd/dra-agents-net`) publishes the node bridge endpoint, protocol (`http-connect`), Pod UID, sandbox ID, TLS settings, and pinned ports in `ResourceClaim.status.devices[].data`, and clears it on `StopPodSandbox`. A stateless inbound proxy (`kubernetes/cmd/agents-net-ingress-gateway`) watches `ResourceClaim` status behind a `LoadBalancer`, `Ingress`, or Gateway API `HTTPRoute`.
