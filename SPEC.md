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

1. **Unix domain sockets (or `vsock`) as capabilities:** Removing the direct network stack reduces kernel attack surface and lets operators roll out security fixes in userspace without rebooting the host kernel or exposing the kernel network stack to untrusted agents.
2. **HTTP `CONNECT` as the framing protocol:** Traffic to and from the PEP uses standard HTTP `CONNECT` framing, reusing existing HTTP protocols and extensions (HTTP/1.1, HTTP/2 multiplexing, RFC 9298 `connect-udp`, RFC 9209 `Proxy-Status`, and mTLS).

### Two Separate Paths

Egress and ingress use separate channels and separate authorization:

```text
Egress (sandbox -> PEP -> upstream):

  sandbox -> [traffic converter] -> egress channel (UDS / vsock) --(mTLS + HTTP CONNECT / connect-udp)--> PEP -> upstream
  (no direct route out)

Ingress (caller -> inbound proxy -> sandbox):

  caller -> inbound proxy --(mTLS + CONNECT <sandbox-id>:<port>)--> [bridge] -> ingress channel -> sandbox:<port>
                                  ^
                                  |
             inbound details exposed by runtime (no sandbox IP)
```

### Capabilities and Trust Boundary

The sandbox has no direct external route, no extra NICs, and no upstream credentials. If the channel or PEP is unavailable or refuses a request, traffic fails closed.

- **Local host (Unix domain sockets):** The runtime creates one pathname Unix socket per sandbox lifetime inside a protected per-sandbox directory and exposes it only to that sandbox's channel client. Reaching the socket is the capability: identity comes from the listener that accepted the connection, never from guest headers. Do not use abstract Unix sockets because they have no filesystem permissions.
- **MicroVMs (`vsock`):** Because a VM cannot mount a host Unix socket, the runtime binds a per-VM `vsock` channel (one host socket per VM/port, or guest CID mapped through controller state).
- **Mandatory mTLS on network hops:** Any network hop to a remote PEP or across a host/node ingress bridge MUST use mTLS (TLS 1.2+/1.3 with mutual certificate authentication — X.509 mTLS, SPIFFE X.509-SVID, or PodCertificate). Plaintext network hops are forbidden. Optional workload tokens may layer on top of mTLS but never replace it.
- **Attested identity headers:** When a host/node forwarder connects over mTLS to a remote PEP, it MUST strip any guest-supplied `Agents-Net-*` headers and attach only platform-attested identity headers:
  - `Agents-Net-Principal`: canonical workload identity (omitted when already carried by a per-sandbox client certificate SAN / SPIFFE ID).
  - `Agents-Net-Generation`: opaque incarnation or attachment identifier for restart, resume, and warm-pool fencing.
  - `Agents-Net-Attributes`: RFC 8941 dictionary of platform-attested attributes (for example `ns="default", pod="agent-1", sa="runner"`). Never populate from guest input or user-writable labels.
  - `Agents-Net-Process` *(optional)*: RFC 8941 dictionary asserted by a host supervisor or kernel hook (for example `exe="/usr/bin/curl", sha256="..."`).
- **Revocation:** Stopping a sandbox stops admission, closes all active tunnels and pending dials, and removes the channel before any path, CID, or sandbox identifier is reused.

### Egress Path

1. **Conversion to HTTP `CONNECT`:** Outbound connections from the sandbox must be converted into HTTP `CONNECT` (TCP) or `connect-udp` (UDP) requests carrying the destination hostname (when known) or literal IP (`[v6]:port` for IPv6) and port. Where conversion happens (inside the guest or on the host) is an implementation choice; see Part 2.
2. **TCP framing:** RFC 9110 `CONNECT host:port` over HTTP/1.1 (`Host` matching the target) or HTTP/2 (`:authority`, no `:scheme` or `:path`). Any `2xx` response (PEPs normally return `200` with no body; clients skip `1xx`) switches the stream into an opaque byte tunnel.
3. **UDP framing (optional):** RFC 9298 `connect-udp` over HTTP/1.1 (`GET` with `Upgrade: connect-udp`) or HTTP/2 extended `CONNECT` (`:protocol: connect-udp` after `SETTINGS_ENABLE_CONNECT_PROTOCOL = 1`, RFC 8441), carrying RFC 9297 datagram capsules.
4. **Errors and refusals:** Non-2xx responses use standard HTTP status codes (`403` policy denial, `4xx` malformed request, `502` DNS or dial failure, `503` unavailable or busy) with an RFC 9209 `Proxy-Status` header formatted as `<proxy>; error=<rfc9209-type>; reason=<token>`, where `reason` is an `agents.net` extension token (for example `not-on-allowlist`, `port-not-permitted`, `busy`). Never reflect raw guest bytes, denied resolved IPs, or policy internals. Any non-2xx fails the workload connection closed and never falls back to direct networking.
5. **PEP responsibilities (policy is PEP-specific):**
   - Parse and validate requests strictly before dialing; never interpret tunnel payload bytes as further control messages.
   - Authorize destination, port, and transport using the mTLS/channel-bound identity.
   - Resolve DNS at the PEP, block private, loopback, link-local, metadata, and other special-purpose addresses unless explicitly allowed, and dial only the checked IP with no second unchecked lookup (preventing DNS rebinding and SSRF).
   - Bound request head size, timeouts, concurrent connections/streams, and idle lifetimes per sandbox.
6. **Optional TLS inspection and credential injection:**
   - When a PEP terminates TLS for L7 inspection or credential injection, mount its CA certificate read-only in the sandbox (default `/var/run/agent-ca.pem`) and expose the path via `AGENT_CA_CERT` plus language trust variables (`SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`). Using `AGENT_CA_CERT` lets rootless sandboxes place the file in a writable mount path.
   - Keep the CA private key unreadable from sandboxes (ideally in memory and ephemeral per gateway start).
   - Select credentials only from the authenticated channel identity, validate upstream TLS independently, strip guest placeholder credentials, refuse with `421` any request whose `Host` or request target disagrees with the `CONNECT` tunnel destination, and re-authorize across reused connections, streams, and redirects.

### Ingress Path

An isolated sandbox has no reachable external IP, so standard IP routing cannot reach services inside it. Ingress splits into **publication** and **forwarding**:

1. **Publication (discovery):** The runtime exposes the inbound network details needed by an external proxy to forward traffic to the sandbox without relying on a sandbox IP:
   - **Bridge endpoint:** Where the inbound proxy connects (a host socket path on a single host, or a reachable node `host:port` plus mTLS server identity in a cluster).
   - **Sandbox identifier:** An immutable identifier (`[A-Za-z0-9._-]`, 1 to 128 characters; no colons, slashes, or whitespace) and generation so traffic reaches the right live workload and never hits a replacement after restart (for example a Pod UID + sandbox ID in Kubernetes).
   - **Allowed ports:** The controller-pinned port(s) or port ranges authorized for inbound delivery.
2. **Forwarding:**
   - The inbound proxy authenticates the external caller and resolves the target route to one live sandbox identifier and one allowed port from the exposed state.
   - When crossing a host/node bridge, the inbound proxy connects over **mTLS** and sends `CONNECT <sandbox-id>:<port> HTTP/1.1` (with matching `Host`) or HTTP/2 `CONNECT`. The bridge verifies the proxy's client certificate identity before forwarding.
   - On the sandbox ingress channel (a separate ingress Unix socket, `vsock` port, or direct dial into the sandbox network namespace), the host/bridge delivers the stream via `CONNECT 127.0.0.1:<port> HTTP/1.1` (or `[::1]:<port>`) to loopback or, when configured by the controller, to the sandbox's own interface address (keeping loopback-only services unreachable).
   - Unpinned ports fail with `403` (`reason=port-not-permitted`); starting or suspended sandboxes fail with `503` (`reason=sandbox-not-ready`); unknown or stopped sandboxes fail with `404` (`reason=unknown-sandbox` or `sandbox-revoked`), all with `Proxy-Status`.
   - Optional `AGENT_INGRESS_PORT` and `AGENT_PUBLIC_URL` environment variables inside the sandbox are hints only and never grant access. Teardown revokes both the exposed state and active ingress tunnels immediately.

---

## Part 2: Implementation Patterns

The architecture above fixes the UDS/`vsock` capability boundary, mandatory mTLS on network hops, and HTTP `CONNECT` framing, while leaving **how sandbox traffic is converted to HTTP `CONNECT`** and **how inbound network details are exposed** to each platform.

### Converting Sandbox Traffic to HTTP `CONNECT`

Converting ordinary application sockets into HTTP `CONNECT` frames has to handle clients that ignore proxy settings and preserve hostnames for DNS-based policy. Platforms choose where that conversion runs:

- **Host-side TUN or packet conversion (no guest binary):** The runtime creates a TUN device inside the confined guest network namespace (or attaches the VM's `virtio-net` socket) and runs the userspace TCP/IP stack and synthetic DNS (`198.18.0.0/15` / `100::/64`, failing closed on unmapped synthetic addresses) on the host. No sidecar, no guest privileges, and no host-kernel TCP/IP or netfilter rules are needed, while clients that ignore `HTTP_PROXY` are captured transparently. Examples: `kubernetes/cmd/dra-agents-net` default `HostTun` mode, `sdk/cmd/qemuproxy`, `sdk/cmd/netnsproxy`.
- **Conversion inside the guest:** An in-sandbox adapter creates a `tun` device with a userspace TCP/IP stack and local virtual DNS (`198.18.0.0/15` / `100::/64`) and translates flows into HTTP `CONNECT` / `connect-udp` over the egress channel. Example: `sdk/cmd/tun2connect` (as PID 1 launcher, microVM init over `vsock`, or Kubernetes `TunSidecar`).
- **Explicit proxy in a confined namespace (no packet conversion, no fake IPs):** The host binds a local loopback HTTP proxy (for example `127.0.0.1:15001` via `socketat`) inside a confined network namespace alongside the UDS egress channel and sets `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY`. No adapter process runs inside the guest; proxy-aware clients send hostnames directly in `CONNECT` with zero synthetic DNS, and clients that ignore proxy settings fail closed. Example: `kubernetes/cmd/dra-agents-net` `ExplicitProxy` mode.

### Exposing Inbound Network Details

How a runtime exposes the bridge endpoint, mTLS server identity, sandbox identifier, and allowed ports to an external inbound proxy is implementation-specific:

- **Single host / microVM:** The controller hands the sandbox's ingress Unix socket or `vsock` port directly to the local ingress proxy (`demo/host_proxy.py`, `scenarios/09-firecracker-vsock/`).
- **Kubernetes:** A node driver exposes the inbound network details for each sandbox without Pod IPs so an external proxy can discover and forward to it over mTLS `CONNECT`. As one implementation, `kubernetes/cmd/dra-agents-net` writes those details into its DRA `ResourceClaim` status, and `kubernetes/cmd/agents-net-ingress-gateway` watches them behind a `LoadBalancer`, `Ingress`, or Gateway API `HTTPRoute`.
