# AGENTS.NET: The Agent Networking Specification

## Introduction: Confinement Is a Route, Not a Convention

As AI agents become more autonomous, sandboxing them has evolved into a nightmare of virtual network interfaces, TAP devices, complex NAT rules, and IP routing.

The first revision of this spec answered with conventions, in the spirit of the most successful standards in the AI ecosystem — the Model Context Protocol, `AGENTS.md` — simple, plain-text agreements: boot the sandbox with zero network and tell the agent, through environment variables, where the HTTP proxy is.

Running real, unmodified harnesses showed the limit of that approach: **every convention needs the agent's cooperation, and an agent that has to cooperate with its own confinement is not confined.** A Python library that opens its client with `trust_env=False` bypasses the proxy. So does a subprocess that clears its environment. Anything that is not HTTP — `git` over SSH, gRPC, Postgres, a raw socket — was never covered in the first place. And an agent driven by a model, acting on text nobody wrote, is exactly the case where cooperation cannot be assumed.

So this revision keeps the zero-network sandbox and replaces the convention with enforcement. The sandbox has no interface except a `tun` device built by a **userspace launcher** running as PID 1; the launcher owns the only route out; every flow leaves through **one Unix socket as an HTTP CONNECT tunnel request, carrying the destination as a name**; and a host-side boundary applies deny-by-default policy on that name. None of this requires the agent's cooperation.

Conventions still exist, but only where they are harmless. The rule this spec follows:

> **A convention may govern what an agent can reach cooperatively. It must never govern what an agent cannot reach.**

Access may be coordinated; denial is enforced.

## Why This Design: the Decision Matrix

There are six known ways to control the traffic of a sandboxed agent. We considered all of them — two were earlier designs of this project. The first table compares them property by property; the second summarizes the trade-offs.

| | 1. Routed NIC + redirect<br/>(veth/tap + nftables/eBPF tc) | 2. Proxy env convention<br/>(`HTTP_PROXY` + CA vars) | 3. Host-side userspace stack<br/>([gvisor-tap-vsock](https://github.com/containers/gvisor-tap-vsock)) | 4. Guest-side userspace stack<br/>(tun → HTTP CONNECT, **this spec**) | 5. Socket-layer eBPF<br/>(cgroup connect hooks / sockmap) | 6. In-guest transparent redirect<br/>(NAT → loopback forwarder → vsock) |
|---|---|---|---|---|---|---|
| **Confinement** | enforced subtractively: a filter over a working network | cooperation required | enforced: frames only reach a host process | enforced: no interface but the tun | enforced, shared kernel only | enforced: vsock is the only way out; guest rules are only routing |
| **Failure mode** | fail-open: a missing rule is a working network | fail-open by design | fail-closed | fail-closed: launcher dies → no route; PID 1 dies → sandbox exits | fail-closed if default-deny; programs can detach silently | fail-closed: tampered guest rules lose connectivity, not gain reach |
| **Policy sees** | IP:port — the name died at DNS time | full URL (HTTP only) | packets; names only by also owning guest DNS | **the destination name, for every flow** | IP:port at `connect()` | IP:port via `SO_ORIGINAL_DST`; names re-derived from SNI/Host or an owned DoH resolver |
| **Guest cost** | none | env + CA plumbing enumerated per runtime | none — guest sees a standard NIC | a launcher as PID 1; `/dev/net/tun` + `NET_ADMIN` (or a user namespace) | none | NAT rules + loopback forwarder + DoH resolver; kernel TCP retained |
| **Host cost** | netns/veth/rules per sandbox, IPAM, ordering, cleanup, `CAP_NET_ADMIN` | none | a full netstack + NAT/DHCP/DNS per sandbox, in a host process | one CONNECT listener per boundary socket | eBPF lifecycle, `CAP_BPF`/`CAP_SYS_ADMIN`, kernel-version treadmill | per-sandbox proxy listener + a proxy-config control loop |
| **Traffic CPU billed to** | host kernel (unattributed) | n/a | **the host component** (noisy neighbor) | **the sandbox itself** (its own cgroup/VM budget) | host kernel (unattributed) | the sandbox (guest kernel) |
| **Containers ↔ microVMs** | two different dataplanes | same everywhere it works | VM-native; containers awkward | identical byte stream (UDS ↔ vsock) | cannot cross a VM boundary; gVisor hides guest sockets | microVM-native; containers need iptables + `NET_ADMIN` in-guest |
| **Protocols** | all | HTTP(S) only | all | TCP (UDP explicitly denied) | TCP/UDP | TCP only |
| **Snapshot / migration** | host kernel state, rebuilt by hand on the new host | n/a | host state per sandbox | dataplane is guest state — travels inside the snapshot | host state, kernel-pinned | guest state travels; vsock connections reset on resume |

In summary:

| Option | Pros | Cons | Bottom line |
|---|---|---|---|
| **1. Routed NIC + redirect** | native kernel TCP performance; no extra processes; mature tooling; works with any guest unmodified | fail-open: a missing rule is a working network; policy sees IPs after the name is gone, so domain policy needs fragile DNS interception; per-sandbox kernel state on the host to create in order, clean up on crash, and rebuild on migration | isolation as a filter over a working network: every bug is a hole, not an outage |
| **2. Proxy env convention** | zero infrastructure; no privileges; useful in-band HTTP signaling | needs the agent's cooperation (`trust_env=False`, cleared env, non-HTTP protocols and static binaries all bypass it); an endless per-runtime list of variables; HTTP(S) only | our own first design: a request, not a boundary; kept below only for coordination |
| **3. Host-side userspace stack** ([gvisor-tap-vsock](https://github.com/containers/gvisor-tap-vsock)) | guest keeps a standard NIC, any OS works; rootless; proven in podman machine, CRC, Lima | the host pays the CPU for every byte of tenant traffic (noisy neighbor); host side is a full netstack with NAT/DHCP/DNS rather than a policy point; names require owning the guest's DNS too | the right transport with the stack on the wrong side of the boundary |
| **4. Guest-side userspace stack** (**this spec**) | fail-closed by construction; the name reaches every policy decision in-band; CPU billed to the sandbox itself; the dataplane migrates inside the snapshot; identical for containers and microVMs | an injected PID 1 carrying a userspace TCP stack; more total CPU than kernel networking; TCP only | the only option that is enforced, fail-closed, name-preserving and tenant-accounted at the same time |
| **5. Socket-layer eBPF** | lowest overhead of all (socket-level splice, no packet processing); invisible to the guest | shared kernel only: cannot cross a microVM boundary, and gVisor hides guest sockets from the host kernel; sees IPs at `connect()`; `CAP_BPF` plus kernel-version maintenance | a good accelerator for option 1, not a boundary for heterogeneous sandboxes |
| **6. In-guest transparent redirect over vsock** | guest kernel's native TCP; fail-closed (tampered guest rules lose connectivity, not gain reach); enforcement on the host; tenant-accounted; proven pattern (AWS Nitro Enclaves) | the name is lost at the NAT redirect (`SO_ORIGINAL_DST` gives an IP) and must be reconstructed from SNI, Host headers, or an operator-run DoH resolver — flows that are neither TLS nor HTTP have no name; netfilter back in the guest image; a per-sandbox proxy-config control loop on the host | the close second: equal on enforcement, accounting and failure mode; loses only on the policy input |

**Why option 4:** options 4 and 6 are the two serious candidates. Both are enforced, fail-closed, tenant-accounted, decided on the host, and built on the same transport (a Unix socket / vsock byte stream), so switching between them later is cheap. The difference is the policy input. Option 6 has to reconstruct destinations from SNI, Host headers, and a resolver the operator must also run; option 4 delivers **the name, in-band, for every flow**, because the guest stack never resolves it away. Deny-by-default on names is the core of this spec, so option 4 is the design.

## The `agents.net` Contract

`agents.net` defines one enforced contract and two coordination contracts.

### I. The Boundary Contract (Egress) — enforced

The sandbox boots with **no network**: no interface other than loopback. A userspace **launcher** runs as PID 1 inside the sandbox and:

1. creates a `tun` device and makes it the sandbox's only default route;
2. terminates the sandbox's TCP in userspace and answers DNS lookups with placeholder addresses it invents (virtual DNS), so the destination reaches the boundary as a **name**, never a resolved IP;
3. opens one **HTTP `CONNECT` tunnel request** per flow over the **boundary socket**, the destination carried as a *name* in the request authority (`CONNECT api.example.com:443`) -- the policy input, in-band, for every flow. UDP crosses the same wire as `connect-udp` (RFC 9298). (Transitional note: the current reference launcher still emits a legacy SOCKS5 encoding of the same named request; converging it is a dialer swap in its embedded stack, not a redesign -- see [The Wire](#the-wire-http-connect-and-tun2connect).);
4. **refuses to start** if any interface other than loopback and its own tun exists — so a half-configured sandbox fails at startup instead of silently keeping a second route;
5. does PID 1 duties: reaps orphans, propagates signals, exits with the agent's status.

The boundary socket is a filesystem object, not a network path — which is what lets the sandbox have no network and still be reachable:

| sandbox | boundary socket |
|---|---|
| container (`--network none`) | bind-mounted Unix socket |
| microVM | vsock, surfacing on the host as a Unix socket |

The host-side boundary applies **deny-by-default policy on the name**. A refused destination is answered with HTTP `403` and a structured `Boundary-Reason` header, which the guest stack surfaces as an immediate, ordinary connection failure — `ECONNREFUSED` at `connect()`, or a reset on first use, depending on timing. Every language and library already handles that; nothing hangs. UDP is denied unless a deployment enables the `connect-udp` path -- and even then it is named, policy-checked, and audited per session like any TCP flow.

The agent needs **no configuration at all** to be confined: no proxy variables, no SDK, no patched binaries. The old proxy contract is gone because there is nothing left for the agent to honour.

The reference launcher is [`nano-init`](https://github.com/google/sam/tree/main/cmd/nano-init) from the SAM project, consumed as a prebuilt binary — it carries the userspace TCP stack ([tun2socks](https://github.com/xjasonlyu/tun2socks)) so neither this spec nor your host code has to. The launcher is replaceable: the contract is the socket and the protocol, never the binary.

#### Injecting the launcher (no image ownership required)

The launcher does not need to be baked into the agent's image, because confinement never comes from the image: the *runtime* provides the empty network namespace, the boundary socket and the tun device, and the platform controls the runtime. The launcher is a dependency-free static binary. There are two ways to inject it; **this spec recommends entrypoint injection**, and the reference implementation below uses it exclusively.

**Recommended — as the entrypoint (PID 1).**

| layer | mechanism |
|---|---|
| `docker` / `podman` | `-v /opt/agents.net/nano-init:/nano-init:ro --entrypoint /nano-init`, appending the image's original command |
| OCI bundle | bind-mount the binary and rewrite `process.args` in `config.json` to wrap the image's configured entrypoint |
| Kubernetes | a mutating webhook in the istio-init mold: an initContainer runs `nano-init copy` into a shared `emptyDir`, and the pod's `command:` is rewritten to wrap the original |
| microVM | the platform assembles the guest rootfs anyway; the launcher is `/sbin/init`, so nothing needs to be injected |

Wrapping the image's command brings PID 1 duties with it (reaping, signal propagation, the agent's exit status), couples the lifecycle (the launcher's death ends the sandbox), and makes the launcher signal-protected from every process it spawns. The one requirement: the injecting layer must read the image's original `argv` from the image config — the same thing `docker inspect` shows.

It is recommended because the lifecycle coupling removes operational work: no supervisor, no restart policy, no startup-ordering problem. If the launcher runs, the agent runs behind it; if the launcher dies, the sandbox ends. And it is one mechanism that works the same way across docker, OCI and microVMs.

**Alternative — as a side process (same network namespace).** For the cases entrypoint injection cannot serve: an agent container that must remain byte-for-byte untouched (argv included), or a platform that owns the sandbox's network namespace outright and prefers to keep the OCI process spec pristine. The launcher runs beside the agent, attached to the same network namespace, and builds the tun there:

| layer | mechanism |
|---|---|
| `docker` / `podman` | run the agent with `--network none`; run the launcher in a second container with `--network container:<agent>` |
| Kubernetes | a native sidecar (initContainer with `restartPolicy: Always`), with the pod's `dnsConfig` pointing at the launcher's resolver |
| orchestrator-owned netns | a platform that creates the sandbox's network namespace runs the launcher attached to it, touching neither the image nor the OCI process spec |

What changes: PID 1 stays the image's own; startup ordering must guarantee the launcher comes up before the agent's first connection (native sidecars provide exactly this); and the lifecycle decouples — a dead launcher leaves a running agent with *no network*, still fail-closed, so the platform has to supervise and restart it instead of relying on shared fate. On protection: a side process loses PID 1's signal shield only when it shares a PID namespace with the agent. In the arrangements above it runs in its own PID namespace, where the agent cannot see it at all, which is stronger, not weaker. The launcher's refuse-to-start interface check applies the same way in both modes.

One precondition is easy to miss on Kubernetes: a standard pod's network namespace has a CNI-provided interface, which the launcher's interface check will (correctly) refuse. Sidecar mode therefore needs a pod that genuinely has no network — a runtime class or platform that provisions an interface-free pod netns. Where that isn't available, use entrypoint injection with the launcher's `--create-namespaces` flag, which builds a nested, interface-free namespace inside the container itself.

Two properties hold in both modes:

* **A missing or dead launcher leaves a sandbox with no network, not an open one.** No interface, no resolver, no route — and in entrypoint mode its exit ends the sandbox. It fails closed at every step.
* **Bypassing the launcher gains nothing.** An agent that skips the tun entirely and speaks CONNECT directly to the boundary socket still reaches only what policy allows, because the decision is made on the host, not in the guest.

### II. The Trust Convention (TLS Inspection) — opt-in coordination

Most flows are byte pipes the boundary never inspects. For the specific domains where the host terminates TLS — credential injection, auditing, Data Loss Prevention — the host mounts a Root CA certificate into the sandbox:

```bash
AGENT_CA_CERT=/var/run/agent-ca.pem
```

This is a *convention*, and under the rule in the introduction that is acceptable: an agent that ignores it does not escape anything — its requests to inspected domains simply fail TLS verification, and the boundary's policy still holds. This is also where HTTP in-band signaling remains available: on inspected domains the boundary can still answer `403` with a block reason, `429`, or `X-Agent-Instruction` headers that agents naturally parse.

**Sandbox Implementation Requirement:** Because programming languages use different trust stores, the sandbox image build (or launcher environment) SHOULD map `AGENT_CA_CERT` to runtime-specific variables:

- `NODE_EXTRA_CA_CERTS=$AGENT_CA_CERT`
- `REQUESTS_CA_BUNDLE=$AGENT_CA_CERT`
- `SSL_CERT_FILE=$AGENT_CA_CERT`

### III. The Ingress Contract (Inbound Traffic)

To allow isolated agents to receive Webhooks, OAuth callbacks, or direct user prompts without exposing open network ports, `agents.net` treats the host harness as an **Ingress API Gateway**.

#### Application Contract (coordination)
If an agent needs to receive inbound HTTP traffic, it MUST NOT attempt to bind to a public interface (`0.0.0.0`) — there is none to bind. It binds its local web server to the loopback interface on the port specified by the environment:

```bash
AGENT_INGRESS_PORT=8081
```

When registering webhooks or providing callback URLs to third-party services, the agent MUST use the public URL provided by the host:

```bash
AGENT_PUBLIC_URL=https://agents.yourdomain.com/callbacks/agent-123
```

Both variables are coordination, not enforcement: an agent that ignores them is simply unreachable, which is fail-closed.

#### Infrastructure Contract (enforced)
The host cannot dial the sandbox: an isolated sandbox has no address to dial, and its `127.0.0.1` is not the host's. Ingress therefore uses the same mechanism as egress: a **second Unix socket**, served from *inside* the sandbox by the launcher. Network namespaces do not apply to it, because a socket is a filesystem object.

The handshake is intentionally the same one Firecracker and cloud-hypervisor hybrid-vsock already use — the host connects, writes `CONNECT <port>`, expects `OK`, then streams one inbound request per connection — so a microVM can offer the identical protocol over vsock with no code change. The launcher's accept loop forwards each stream to `127.0.0.1:$AGENT_INGRESS_PORT`.

The Host Harness MUST act as a Web Application Firewall (WAF) and Reverse Proxy: it owns the public IPs, terminates public TLS, absorbs internet attacks (DDoS, malformed payloads), strips malicious headers and enforces payload limits before anything reaches the ingress socket. The sandbox remains hermetically sealed.

## The Wire: HTTP CONNECT and tun2connect

The Boundary Contract needs exactly one thing from its wire: that every flow crosses as a *named tunnel request*. This spec standardizes that wire as **HTTP CONNECT**, because it is the tunnel primitive the entire cloud native ecosystem converged on: Envoy terminates it natively, Istio's ambient dataplane (HBONE) *is* HTTP/2 CONNECT over mTLS, gateways in the [kgateway](https://kgateway.dev) mold program the same semantics, and the IETF standardized UDP tunneling over it (MASQUE: `connect-udp`, RFC 9298, with HTTP Datagrams, RFC 9297). Standardizing on CONNECT does something no bespoke encoding could: **it makes any agentic workload pluggable into existing mesh and proxy infrastructure with zero adaptation layers.** The boundary stops being a custom component and becomes a role an off-the-shelf dataplane can fill.

The first implementation used SOCKS5, inherited from the launcher's embedded userspace stack ([tun2socks](https://github.com/xjasonlyu/tun2socks)). It is retired from the spec, kept only as a transitional compatibility note: SOCKS5 has no extension mechanism, no identity, no multiplexing, a one-opaque-byte refusal, a dead-end UDP story -- and, decisively, it is not what the rest of the infrastructure world speaks. What CONNECT provides that it could not:

| | SOCKS5 (legacy, retired) | HTTP CONNECT (the wire) |
|---|---|---|
| TCP flow | `CONNECT` + `ATYP=0x03` | `CONNECT name:port` (name is the authority, natively) |
| UDP session | denied, no path | extended CONNECT, `:protocol: connect-udp` (RFC 9298), datagrams in capsules (RFC 9297) |
| Refusal | one opaque byte (`0x02`) | `403` + `Boundary-Reason` header -- structured, in-band |
| Extension point | none | headers (identity, tracing, block reasons) |
| Multiplexing | one connection per flow | one HTTP/2 session for the whole sandbox, one stream per flow |
| Identity | none | (m)TLS under the session; the client certificate is the workload identity |
| Mesh interop | adapter required | native -- HBONE is this wire plus mesh mTLS |

### The reference implementation: [tun2connect/](tun2connect/)

[tun2connect](tun2connect/) is a standalone Go module (`github.com/aojea/agents.net/tun2connect`), the reference implementation of the wire. It terminates the sandbox's TCP/IP in userspace (gVisor) and emits one CONNECT per flow, staged so a deployment adopts exactly as much as it needs:

1. **HTTP/1.1 CONNECT** -- one boundary connection per flow; a text handshake auditable by eye; curl-compatible.
2. **HTTP/2 CONNECT** -- ONE multiplexed session for the whole sandbox (one Unix socket, one vsock, one fd); each TCP flow a CONNECT stream, each UDP session an extended CONNECT stream carrying capsules.
3. **(m)TLS under the session** -- the workload presents a client certificate; the boundary requires and verifies it. With mesh-issued certificates this is HBONE; with any other PKI it is the same wire under a different trust domain.

The module is three composable pieces, each usable alone, and every seam is an interface so implementations are pluggable:

- **`Engine`** -- the TUN-to-tunnel datapath (gVisor forwarders, per-flow dial, byte relay). Takes any `Dialer`.
- **`Dialer`** -- `DialTCP(ctx, name, port)` / `DialUDP(ctx, name, port)`: the boundary contract as a Go interface. Ships `BoundaryClient` (h1) and `BoundaryClientH2` (h2 + optional TLS); a deployment can implement it against anything that terminates CONNECT.
- **`VirtualDNS`** -- the name-preservation contract: `Resolve` invents one stable synthetic address per name (IPv4 from CGNAT `100.64.0.0/10`; IPv6 from `100::/64`, the RFC 6666 discard-only prefix, so a flow that ever escapes through a misconfigured interface is blackholed at the first conforming router); `Reverse` recovers the name at dial time. **A reverse miss is a policy event**: an address the guest never resolved has no name, and a flow without a name is refused before the boundary is ever dialed. Port 53 is always answered locally -- whatever address the guest sends it to -- and never tunneled, so a hardcoded `8.8.8.8` gets the virtual answer instead of a leak.

The virtual DNS is what keeps every stage of the wire name-preserving: the name is recovered *before* the transport is chosen, so h1 CONNECT and multiplexed h2 CONNECT carry it identically -- and policy never sees anything else.

### Mesh integration, validated

The pluggability claim is tested against a real dataplane, not argued: an **unmodified Envoy** ([tun2connect/examples/envoy-boundary.yaml](tun2connect/examples/envoy-boundary.yaml)) terminates both stages of the wire from the same engine -- h1 CONNECT and h2 prior-knowledge CONNECT -- resolving destination names with its dynamic forward proxy. Envoy is the engine inside Istio sidecars and waypoints and under kgateway, so "the boundary can be a mesh dataplane" is demonstrated, not extrapolated. The reference boundary ([tun2connect/cmd/connect-proxy](tun2connect/cmd/connect-proxy/main.go)) and Envoy are interchangeable behind the same `Dialer`.

**Identity (and where SPIFFE fits).** On the mTLS tier the workload's identity is its client certificate. Service meshes assert identity as a [SPIFFE](https://spiffe.io) ID -- a URI SAN like `spiffe://cluster.local/ns/sandbox/sa/agent-123`, issued per-workload by the mesh CA -- and a boundary joined to a mesh authenticates sandboxes exactly that way. The spec and the library are deliberately **PKI-agnostic**: tun2connect carries a `*tls.Config` and never parses what the certificates assert; the reference boundary audits the peer's first URI SAN (else DNS SAN, else CN) whatever its scheme. SPIFFE is one deployment's identity convention -- the important property is that identity rides the session's certificates, not the protocol, so rotating PKIs never touches the wire.

### Ingress on the same wire

The ingress handshake (`CONNECT <port>` / `OK`) was already CONNECT-shaped by design, for Firecracker hybrid-vsock compatibility. On the standard wire it becomes literal HTTP CONNECT, making the boundary one protocol in both directions.

## Reference Implementation: The Zero-Network Sandbox

![agents.net terminal demo](demo/terminal-demo.gif)

This demo proves that a real, unmodified, off-the-shelf agent harness running inside a container with **`--network none`** (no `eth0`, no routing, no DNS) can reach the outside world purely through the `agents.net` boundary -- no custom transport code, no vendor-specific patch, and **no proxy environment variables**. The only additions to the container are the launcher as its entrypoint and the two flags the tun device needs (`--device /dev/net/tun --cap-add NET_ADMIN`); the harness itself is untouched.

The pattern is intentionally harness-agnostic: this spec doesn't care whether the agent is a Python script, a Node process, or a packaged CLI from any vendor. The only requirement is that the harness runs non-interactively and reads its credentials from its own environment rather than requiring an interactive sign-in -- an interactive OAuth/browser flow simply can't complete inside a disposable `--network none --rm` container with no human attached. [demo/](demo/) wires up one concrete, real, off-the-shelf CLI harness end-to-end as a worked example; swap in any other harness that meets that one requirement and the same contracts and boundary apply unchanged.

**The boundary enforces a real, four-tier ACL, not just relaying.** To make the "deny-by-default on names" claim concrete rather than theoretical, the host boundary allow-lists exactly four kinds of destination. Everything else the agent tries is refused at the boundary handshake *and logged* for auditing -- the agent sees an ordinary connection error instead of a silent hang, and on the TLS-inspected tiers the boundary can additionally answer in-band HTTP (`403` with a block reason) that agents naturally parse.

1. **Fake-response hosts** (the demo's task target, `example.com`): never forwarded anywhere. The boundary terminates TLS locally with a certificate signed by a demo CA and returns a canned success response, proving the Boundary and Trust contracts together (the response is only trusted because `AGENT_CA_CERT` was mounted and wired into the runtime's trust store).
2. **Local-provider hosts** (a model server on the operator's own machine, e.g. a local Ollama instance -- the demo's default, requiring no account or paid API key): the sandbox only ever knows a symbolic hostname -- one it could never resolve on its own, since the launcher's virtual DNS invents the answer -- and the boundary alone maps it to a real `host:port`. Genuinely relayed, no TLS termination, no secret involved -- the same principle as credential-inject below, minus the credential.
3. **Credential-inject hosts**, opt-in (a real hosted model API or other bearer-token backend, for anyone migrating off the local provider): genuinely relayed to the real internet, with the boundary swapping in the real credential -- see [demo/README.md](demo/README.md) for the full mechanism. The sandbox never holds the real secret.
4. **Passthrough hosts** (housekeeping the harness does on its own -- package installs, update checks, telemetry -- that carry no secret and need no canned response): genuinely relayed byte-for-byte, with no TLS termination at all.

**Follow [demo/README.md](demo/README.md) for the full, step-by-step, hands-on walkthrough** -- generating the demo CA, starting the host boundary, building the sandbox image around the launcher, running it with `--network none`, and reading the resulting audit trail line by line, including how credential injection is proven and how to troubleshoot common failures.

The full reference implementation lives in [demo/](demo/):

- [demo/README.md](demo/README.md) — step-by-step tutorial for building and running the zero-network sandbox.
- [demo/gen_certs.sh](demo/gen_certs.sh) — generates the demo root CA and a single multi-SAN leaf certificate covering every TLS-inspected host.
- [demo/host_proxy.py](demo/host_proxy.py) — the host-side boundary of the walkthrough, speaking the legacy SOCKS5 encoding the current launcher ships (RFC 1928, `CONNECT` only, `NO AUTH`) on the boundary socket. It enforces the four-tier allow-list on destination *names*, logs every flow (relayed, injected, answered, or refused) for auditing, answers fake-response hosts itself, relays to local providers, injects real credentials for credential-inject hosts, and dials the sandbox's ingress socket for inbound traffic. It is deliberately independent of any production implementation: this file and the launcher binary interoperate only through the boundary protocol. Two unrelated implementations working together is what the spec exists to make possible.
- [demo/Dockerfile](demo/Dockerfile) — builds the sandbox image: copies the prebuilt [`nano-init`](https://github.com/google/sam/tree/main/cmd/nano-init) launcher out of its upstream image and wires one specific off-the-shelf CLI harness, unmodified, as the launched command; swap in any other harness by editing this one file.

The standard-wire reference implementation lives in [tun2connect/](tun2connect/):

- [tun2connect/pkg/tun2connect](tun2connect/pkg/tun2connect/doc.go) — the Go library: `Engine` (gVisor datapath), `VirtualDNS` (name preservation), `BoundaryClient`/`BoundaryClientH2` (h1/h2 CONNECT dialers, optional mTLS), and the exported RFC 9297 capsule codec so boundary servers reuse it.
- [tun2connect/cmd/tun2connect](tun2connect/cmd/tun2connect/main.go) — the guest-side daemon: opens a TUN, runs the engine against any CONNECT boundary.
- [tun2connect/cmd/connect-proxy](tun2connect/cmd/connect-proxy/main.go) — the reference boundary: deny-by-default on names, one audit line per decision, `-h2` for the multiplexed session, `-tls-client-ca` for mTLS with peer identity auditing. Curl-testable without root.
- [tun2connect/examples/envoy-boundary.yaml](tun2connect/examples/envoy-boundary.yaml) — an unmodified Envoy filling the boundary role at both wire stages: the mesh-integration proof.
