# Isolation Model and Controller Requirements

**Part of:** [agents.net specification, version 1 (draft)](index.md)  
**Status:** Draft

This document states what the runtime and controller have to provide for the
wire profile's guarantee to hold. It covers the local security model, socket
ownership, the threat model, what a boundary can establish about a request,
software integrity, controller conformance, and the limits of the guarantee.
Lifecycle, revocation, and resource limits are in
[lifecycle.md](lifecycle.md); identity bindings are in
[identity.md](identity.md).

## 1. Local Security Model

The baseline is one dedicated boundary socket per sandbox lifetime:

```text
sandbox A -> adapter A -> socket A -> policy A -> permitted destinations
sandbox B -> adapter B -> socket B -> policy B -> permitted destinations
```

The controller binds each socket to a policy. The boundary takes the identity
of a connection from the listener that accepted it; CONNECT headers, source
IPs, and the adapter's own claims play no part in that selection. Every
connection and HTTP/2 stream accepted on a listener carries the same sandbox
identity. One socket pathname serves any number of connections, so FD passing
is not needed.

The simplest deployment runs one boundary process per sandbox with one
listener and one fixed policy. A boundary implementation can instead serve
several dedicated listeners from one process if it keeps their policies and
resources separate, at the cost that a compromise of that process reaches
every listener it serves. A single listener serving several workload
identities is not part of the baseline.

The local model requires:

1. **Confinement:** Neither the sandbox nor its adapter has any external network path other than the assigned socket. The namespace proxy also has to be kept away from other boundary sockets, host management sockets, and inherited external sockets; a network namespace does not do this by itself, since it does not restrict filesystem access.
2. **Socket access:** The controller owns the socket directory and the policy. Mount visibility, filesystem permissions, and runtime isolation keep other untrusted workloads from connecting to the endpoint or replacing it. The pathname and the numeric mode by themselves do not show that these restrictions hold.
3. **Fixed identity:** A process that can reach the socket can use the sandbox policy behind it and nothing more. Selecting that policy needs no guest-held certificate, identity header, or per-request credential exchange.
4. **External enforcement:** The boundary treats every CONNECT field as untrusted input. It parses the request, checks the destination, port, and transport against policy, and dials only an address the policy authorizes. The adapter takes no part in authorization.
5. **Opaque content:** A successful CONNECT opens an untrusted byte stream, or a flow of datagrams, to one selected destination. Nothing in it authenticates the application's intent or makes the content safe.
6. **Bounded lifetime:** The controller installs the policy before it exposes the endpoint, and at teardown revokes the endpoint together with its active flows. Socket access is never handed to a different sandbox while sessions from the old one are still live.

The host kernel, the runtime confinement, the controller, and the boundary are
trusted. A compromised adapter of either kind gains at most the use of its
assigned socket policy; keeping such a compromise away from the host is the
runtime's job. The two adapters expose different attack surfaces and need
different privileges. The namespace adapter lets workload packets traverse the
host kernel's network stack, while the in-guest TUN adapter translates them
inside the sandbox. The TUN adapter needs `CAP_NET_ADMIN` and `/dev/net/tun`
inside the sandbox to create its device; the namespace adapter needs
`CAP_NET_ADMIN` only in its own namespace, and the workload needs no
capability at all. The reference launcher drops `CAP_NET_ADMIN` from itself
and from the workload's bounding set once the device exists.

FD registration, `SCM_CREDENTIALS`, workload mTLS, attestation, credential
injection, and ingress are optional extensions; the local model works without
them. A deployment that selects an extension remains subject to the security
requirements this specification places on it.

## 2. Socket Ownership and Namespace Access

For egress the boundary is the Unix socket server and the adapter its client.
The boundary creates the socket and listens on it in its own environment, and
the adapter connects to it. The boundary never connects to a listener in the
adapter, enters the adapter's network namespace, or receives its namespace FD.

```text
Boundary environment                         Adapter environment

listen: /run/agents.net/sandbox-A/boundary.sock
                      ^
                      | same socket, exposed by the runtime
                      |
                      +----- connect: /run/agents.net/boundary.sock

accept CONNECT -> authorize -> dial upstream
```

On Linux a pathname Unix socket can be connected to across network namespaces
on the same kernel. The client needs to resolve the socket inode through its
own filesystem view and pass the applicable permission and security checks; it
needs no IP route, no veth link to the host, and no `setns` call. Abstract
Unix socket names, unlike pathnames, are scoped to a network namespace. The
baseline uses pathname sockets.

The runtime exposes the socket as follows:

1. The boundary listener starts in a protected per-sandbox directory, with its policy configured and access restricted, before anything is exposed.
2. Only that socket, or its dedicated directory, is bind-mounted into the adapter's mount namespace. The host pathname and the adapter pathname can differ; they name the same socket, and the adapter is configured with the path visible inside its own environment.
3. The adapter's mapped UID/GID is granted permission to connect while the directory and the endpoint stay under trusted ownership. A read-only bind mount prevents filesystem changes through that mount; it does not make socket communication read-only and does not replace socket access checks.
4. The sandbox starts only after the adapter is ready. At teardown, active sessions are closed and the exposure is removed. If an individually mounted socket is unlinked and recreated, the mount still points at the old inode, so a restart has to set up the new exposure explicitly.

The TUN adapter receives this mount inside the sandbox. The namespace adapter
receives it in its own restricted process environment outside the workload,
and the workload itself does not need the socket mounted. Processes that
already share a filesystem view can resolve the same path without a bind
mount; sharing the host filesystem with the adapter is not a substitute for
restricting what it can reach.

A central boundary can own several dedicated listeners in one network
namespace, each bound to a different sandbox policy. It creates its upstream
sockets in its own network namespace while the adapters stay in theirs. The
requirements for such a process are in [identity.md](identity.md#5-shared-process-dedicated-listeners-boundary-multi).

| Mechanism | Purpose | Needed for the local socket path? |
| --- | --- | --- |
| Pathname visibility, permissions, and runtime isolation | Expose exactly the assigned endpoint and control who can connect | Yes |
| `SO_PEERCRED` or `SO_PASSCRED` / `SCM_CREDENTIALS` | Obtain kernel-checked peer or sender credentials; does not expose or transfer a socket | No; optional additional access or audit checks |
| `SCM_RIGHTS` | Pass access to an already-open socket FD over Unix IPC | No; optional alternative provisioning mechanism |
| Entering a network namespace | Run packet redirection or create network sockets in that namespace | The namespace adapter runs there; the boundary does not |

These rules apply to processes that share the host kernel. A VM cannot reach
a host Unix socket through a filesystem mount and needs a VM channel instead
([identity.md](identity.md#6-vm-channels-controller-vm)). Optional ingress
reverses the client and server roles, but it is a separate channel and leaves
the egress arrangement unchanged.

## 3. Threat Model

The workload and either adapter can be malicious. They can forge CONNECT
requests, change DNS settings, open connections to literal IP addresses,
replace the adapter, send malformed packets or HTTP frames, replay requests,
and try to exhaust resources. Every name, header, packet, and payload that
originates in the guest is untrusted, and so are upstream services and their
responses.

The trusted system consists of the host kernel, the isolation runtime or VMM,
the controller, and the boundary. An optional credential gateway or issuer,
when present, joins that trusted system. A container shares the host kernel,
so a compromise of container root is a different threat from a compromise of
a VM's guest kernel. A compromise of the host kernel or the VMM is outside
what this interface guarantees. In namespace mode the packet path additionally
includes the namespace-local kernel network stack and the trusted redirection
setup.

The guarantee is that external traffic crosses an authorized channel and
reaches only destinations permitted for the workload assigned to that channel.
It says nothing about the application's intent, the safety of the content, or
how an allowed service behaves. Implementation status and verification gaps
are recorded with the [conformance suite](../../conformance/README.md) and in
[docs/implementations.md](../../docs/implementations.md). A requirement in
this document is not a claim that every implementation meets it.

## 4. What Can Be Established

A CONNECT request asks for permission to reach a destination; it carries no
evidence that the caller already has that permission. A request produced by
the reference adapter earns no more trust than an identical request written
by the workload itself.

| Input or observation | Required verification | Result and limit |
| --- | --- | --- |
| Channel ownership | Controller-configured listener binding and exclusive workload access; authenticated transport for deployments that require it | Identifies the sandbox policy available through the channel, not the particular code sending bytes |
| CONNECT destination | Strict parsing followed by destination, port, transport, and workload policy | Establishes permission to connect, not that the declared name describes the tunneled application |
| Resolved address | Boundary-side resolution and policy check on the exact address dialed | Establishes an allowed network destination; DNS alone does not authenticate the upstream service |
| Protected transport record | TLS verification or kernel-protected local IPC under the host trust assumptions | Detects unauthorized modification in transit; authenticated endpoints can still send malicious data |
| Tunneled content | No semantic verification in opaque tunnel mode | Arbitrary untrusted bytes in both directions, including additional protocol handshakes and apparent identity headers |
| Software identity | Verified artifact and, where required, measured launch | Evidence of an approved artifact or launch state, not proof of continued runtime integrity |

After verifying a request, for example, the boundary can record "sandbox A,
generation G, was allowed by policy P to connect to address D on TCP port
443." It cannot conclude that the stream carries HTTPS, that an HTTP Host
header inside it matches the CONNECT name, or that the operation is benign.

## 5. Software Integrity and Attestation

The local model trusts the host and its runtime and needs no attestation
service. It still depends on trusted components being protected from
modification by the workload.

Controllers, boundary proxies, and credential gateways MUST load executable
code and policy only from authorized sources. A workload has to be unable to
modify their binaries, libraries, configuration, or administrative endpoints.
Recommended controls include:

- Artifacts pinned by digest, with signatures verified against configured publisher identities and build provenance validated where required. A digest alone, without an authenticated source, does not identify a trusted publisher.
- Read-only images and configuration, least-privilege UIDs, isolated mounts and PID namespaces, restricted process tracing, and SELinux, AppArmor, or equivalent policy. Capabilities the selected adapter does not need are dropped; namespace TPROXY has capability requirements of its own.
- Protection of runtime and controller sockets, debug endpoints, core dumps, and process memory. Policy updates that are authenticated, applied atomically, and rejected when they carry a stale version, according to the controller's update protocol.
- Patched dependencies and isolated protocol parsers, with fuzzing, race detection, negative tests, and independent review applied to exposed parsers and lifecycle handling.

Measured boot, TPM quotes, or confidential-VM attestation MAY be used when a
deployment requires a verified launch state. Verification covers the
endorsement chain, a fresh verifier challenge, the accepted measurements, the
minimum security version, and the debug and migration policy. Evidence that
authorizes a channel or releases a key has to be bound to that channel's
public key and to the intended workload, so that an attestation report from
one session cannot authorize another.

Attestation establishes a measured state under the trust assumptions of its
hardware and verifier. It does not show that application requests are safe or
that the runtime stayed uncompromised after measurement. Without attestation,
the integrity of the proxy is a trust assumption about the host and runtime,
supported by deployment controls and tests rather than by cryptographic proof.

## 6. Controller Conformance

### 6.1 Local (`controller-local`)

The lifecycle in [lifecycle.md](lifecycle.md#2-ingress-revocation-and-updates)
has two observable states. **Ready** is reached when a CONNECT to a
destination the policy denies, sent on the sandbox's channel, receives a 403
rather than a connection error within the `ready_timeout_ms` declared in the
implementation statement. A controller MUST NOT start the workload before
observing readiness. **Revoked** is reached when a new connection on the
channel fails, every connection the listener had accepted has been closed by
the boundary (the client sees EOF or a reset), and the last audit record for
that generation carries a timestamp no later than the controller's revocation
report. A controller MUST NOT report revocation, reuse the socket path, or
reuse the sandbox identity for a new generation before observing that state.
Two sandboxes under one controller MUST NOT be able to connect to each
other's boundary sockets, and a request forged on one sandbox's channel MUST
be decided under that channel's policy.

### 6.2 VM (`controller-vm`)

[identity.md Section 6](identity.md#6-vm-channels-controller-vm) applies. The
VM has no network device other than one that terminates in a conformant
adapter, and only the boundary and ingress ports are bound for it.

### 6.3 Ingress Binding

The controller pins one loopback port per sandbox generation, exposes the
ingress channel only to the gateway, and revokes the route at teardown
([ingress.md](ingress.md)).

### 6.4 Runtime Audit Checklist

Properties that cannot be observed through the wire are recorded per
deployment by inspection, following the checklist in
[conformance/README.md Section 6](../../conformance/README.md#6-runtime-audit-checklist).

## 7. Limits of the Guarantee

A compromised boundary can misuse all the authority its process holds. An
allowed destination can exfiltrate data or relay traffic elsewhere. Any holder
of a local channel who can pass or duplicate its descriptor can delegate it.
Network namespaces do not contain host-kernel vulnerabilities, and they do not
close every resource side channel; this protocol also leaves timing and
traffic-volume leakage in place. Tests provide evidence for the cases they
cover. They do not prove universal isolation, complete application
compatibility, or the absence of implementation bugs.
