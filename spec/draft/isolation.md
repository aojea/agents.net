# Isolation Model and Controller Requirements

**Part of:** [agents.net specification, version 1 (draft)](index.md)  
**Status:** Draft

This document states what the runtime and controller must guarantee so that
the wire profile's guarantee holds: the local security model, socket
ownership, the threat model, what a boundary can and cannot establish,
software integrity, controller conformance, and the limits of the guarantee.
Lifecycle, revocation, and resource limits are in
[lifecycle.md](lifecycle.md); identity bindings in [identity.md](identity.md).

## 1. Local Security Model

The baseline is one dedicated boundary socket per sandbox lifetime:

```text
sandbox A -> adapter A -> socket A -> policy A -> permitted destinations
sandbox B -> adapter B -> socket B -> policy B -> permitted destinations
```

The controller creates the socket-to-policy binding. The boundary selects
identity from the listener that accepted the connection, never from CONNECT
headers, source IPs, or the adapter's claims. All connections and HTTP/2 streams
accepted on that listener use the same sandbox identity. A single socket
pathname supports many connections; it does not require FD passing.

The simplest deployment runs one boundary process per sandbox, with one
listener and one fixed policy. A boundary implementation may instead share a
process across dedicated listeners if it keeps their policies and resources
separate. A shared process remains a shared compromise boundary. A single
listener serving multiple workload identities is not part of the baseline.

The local model requires:

1. **Confinement:** Neither the sandbox nor its adapter has an external network path other than the assigned socket. The namespace proxy must also be restricted from accessing other boundary sockets, host management sockets, or inherited external sockets; a network namespace alone does not restrict filesystem access.
2. **Socket access:** The controller owns the socket directory and policy. Mount visibility, filesystem permissions, and runtime isolation prevent other untrusted workloads from connecting or replacing the endpoint. A pathname or numeric mode alone is not evidence that these restrictions hold.
3. **Fixed identity:** Access to the socket grants use of its sandbox policy, not unrestricted upstream access. No guest-held certificate, identity header, or per-request credential exchange is needed to select that policy.
4. **External enforcement:** The boundary treats all CONNECT fields as untrusted, parses them, checks destination/port/transport policy, and dials only an authorized address. The adapter is not an authorization component.
5. **Opaque content:** A successful CONNECT permits an untrusted byte stream or datagrams to one selected destination. It does not authenticate application intent or make content safe.
6. **Bounded lifetime:** The controller installs policy before exposing the endpoint and revokes the endpoint and its active flows during teardown. Socket access is never reassigned to a different sandbox while old sessions remain live.

The host kernel, runtime confinement, controller, and boundary are trusted.
Compromise of either adapter must not grant more than use of its assigned
socket policy; protecting the host from such a compromise is the runtime's
responsibility. The namespace adapter exposes the host kernel's packet stack,
whereas the in-guest TUN adapter performs translation inside the sandbox. The
two adapters also differ in privilege: the TUN adapter needs `CAP_NET_ADMIN`
and `/dev/net/tun` inside the sandbox to create its device, while the
namespace adapter needs `CAP_NET_ADMIN` only in its own namespace and the
workload needs no capability. The reference launcher drops `CAP_NET_ADMIN`
from itself and from the workload's bounding set once the device exists.

FD registration, `SCM_CREDENTIALS`, workload mTLS, attestation, credential
injection, and ingress are optional extensions, not prerequisites for this
local model. The applicable security requirements in this specification still apply
when an extension is selected.

## 2. Socket Ownership and Namespace Access

For egress, the boundary is the Unix socket server and the adapter is its
client. The boundary creates and listens on the socket in its own environment;
the adapter connects to it. The boundary does not connect to a listener in the
adapter, enter the adapter's network namespace, or receive its namespace FD.

```text
Boundary environment                         Adapter environment

listen: /run/agents.net/sandbox-A/boundary.sock
                      ^
                      | same socket, exposed by the runtime
                      |
                      +----- connect: /run/agents.net/boundary.sock

accept CONNECT -> authorize -> dial upstream
```

On Linux, pathname Unix sockets can connect across network namespaces on the
same kernel. The client must be able to resolve the socket inode through its
filesystem view and pass the applicable permissions and security checks. No IP
route, veth connection to the host, or `setns` call is needed for that Unix
connection. Abstract Unix socket names, unlike pathname sockets, are scoped by
the network namespace; the baseline uses pathname sockets.

The runtime exposes the socket as follows:

1. Start the boundary listener in a protected per-sandbox directory with its policy configured and access restricted before exposing it.
2. Bind-mount only that socket, or its dedicated directory, into the adapter's mount namespace. The host and adapter pathnames may differ; they refer to the same socket. Configure the adapter with the path visible inside its environment.
3. Grant the adapter's mapped UID/GID permission to connect while keeping the directory and endpoint under trusted ownership. A read-only bind mount can prevent filesystem changes through that mount, but does not make socket communication read-only or replace socket access checks.
4. Start the sandbox only after the adapter is ready. During teardown, close active sessions and remove exposure. If an individually mounted socket is unlinked and recreated, its mount still references the old inode; restart must establish the new exposure explicitly.

The TUN adapter gets this mount inside the sandbox. The namespace adapter gets
it in its own restricted process environment, outside the workload; the workload
does not need the socket mounted. Processes already sharing a filesystem view
can resolve the same path without a bind mount, but sharing the host filesystem
is not a substitute for restricting the adapter's access.

A central boundary can own several dedicated listeners in one network
namespace, each bound to a different sandbox policy. Its upstream sockets are
created in the boundary's network namespace. The adapters remain in their
respective namespaces. The requirements for such a process are in [identity.md](identity.md#5-shared-process-dedicated-listeners-boundary-multi).

| Mechanism | Purpose | Needed for the local socket path? |
| --- | --- | --- |
| Pathname visibility, permissions, and runtime isolation | Expose exactly the assigned endpoint and control who can connect | Yes |
| `SO_PEERCRED` or `SO_PASSCRED` / `SCM_CREDENTIALS` | Obtain kernel-checked peer or sender credentials; does not expose or transfer a socket | No; optional additional access or audit checks |
| `SCM_RIGHTS` | Pass access to an already-open socket FD over Unix IPC | No; optional alternative provisioning mechanism |
| Entering a network namespace | Run packet redirection or create network sockets in that namespace | The namespace adapter runs there; the boundary does not |

These rules concern processes sharing the host kernel. A VM cannot use a host
Unix socket through a filesystem mount alone; it needs a VM channel
([identity.md](identity.md#6-vm-channels-controller-vm)). Optional ingress reverses client/server roles but is a
separate channel and does not change the egress arrangement.

## 3. Threat Model

The workload and either adapter may be malicious. They may forge CONNECT
requests, change DNS settings, open literal-IP connections, replace the adapter,
send malformed packets or HTTP frames, replay requests, and attempt resource
exhaustion. Guest-provided names, headers, packets, and payloads are untrusted.
Upstream services and their responses may also be malicious.

The trusted system consists of the host kernel, the isolation runtime or VMM,
the controller, and the boundary. An optional credential gateway or issuer adds
to that trusted system.
A container shares the host kernel; container root and VM guest-kernel
compromise are different threat models. Host-kernel or VMM compromise is outside
this interface's guarantees. Namespace mode adds the namespace-local kernel
network stack and trusted redirection setup to the packet path.

The guarantee is that external traffic crosses an authorized channel and
reaches only destinations permitted for its assigned workload. It is not a
guarantee about application intent, content safety, or the behavior of an
allowed service. Implementation status and verification gaps are recorded with the
[conformance suite](../../conformance/README.md) and
[docs/implementations.md](../../docs/implementations.md); requirements here
are not claims that all controls exist.

## 4. What Can Be Established

CONNECT is a request for authority, not evidence that the caller already has
it. A request generated by the reference adapter has no special trust over an
identical request written by the workload itself.

| Input or observation | Required verification | Result and limit |
| --- | --- | --- |
| Channel ownership | Controller-configured listener binding and exclusive workload access; authenticated transport for deployments that require it | Identifies the sandbox policy available through the channel, not the particular code sending bytes |
| CONNECT destination | Strict parsing followed by destination, port, transport, and workload policy | Establishes permission to connect, not that the declared name describes the tunneled application |
| Resolved address | Boundary-side resolution and policy check on the exact address dialed | Establishes an allowed network destination; DNS alone does not authenticate the upstream service |
| Protected transport record | TLS verification or kernel-protected local IPC under the host trust assumptions | Detects unauthorized modification in transit; authenticated endpoints can still send malicious data |
| Tunneled content | No semantic verification in opaque tunnel mode | Arbitrary untrusted bytes in both directions, including additional protocol handshakes and apparent identity headers |
| Software identity | Verified artifact and, where required, measured launch | Evidence of an approved artifact or launch state, not proof of continued runtime integrity |

For example, after verifying a request the boundary can record:
"sandbox A, generation G, was allowed by policy P to connect to address D on
TCP port 443." It cannot conclude that the stream contains HTTPS, that an
HTTP Host header matches the CONNECT name, or that the operation is benign.

## 5. Software Integrity and Attestation

The local model trusts the host and its runtime; it does not require an
attestation service. Protecting trusted components from workload modification
is still required.

Controllers, boundary proxies, and credential gateways MUST load executable
code and policy only from authorized sources. Workloads must not be able to
modify their binaries, libraries, configuration, or administrative endpoints.
Recommended controls include:

- Pin artifacts by digest and verify signatures against configured publisher identities. Validate build provenance where required. A digest without an authenticated source is not evidence of a trusted publisher.
- Use read-only images/configuration, least-privilege UIDs, isolated mounts and PID namespaces, restricted process tracing, and SELinux/AppArmor or equivalent policy. Drop capabilities not needed by the selected adapter; namespace TPROXY has specific capability requirements.
- Protect runtime and controller sockets, debug endpoints, core dumps, and access to process memory. Authenticate policy updates, apply them atomically, and reject stale versions according to the controller's update protocol.
- Patch dependencies and isolate protocol parsers. Use fuzzing, race detection, negative tests, and independent review for exposed parsers and lifecycle handling.

Measured boot, TPM quotes, or confidential-VM attestation MAY be used when a
deployment requires verified launch state. Verification must include a trusted
endorsement chain, fresh verifier challenge, accepted measurements, minimum
security version, and debug/migration policy. To authorize a channel or release
a key, bind the evidence to that channel's public key and intended workload;
an unrelated attestation report must not authorize another session.

Attestation establishes a measured state under its hardware and verifier trust
assumptions. It does not prove that application requests are safe or that no
runtime compromise occurred after measurement. Without attestation, proxy
integrity is an explicit host/runtime trust assumption, supported by deployment
controls and tests rather than claimed as a cryptographic proof.

## 6. Controller Conformance

### 6.1 Local (`controller-local`)

The lifecycle in [lifecycle.md](lifecycle.md#2-ingress-revocation-and-updates)
has two observable states. **Ready** means the boundary listener accepts
connections and answers a request under the installed policy; a controller
MUST NOT start the workload before observing readiness. **Revoked** means the
listener no longer accepts connections and every connection it had accepted
has terminated; a controller MUST NOT report revocation, reuse the socket
path, or reuse the sandbox identity for a new generation before observing it.
Two sandboxes under one controller MUST NOT be able to connect to each other's
boundary sockets, and a request forged on one sandbox's channel MUST be
decided under that channel's policy.

### 6.2 VM (`controller-vm`)

[identity.md Section 6](identity.md#6-vm-channels-controller-vm) applies. The
VM has no network device other than one that terminates in a conformant
adapter; only the boundary and ingress ports are bound for it.

### 6.3 Ingress Binding

The controller pins one loopback port per sandbox generation, exposes the
ingress channel only to the gateway, and revokes the route at teardown
([ingress.md](ingress.md)).

### 6.4 Runtime Audit Checklist

Properties that are not observable through the wire are recorded per
deployment by inspection; the checklist is
[conformance/README.md Section 6](../../conformance/README.md#6-runtime-audit-checklist).

## 7. Limits of the Guarantee

A compromised boundary can misuse all authority available to its process.
Allowed destinations can exfiltrate data or relay traffic elsewhere. A local
channel can be delegated by any holder able to pass or duplicate its descriptor.
Network namespaces do not isolate host-kernel vulnerabilities or all resource
side channels. Timing and traffic-volume leakage are not eliminated by this
protocol. Tests provide evidence for specified cases, not proof of universal
isolation, complete application compatibility, or absence of implementation bugs.
