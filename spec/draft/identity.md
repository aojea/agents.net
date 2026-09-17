# Identity and Channel Binding

**Part of:** [agents.net specification, version 1 (draft)](index.md)  
**Status:** Draft

This document defines how a boundary learns which sandbox a request belongs
to and which policy applies. The wire ([wire.md](wire.md)) never carries
identity; the channel does. Four bindings are defined: a dedicated listener
(the baseline), a certificate-authenticated channel, a shared process with
dedicated listeners, and VM channels.

## 1. Identity and Metadata

- **Guest metadata:** Headers such as `Sandbox-Id` MAY carry telemetry. They MUST NOT select an identity or grant permissions. The boundary MUST discard or overwrite guest identity headers before passing identity to another trusted service. A boundary MAY copy such values into the audit record's `meta` object ([audit.md](audit.md)).
- **Dedicated endpoint:** In the local model, the controller MUST bind the listener to one sandbox lifetime and policy. Socket access controls establish permission to use that policy. Peer credentials MAY provide additional audit or access checks; they are not required to rediscover an identity already fixed by the listener.
- **Other transports:** A deployment using a shared listener or VM relay MUST provide an equivalent trusted binding. Unix peer credentials and VSOCK CIDs require a mapping that handles restarts and identifier reuse. The socket peer may be a runtime process rather than the application. These identifiers are not cryptographic attestation.
- **Optional mTLS:** The channel MAY use mTLS with a deployment-issued workload certificate. The certificate format and issuing authority are deployment choices. The authenticated identity selects policy (Section 4). A shared session MUST NOT select different identities from untrusted per-stream headers.

Policy configuration and certificate issuance are outside the wire protocol.
Implementation-specific filters, APIs, and route resources are not part of this
specification.

## 2. Isolation and Channel Ownership

The controller MUST exclude direct external routes, additional NICs, inherited
host network sockets, unauthorized VSOCK services, and access to other
workloads' boundary endpoints. Management interfaces and descriptor-transfer
interfaces MUST NOT be exposed on workload data channels.

In the local model, the controller MUST create a dedicated pathname Unix socket
with a fixed sandbox and policy binding before exposing it to the adapter.
Exclusive access to that listener is sufficient to select the assigned policy;
the adapter does not need to prove its identity again. The boundary MUST NOT
let a request select another listener's identity or policy.

Pathname socket access depends on filesystem permissions, mount visibility,
and directory ownership. Network-namespace isolation alone does not protect a
shared pathname. Abstract Unix sockets do not have filesystem permissions.
Workloads MUST NOT be able to replace socket paths or modify boundary policy,
credentials, logs, or executable files.

Only the assigned socket or its dedicated directory is exposed to the adapter,
not a directory containing other workloads' sockets. Permissions must account
for host UID/GID mappings and any capabilities that bypass filesystem checks.
Several sandboxes running as the same host UID are not separated by a `0600`
socket mode alone. The runtime MUST prevent alternate filesystem access,
cross-process FD theft, and access to container/runtime management sockets.
The namespace adapter needs these process and filesystem restrictions as well
as its network namespace. Its namespace-local network capability does not
justify unrestricted host privileges.

`SO_PEERCRED` reports credentials associated with connection or socket-pair
creation; passing an FD does not update those credentials to the new holder.
It may support audit or an additional access check on a dedicated listener.
If a deployment uses UIDs, PIDs, namespace handles, or VSOCK CIDs to select
identity, it MUST map them through trusted controller state, handle reuse, and
not treat them as globally unique tenant identities. VSOCK CID 1 is local
communication, not VM attestation.

Connected-FD provisioning is an optional alternative to pathname sockets.
`SCM_RIGHTS` duplicates access to an open file description; it does not move a
socket into another namespace or establish its holder's identity. A deployment
using a registration service MUST authenticate and authorize its control peer,
bind each endpoint to a sandbox lifetime and policy, validate descriptor
count/type/state, reject truncated ancillary data, close unexpected descriptors,
and prevent unintended inheritance. `SO_PASSCRED` with `SCM_CREDENTIALS` can
authenticate local registration messages under Linux credential rules. Neither
mechanism is required on the baseline CONNECT data channel.

## 3. Listener-Bound Identity (`boundary-core`)

Access to the listener selects the policy. A request field never selects
identity. This is the baseline binding; every other binding in this document
must provide an equivalent to it.

## 4. Certificate-Bound Identity (`boundary-tls`)

### 4.1 Authentication and Transport Integrity

The local model relies on kernel access controls, runtime confinement, and the
controller's fixed listener binding. It does not require mTLS, signed CONNECT
requests, or a registration protocol between the adapter and boundary. Across an
untrusted transport, the adapter and boundary MUST authenticate each other and
protect traffic confidentiality and integrity. TLS is the reference mechanism.
Transport protection applies to the outer channel; it does not authenticate
the upstream application or inspect inner TLS traffic.

For TLS deployments:

1. Verify certificate chains against configured trust anchors, validity periods, permitted algorithms, and the appropriate server/client extended key usage.
2. Verify the expected boundary identity against a SAN. A client certificate must map to an authorized workload identity; a valid chain alone does not grant policy or tenant access. Ambiguous identity mappings MUST be rejected.
3. Reject missing required client certificates, unknown issuers, expired or not-yet-valid certificates, and mismatched endpoint identities. Authentication failure MUST NOT fall back to plaintext or anonymous access.
4. Require TLS 1.2 or later and prefer TLS 1.3. HTTP/2 over TLS MUST negotiate `h2` through ALPN. Verification must remain enabled in production.
5. Define certificate rotation, compromise response, and revocation. Expiration does not automatically terminate an established TLS session. Session resumption MUST NOT bypass current identity, generation, or policy checks. Do not accept tunnel authorization in replayable TLS early data.

TLS proves possession of a key and protects records against modification. It
does not prove that an authenticated workload is uncompromised. A key stored
inside an untrusted guest may be extracted or used by guest root. A certificate
or signature supplied by that guest cannot attest to the integrity of its own
CONNECT construction.

A separate CONNECT signature is not required on an authenticated, protected
channel. If a deployment uses signed delegation through intermediaries, the
signature must bind the issuer, subject, audience, destination, port, transport,
direction, generation, expiry, and replay context. The boundary still validates
the request and applies local policy. Signing untrusted claims does not make
their content safe.

### 4.2 Identity Mapping

A `boundary-tls` listener terminates TLS 1.2 or later with a
deployment-issued server certificate. When it requires client certificates it
MUST verify the chain against configured anchors and the `clientAuth`
extended key usage, derive the identity from the first URI SAN, else the
first DNS SAN, else the Common Name, and look it up in controller-provided
state that maps identity to policy. A missing or unmapped identity MUST be
rejected with a TLS alert or a 403 `identity-unknown` before any request is
authorized. All streams and requests on the session carry that identity.
Session resumption MUST re-evaluate the mapping. The listener's own policy,
if any, applies only to connections whose identity maps to it.

This binding is the HBONE-style arrangement: HTTP/2 CONNECT over mTLS with a
SPIFFE URI SAN is one conforming instance.

## 5. Shared Process, Dedicated Listeners (`boundary-multi`)

A boundary process serving several listeners MUST keep, per listener: the
identity and generation, the policy descriptor, connection and stream
budgets, idle and head deadlines, and the audit `listener`/`sandbox` labels.
Exhaustion of one listener's budget MUST NOT cause another listener to refuse
requests. Closing one listener MUST terminate its accepted connections and
pending dials and MUST NOT affect other listeners. Policy replacement for one
listener MUST be atomic with respect to requests on that listener and MUST be
recorded with the new `policy` value. The process is a shared compromise
boundary; deployments that isolate mutually untrusted workloads from a
boundary compromise MUST NOT rely on this binding alone.

## 6. VM Channels (`controller-vm`)

| Channel | Identity source | Requirements |
| --- | --- | --- |
| Firecracker-style Unix-backed vsock | Host Unix socket `<prefix>_<port>` bound by the controller for one VM | Listener-bound identity; ports not bound are unreachable; no relay process |
| Host `AF_VSOCK` | Guest CID observed on accept | Controller maps CID to sandbox generation; one listener per (CID, port) or a listener that dispatches on CID from controller state only; CID reuse invalidates the mapping before a new VM starts |
| Hyper-V sockets (`AF_HYPERV`) | VM ID (GUID) observed on accept | Same rules as `AF_VSOCK` with the VM ID as the identifier |
| Userspace packet backend (QEMU stream, similar) | The adapter is outside the guest; its boundary socket is listener-bound | Adapter confinement per Section 2; one packet channel per VM lifetime |

Any identifier observed on accept is provenance, not attestation. The
controller MUST record the mapping before the VM starts, revoke it before the
identifier can be reused, and expose to each VM only the ports bound for it.
