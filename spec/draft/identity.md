# Identity and Channel Binding

**Part of:** [agents.net specification, version 1 (draft)](index.md)  
**Status:** Draft

This document defines how a boundary learns which sandbox a request belongs
to and which policy applies. The identity of a request comes from the channel
it arrives on; the wire protocol ([wire.md](wire.md)) has no field for it.
Four bindings are defined: a dedicated listener (the baseline), a
certificate-authenticated channel, a shared process with dedicated listeners,
and VM channels.

## 1. Identity and Metadata

Headers set by the guest, such as `Sandbox-Id`, MAY carry telemetry. They
MUST NOT select an identity or grant permissions. Before the boundary passes
identity to another trusted service it MUST discard or overwrite any guest
identity headers. A boundary MAY copy their values into the `meta` object of
the audit record ([audit.md](audit.md)).

In the local model the controller MUST bind each listener to one sandbox
lifetime and one policy. A process that can connect to the socket is
permitted to use that policy; the socket's access controls are the permission
check. Peer credentials MAY add audit detail or a further access check. They
are not needed to establish an identity the listener already fixes.

A deployment that uses a shared listener or a VM relay MUST provide a trusted
binding equivalent to the dedicated listener. Unix peer credentials and vsock
CIDs need a mapping that survives restarts and identifier reuse before they
can name a sandbox. The peer on such a socket can be a runtime process rather
than the application itself, and none of these identifiers is cryptographic
attestation.

The channel MAY use mTLS with a workload certificate issued by the
deployment; the certificate format and the issuing authority are deployment
choices. The authenticated identity then selects the policy (Section 4). A
shared session MUST NOT select different identities from untrusted per-stream
headers.

Policy configuration and certificate issuance are outside the wire protocol,
and implementation-specific filters, APIs, and route resources are not part of
this specification.

## 2. Isolation and Channel Ownership

The controller MUST exclude direct external routes, additional NICs, inherited
host network sockets, unauthorized vsock services, and access to other
workloads' boundary endpoints from the sandbox. Management interfaces and
descriptor-transfer interfaces MUST NOT be exposed on workload data channels.

In the local model the controller MUST create a dedicated pathname Unix
socket, bound to one sandbox and one policy, before exposing it to the
adapter. Because only that sandbox's adapter can reach the listener,
connecting to it is enough to select the assigned policy, and the adapter does
not prove its identity again. The boundary MUST NOT let a request select
another listener's identity or policy.

Access to a pathname socket is governed by filesystem permissions, mount
visibility, and directory ownership. A network namespace by itself does not
protect a shared pathname, and abstract Unix sockets have no filesystem
permissions at all. Workloads MUST NOT be able to replace socket paths or
modify boundary policy, credentials, logs, or executable files.

The adapter sees only its assigned socket or the directory dedicated to it,
never a directory that also holds other workloads' sockets. Permissions have
to be evaluated against the host UID/GID mapping and against any capability
that bypasses filesystem checks; a `0600` socket mode does not separate
several sandboxes that run as the same host UID. The runtime MUST prevent
alternate filesystem access, cross-process FD theft, and access to container
or runtime management sockets. The namespace adapter needs these process and
filesystem restrictions in addition to its network namespace; the network
capability it holds inside that namespace is not a reason to grant it wider
host privileges.

`SO_PEERCRED` reports the credentials recorded when the connection or socket
pair was created; passing the FD to another process does not update them. On
a dedicated listener it can support audit or an additional access check. A
deployment that selects identity from UIDs, PIDs, namespace handles, or vsock
CIDs MUST map them through trusted controller state, handle reuse, and not
treat them as globally unique tenant identities. vsock CID 1 is the local
CID; it does not attest to a VM.

Passing a connected FD is an optional alternative to a pathname socket.
`SCM_RIGHTS` duplicates access to an open file description; the socket stays
in the namespace where it was created, and holding the descriptor establishes
nothing about the holder's identity. A deployment that uses a registration
service MUST authenticate and authorize its control peer, bind each endpoint
to a sandbox lifetime and policy, validate descriptor count, type, and state,
reject truncated ancillary data, close unexpected descriptors, and prevent
unintended inheritance. `SO_PASSCRED` with `SCM_CREDENTIALS` can authenticate
local registration messages under Linux credential rules. The baseline CONNECT
data channel requires neither mechanism.

## 3. Listener-Bound Identity (`boundary-core`)

In this binding the listener that accepted the connection selects the policy,
and no request field can change that selection. It is the baseline; every
other binding in this document has to provide an equivalent.

## 4. Certificate-Bound Identity (`boundary-tls`)

### 4.1 Authentication and Transport Integrity

The local model relies on kernel access controls, runtime confinement, and the
controller's fixed listener binding, so it needs no mTLS, signed CONNECT
requests, or registration protocol between adapter and boundary. When the
transport between them is untrusted, the adapter and boundary MUST authenticate
each other and protect the confidentiality and integrity of the traffic; TLS
is the reference mechanism. This protection covers the outer channel only. It
does not authenticate the upstream application and does not inspect TLS
traffic inside the tunnel.

In a TLS deployment:

1. Each side verifies the peer's certificate chain against configured trust anchors, validity periods, permitted algorithms, and the appropriate server or client extended key usage.
2. The expected boundary identity is verified against a SAN. A client certificate has to map to an authorized workload identity; a valid chain by itself grants neither policy nor tenant access, and ambiguous identity mappings MUST be rejected.
3. A missing client certificate where one is required, an unknown issuer, an expired or not-yet-valid certificate, or a mismatched endpoint identity is rejected. Authentication failure MUST NOT fall back to plaintext or anonymous access.
4. TLS 1.2 or later is required and TLS 1.3 preferred. HTTP/2 over TLS MUST negotiate `h2` through ALPN. Verification stays enabled in production.
5. The deployment defines certificate rotation, compromise response, and revocation. An established TLS session does not end when its certificate expires. Session resumption MUST NOT bypass current identity, generation, or policy checks, and tunnel authorization is not accepted in replayable TLS early data.

TLS proves possession of a key and protects records against modification; it
does not show that the authenticated workload is uncompromised. Guest root can
extract or use a key stored inside an untrusted guest, so a certificate or
signature supplied by that guest says nothing about how its CONNECT requests
were constructed.

On an authenticated, protected channel no separate CONNECT signature is
needed. A deployment that delegates through intermediaries with signed
requests has to bind the signature to the issuer, subject, audience,
destination, port, transport, direction, generation, expiry, and replay
context. The boundary still validates the request and applies local policy,
because a signature over untrusted claims does not make their content safe.

### 4.2 Identity Mapping

A `boundary-tls` listener terminates TLS 1.2 or later with a server
certificate issued by the deployment. When it requires client certificates it
MUST verify the chain against configured anchors and the `clientAuth`
extended key usage, derive the identity from the first URI SAN, else the
first DNS SAN, else the Common Name, and look that identity up in
controller-provided state that maps identities to policies. A missing or
unmapped identity MUST be rejected with a TLS alert or a 403
`identity-unknown` before any request is authorized. Every stream and request
on the session carries the identity, and session resumption MUST re-evaluate
the mapping. If the listener has a policy of its own, it applies only to
connections whose identity maps to it.

HTTP/2 CONNECT over mTLS with a SPIFFE URI SAN, as in HBONE, is one
conforming instance of this binding.

## 5. Shared Process, Dedicated Listeners (`boundary-multi`)

A boundary process serving several listeners MUST keep, per listener: the
identity and generation, the policy descriptor, connection and stream
budgets, idle and head deadlines, and the audit `listener`/`sandbox` labels.
The controller configures budgets per listener, outside the policy
descriptor. Exhaustion of one listener's budget MUST NOT cause another
listener to refuse requests. Closing one listener MUST terminate its accepted
connections and pending dials and MUST NOT affect other listeners. Policy
replacement for one listener MUST be atomic with respect to requests on that
listener and MUST be recorded with the new `policy` value. A compromise of
the process reaches every listener it serves; deployments that need to
isolate mutually untrusted workloads from a boundary compromise MUST NOT rely
on this binding alone.

## 6. VM Channels (`controller-vm`)

| Channel | Identity source | Requirements |
| --- | --- | --- |
| Firecracker-style Unix-backed vsock | Host Unix socket `<prefix>_<port>` bound by the controller for one VM | Listener-bound identity; ports not bound are unreachable; no relay process |
| Host `AF_VSOCK` | Guest CID observed on accept | Controller maps CID to sandbox generation; one listener per (CID, port) or a listener that dispatches on CID from controller state only; CID reuse invalidates the mapping before a new VM starts |
| Hyper-V sockets (`AF_HYPERV`) | VM ID (GUID) observed on accept | Same rules as `AF_VSOCK` with the VM ID as the identifier |
| Userspace packet backend (QEMU stream, similar) | The adapter is outside the guest; its boundary socket is listener-bound | Adapter confinement per Section 2; one packet channel per VM lifetime |

An identifier observed on accept tells the boundary which channel a
connection arrived on. It does not attest to the software running behind that
channel. The controller MUST record the mapping before the VM starts, revoke
it before the identifier can be reused, and expose to each VM only the ports
bound for it.
