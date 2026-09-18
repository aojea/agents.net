# Lifecycle, Revocation, and Limits

**Part of:** [agents.net specification, version 1 (draft)](index.md)  
**Status:** Draft

This document defines the controller's lifecycle obligations, how revocation
and policy replacement behave, what a snapshot and restore must preserve, and
the resource limits a boundary enforces. Controller conformance profiles are
summarized in [isolation.md Section 6](isolation.md#6-controller-conformance).

## 1. Lifecycle and Control Plane

The controller MUST establish confinement, endpoint access, identity, and policy
before it enables any external flow. The baseline uses a dedicated endpoint
with a fixed policy. A process that serves several dedicated listeners MUST
preserve their bindings; additional identity dispatch is needed only when one
listener is shared across identities. Tenant-supplied headers are not a basis
for identity in any model. Socket directories MUST prevent one workload from
replacing another workload's endpoints or modifying boundary credentials,
configuration, or audit files.

Policy updates MUST be versioned and auditable. Every decision SHOULD record
the controller-bound identity, the requested destination, the upstream address
chosen, the port, the transport, the policy version, and the result, without
logging secrets. Teardown MUST revoke new access, dispose of flow resources
according to the documented revocation policy, and prevent stale routes or
recycled identifiers from granting access to a later workload.

## 2. Ingress, Revocation, and Updates

Optional ingress and egress MUST have separate authorization. An ingress gateway
authenticates the caller and maps an authorized service to one sandbox
generation and one local address and port; neither guest variables nor a port
chosen by the caller grant that access. A reverse-channel deployment uses a
separate connection on which the gateway is the client and the adapter the
server, because an HTTP/2 server cannot initiate arbitrary reverse CONNECT
requests on an existing client session.

The baseline lifecycle uses ordinary runtime supervision:

1. The controller creates the isolated sandbox and adapter environment without starting the untrusted workload, and assigns a fresh socket path for this sandbox lifetime.
2. It starts the boundary with a fixed policy and resource limits, installs socket permissions and the mount exposure, and then initializes the adapter. The workload is enabled only after the confinement and boundary readiness checks succeed.
3. To revoke, it stops admission and terminates the sandbox's boundary process together with its pending dials and upstream sockets, then stops the workload and adapter, removes the socket exposure, and destroys their isolated resources. A shared boundary process has to provide equivalent per-listener session cancellation.
4. A policy change in the baseline is a stop followed by a restart. The old sessions are terminated before the replacement endpoint is exposed, and a live listener is never reassigned to another sandbox. A fresh path does not by itself revoke old connections.

No hot handoff, registration service, or draining protocol is needed, and a
policy change can interrupt active connections. The controller MUST bound
shutdown and does not report revocation complete until the owning process, or
every tracked flow, has terminated. Data already delivered cannot be recalled.

A missing policy or identity results in denial. Adapter failure MUST NOT
enable unmediated external traffic. A guest that outlives its adapter can
still send authorized CONNECT requests directly if it has access to the
socket. Namespace rules and routes remain necessary, and they do not replace
the exclusion of external network attachments.

Revocation MUST disable new streams and specify how existing ones end. Closing
one duplicate of an FD, unlinking a Unix pathname, removing a credential file,
or letting a certificate expire does not by itself close existing sessions, so
a boundary has to keep enough session state to enforce revocation. A
reconnect is admitted only with current identity and policy, and a retired
generation is not reused.

A deployment that needs non-disruptive updates has to add a handoff and
bounded-draining mechanism. Removing redirect rules while an active workload
can reach another network is not a valid update procedure. An adapter that
cannot hand off its state needs a fresh environment on restart.

## 3. Snapshot and Restore (`controller-snapshot`)

The adapter's synthetic name state belongs to the sandbox generation. On
restore the controller MUST do one of three things: (a) restore the adapter's
state together with the guest; (b) start a fresh adapter whose address
allocations cannot equal any address the previous generation could have
issued; or (c) refuse the restore. The adapter's compatibility statement MUST
declare which of these it supports and, for (b), the partition scheme. One
such scheme has the controller pass a generation index `g` and the adapter
allocate only from the `g`-th equal slice of its pool, so that two
generations of one sandbox never share an address. The restored generation
MUST be bound to its policy and recorded as a new `generation` in audit
records before the guest runs. Restart, snapshot, or restore MUST NOT attach
fresh synthetic DNS state to a guest that retains old mappings.

## 4. Availability and Audit

Boundaries MUST limit handshakes, header bytes, HTTP/2 streams, capsule lengths,
DNS and cache entries, buffered bytes, active sockets, retries, and idle
lifetimes, both per workload and in aggregate. Unsupported capsule types and
contexts are handled as the protocol specifies, without unbounded allocation.
A UDP proxy restricts replies to the authorized peer so that it cannot be used
for reflection or amplification.

Workload traffic MUST NOT starve supervision, revocation, or health handling.
Audit records are defined in [audit.md](audit.md). Access to audit data and
its retention need protection, since the names and addresses it contains can
themselves be sensitive. The behavior on audit failure is stated explicitly,
and it never turns a denied request into an allowed one.
