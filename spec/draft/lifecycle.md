# Lifecycle, Revocation, and Limits

**Part of:** [agents.net specification, version 1 (draft)](index.md)  
**Status:** Draft

This document defines the controller's lifecycle obligations, how revocation
and policy replacement behave, what a snapshot and restore must preserve, and
the resource limits a boundary enforces. Controller conformance profiles are
summarized in [isolation.md Section 6](isolation.md#6-controller-conformance).

## 1. Lifecycle and Control Plane

The controller MUST establish confinement, endpoint access, identity, and policy
before enabling external flows. The baseline uses a dedicated endpoint with a
fixed policy. A process serving several dedicated listeners MUST preserve their
bindings; only a listener shared across identities needs additional identity
dispatch. No model can rely on tenant-supplied headers. Socket directories
MUST prevent one workload from replacing another workload's endpoints or
modifying boundary credentials, configuration, or audit files.

Policy updates MUST be versioned and auditable. Every decision SHOULD record
the controller-bound identity, requested destination, chosen upstream address,
port, transport, policy version, and result without logging secrets. Teardown
MUST revoke new access, dispose of flow resources according to the documented
revocation policy, and prevent stale routes or recycled identifiers from
granting access to a later workload.

## 2. Ingress, Revocation, and Updates

Optional ingress and egress MUST have separate authorization. An ingress gateway
authenticates the caller and maps an authorized service to one sandbox
generation and local address/port. Guest variables or caller-selected ports do
not grant that access. A reverse-channel deployment uses a separate connection
with gateway/client and adapter/server roles; an HTTP/2 server cannot initiate
arbitrary reverse CONNECT requests on an existing client session.

The baseline lifecycle uses ordinary runtime supervision:

1. Create the isolated sandbox and adapter environment without starting the untrusted workload. Assign a fresh socket path for this sandbox lifetime.
2. Start its boundary with fixed policy and resource limits. Install socket permissions and mount exposure, then initialize the adapter. Enable the workload only after confinement and boundary readiness checks succeed.
3. For revocation, stop admission and terminate the sandbox's boundary process, including its pending dials and upstream sockets. Stop the workload and adapter, remove the socket exposure, and destroy their isolated resources. A shared boundary process must provide equivalent per-listener session cancellation.
4. Use stop/restart for policy changes in the baseline. Terminate the old sessions before exposing the replacement endpoint; never reassign a live listener to another sandbox. A fresh path does not by itself revoke old connections.

No hot handoff, registration service, or draining protocol is required. A policy
change may interrupt active connections. The controller MUST bound shutdown
and must not report revocation complete until the owning process or all tracked
flows have terminated. Already delivered data cannot be recalled.

Missing policy or identity is a denial, not an allow-all default. Adapter
failure MUST NOT enable unmediated external traffic. A surviving guest may
still send authorized CONNECT requests directly if it has socket access.
Namespace rules and routes remain necessary; they are not a substitute for
excluding external network attachments.

Revocation MUST disable new streams and specify how existing ones end. Closing
one duplicated FD, unlinking a Unix pathname, removing a credential file, or
expiring a certificate does not necessarily close existing sessions. Boundaries
must retain enough session state to enforce revocation. Reconnects require
current identity and policy; retired generations must not be reused.

Deployments requiring non-disruptive updates need an additional handoff and
bounded-draining mechanism. Removing redirect rules while an active workload
can reach another network is not a valid update procedure. An adapter
that cannot hand off its state requires a fresh environment on restart.

## 3. Snapshot and Restore (`controller-snapshot`)

The adapter's synthetic name state belongs to the sandbox generation. On
restore, the controller MUST do one of: (a) restore the adapter's state
together with the guest; (b) start a fresh adapter whose address allocations
cannot equal any address the previous generation could have issued, for
example by deriving a disjoint sub-pool from the generation; or (c) refuse
the restore. The restored generation MUST be bound to its policy and recorded
as a new `generation` in audit records before the guest runs. Restart,
snapshot, or restore MUST NOT attach a fresh synthetic DNS state to a guest
retaining old mappings.

## 4. Availability and Audit

Boundaries MUST limit handshakes, header bytes, HTTP/2 streams, capsule lengths,
DNS/cache entries, buffered bytes, active sockets, retries, and idle lifetimes.
Limits need per-workload and aggregate enforcement. Unsupported capsule types
and contexts must be handled according to the protocol without unbounded
allocation. UDP proxies must restrict replies to the authorized peer and avoid
becoming reflection or amplification services.

Workload traffic MUST NOT starve supervision, revocation, or health handling.
Audit records are defined in [audit.md](audit.md). Audit access and retention
require protection; names and addresses may themselves be sensitive. Audit
failure behavior must be explicit and must never turn a denied request into an
allowed one.
