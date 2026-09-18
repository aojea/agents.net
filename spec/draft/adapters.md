# Adapter Profiles

**Part of:** [agents.net specification, version 1 (draft)](index.md)  
**Status:** Draft

An adapter turns a workload's connections into requests on the egress wire
([wire.md](wire.md)). It holds no authority of its own; every request is
decided by the boundary. This document defines two adapter kinds and two
optional extensions, UDP and diagnostics. The reference adapters and how they
work are described in the [reference implementation](../../sdk/README.md).

## 1. Requirements on Applications

Applications MUST NOT be required to cooperate with network confinement:

- Clients that ignore `HTTP_PROXY`, including clients configured with `trust_env=False`, remain subject to policy.
- Clearing or replacing environment variables does not grant network access.
- Every supported TCP connection, whether it carries HTTP, a database protocol, SSH, or another byte-stream protocol, goes through the same tunnel.

A packet adapter has these properties by construction. With an explicit
adapter the first two come from the runtime, which makes a connection that
bypasses the adapter fail rather than escape.

## 2. Packet Adapter (`adapter-packet`)

This profile covers a TUN device in the guest, namespace redirection, VMM
packet backends, and any other placement that receives the workload's packets
or socket calls before they reach a network, including a userspace network
stack built into the runtime. It states requirements and does not prescribe a
device.

The adapter MUST deliver every TCP connection that the workload opens to a
destination outside the sandbox as a CONNECT request, naming the workload's
hostname when it is known and the literal address otherwise. When it uses
synthetic addresses it MUST answer DNS on UDP port 53 locally, and it MUST NOT
forward UDP unless UDP is enabled. Protocols the adapter does not carry MUST
fail without an alternative path. QUIC and HTTP/3 need UDP, so with UDP
disabled only clients that fall back to TCP succeed. A denied CONNECT MUST
appear to the workload as a connection failure within the bound the
compatibility statement declares; where the adapter controls the workload's
TCP handshake, refusing before that handshake completes is RECOMMENDED.

The adapter MUST publish a compatibility statement that lists the transports
carried, the DNS record types answered and the response code for names and
types it does not answer, the synthetic address ranges, the name capacity and
address reuse policy, the scheme that keeps synthetic allocations disjoint
across generations ([lifecycle.md Section 3](lifecycle.md#3-snapshot-and-restore-controller-snapshot)),
the MTU, the denial latency bound in milliseconds, and the observable form of
a denial (refused, reset, or timeout) for TCP and UDP.

A synthetic resolver hands out an address for each name it is asked about, so
that the CONNECT request reaching the boundary carries the name rather than an
address. Its ranges MUST NOT overlap destinations the workload needs to reach
as literals, and an address MUST NOT be reused for a different name within one
adapter generation. If the workload connects to an address inside a synthetic
range whose name the adapter no longer knows, the adapter forwards the literal
address and the boundary denies it, because synthetic ranges are
special-purpose.

## 3. Explicit Adapter (`adapter-explicit`)

This profile serves hosts without packet interception and also works as a
companion endpoint beside a packet adapter.

The adapter exposes an HTTP/1.1 CONNECT endpoint on a loopback address or a
Unix socket inside the sandbox and relays each request it accepts to the
boundary channel, changing nothing but hop-by-hop fields. It MUST NOT
authorize or rewrite destinations, and it MUST return the boundary's status
and `Proxy-Status` field to the client. It MUST set `HTTP_PROXY`,
`HTTPS_PROXY`, and `ALL_PROXY` (and their lowercase forms) in the workload
environment to its endpoint and MAY set tool-specific variables as well. It
MAY expose a SOCKS5 endpoint that it translates to CONNECT under the same
rules. The runtime MUST cause any connection that bypasses the endpoint to
fail; if such a connection succeeds, the conformance failure is the sandbox's
and not the adapter's.

## 4. UDP (`adapter-udp`)

When UDP is enabled the adapter carries datagrams through connect-udp
([wire.md Section 8](wire.md#8-udp)), addressed to the destination the
workload used. A denied UDP session is dropped, and the compatibility
statement describes what the workload observes when that happens.

## 5. Diagnostics (`adapter-diagnostics`)

When this extension is present, the environment variable
`AGENTS_NET_DIAGNOSTICS` holds an `http://127.0.0.1:<port>/` or `unix:<path>`
endpoint. `GET /denials` returns a JSON array holding at most the last N
denials for this sandbox, where N is documented by the adapter. Each entry
carries `ts`, `destination`, `transport`, `reason`, and `policy`, and MAY
include `suggested_rule`, a descriptor rule that would have matched the denied
request, derived from the request and not from the policy. The endpoint is
read-only, contains no data about other sandboxes, and MUST NOT expose policy
contents beyond `policy`.
