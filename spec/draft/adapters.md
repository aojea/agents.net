# Adapter Profiles

**Part of:** [agents.net specification, version 1 (draft)](index.md)  
**Status:** Draft

An adapter turns a workload's connections into requests on the egress wire
([wire.md](wire.md)). It has no authority: the boundary decides. Two adapter
kinds are defined, plus optional UDP and diagnostics extensions. Reference
adapters and their mechanics are described in the
[reference implementation](../../sdk/README.md).

## 1. Requirements on Applications

Applications MUST NOT be required to cooperate with network confinement:

- Clients that ignore `HTTP_PROXY`, including clients configured with `trust_env=False`, remain subject to policy.
- Clearing or replacing environment variables does not grant network access.
- Supported TCP connections use the same tunnel mechanism for HTTP, database protocols, SSH, and other byte-stream protocols.

For a packet adapter this holds by construction. For an explicit adapter the
first two properties are provided by the runtime: connections that bypass the
adapter fail, they do not escape.

## 2. Packet Adapter (`adapter-packet`)

Covers TUN in the guest, namespace redirect, and VMM packet backends.

The adapter MUST deliver every TCP connection the workload initiates to a
destination outside the sandbox as a CONNECT request with the workload's
hostname when known and the literal address otherwise. It MUST answer DNS on
UDP port 53 locally when it uses synthetic addresses and MUST NOT forward UDP
unless UDP is enabled. Protocols it does not carry MUST fail without an
alternative path. A denied CONNECT MUST be exposed to the workload as a
connection failure within a documented bound; refusal before completing the
workload's TCP handshake is RECOMMENDED where the adapter controls the
handshake. The adapter MUST publish a compatibility statement listing:
transports carried, DNS record types answered, synthetic address ranges, name
capacity and address reuse policy, MTU, and the observable form of a denial
(refused, reset, or timeout) for TCP and UDP.

A synthetic resolver invents addresses for names so that the name, not an
address, reaches the boundary. Its ranges MUST NOT overlap destinations the
workload needs to reach as literals, and an address MUST NOT be reused for a
different name within one adapter generation. A literal destination inside a
synthetic range whose name is no longer known is forwarded as a literal; the
boundary denies it because synthetic ranges are special-purpose.

## 3. Explicit Adapter (`adapter-explicit`)

For hosts without packet interception, and as a companion endpoint next to a
packet adapter.

The adapter exposes an HTTP/1.1 CONNECT endpoint on a loopback address or
Unix socket inside the sandbox and relays each accepted request to the
boundary channel unchanged except for hop-by-hop fields. It MUST NOT
authorize or rewrite destinations. It MUST return the boundary's status and
`Proxy-Status` field to the client. It MUST set `HTTP_PROXY`, `HTTPS_PROXY`,
and `ALL_PROXY` (and their lowercase forms) in the workload environment to its
endpoint and MAY set tool-specific variables. It MAY expose a SOCKS5 endpoint
that it translates to CONNECT with the same rules. The runtime MUST ensure
that connections not made through the endpoint fail; a connection that
succeeds without the endpoint is a conformance failure of the sandbox, not of
the adapter.

## 4. UDP (`adapter-udp`)

When UDP is enabled, the adapter carries datagrams through connect-udp
([wire.md Section 8](wire.md#8-udp)) with the destination the workload
addressed. Denied UDP sessions are dropped; the observable form of the
failure is part of the compatibility statement.

## 5. Diagnostics (`adapter-diagnostics`)

When present, the environment variable `AGENTS_NET_DIAGNOSTICS` holds an
`http://127.0.0.1:<port>/` or `unix:<path>` endpoint. `GET /denials` returns a
JSON array of at most the last N (documented) denials for this sandbox, each
with `ts`, `destination`, `transport`, `reason`, and `policy`. The endpoint is
read-only, contains no data about other sandboxes, and MUST NOT expose policy
contents beyond `policy`.
