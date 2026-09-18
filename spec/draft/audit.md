# Audit Record

**Part of:** [agents.net specification, version 1 (draft)](index.md)  
**Status:** Draft  
**Schema:** [schema/audit.schema.json](schema/audit.schema.json)

A boundary writes one JSON object per line for every decision. The record is
the portable evidence that a request was decided under a given identity and
policy; the conformance suite reads it to verify implementations.

## 1. Fields

| Field | Type | Required | Content |
| --- | --- | --- | --- |
| `agents_net_audit` | integer | no | Schema version `1` when present |
| `ts` | string | yes | RFC 3339 timestamp, UTC |
| `listener` | string | no | Boundary-local listener identifier |
| `sandbox` | string | yes | Controller-assigned identity of the listener |
| `generation` | string | no | Sandbox generation when the controller distinguishes restarts |
| `policy` | string | yes | Descriptor `version` |
| `wire` | string | yes | `h1` or `h2` |
| `transport` | string | when parsed | `tcp` or `udp` |
| `direction` | string | no | `egress` (default) or `ingress` |
| `destination` | string | when parsed | Requested authority after normalization, `host:port` or `[v6]:port` |
| `address` | string | no | Dialed `ip:port`; present only when a connection was established |
| `peer` | string | no | Channel-authenticated identity (certificate SAN) or kernel credentials |
| `connection` | string | no | Boundary-local identifier of the accepted connection or HTTP/2 session, so that requests on one session can be correlated |
| `rule` | string | no | `id` of the rule that allowed the request |
| `decision` | string | yes | `allow`; `block` when the boundary refused the request (policy or malformed); `fail` when it could not serve it (resolution, dial, budget, TLS) |
| `reason` | string | when not `allow` | Reason token ([registries.md](registries.md#2-reason-tokens)) |
| `meta` | object | no | Untrusted telemetry strings copied from request fields the policy names; never used for decisions |

## 2. Requirements

Every value derived from the request MUST be a JSON string. The record MUST
NOT contain credentials, tunnel payload, or policy contents other than
`version` and `rule`. Audit failure MUST NOT change a decision. A record MUST
be written for every request that reaches parsing, including malformed
requests and requests refused for their method, for every connection refused
for budget, and for every TLS handshake failure on a `boundary-tls` listener.
`transport` and `destination` are present whenever the request head was
parsed far enough to know them. Untrusted values are structurally encoded so
that a request cannot add fields or lines.

```json
{"ts":"2026-09-17T10:00:01.234567Z","listener":"unix:///run/agents.net/a/boundary.sock","sandbox":"sandbox-a","policy":"2026-09-17T10:00:00Z/3","wire":"h1","transport":"tcp","destination":"registry.npmjs.org:443","address":"203.0.113.42:443","rule":"npm","decision":"allow"}
{"ts":"2026-09-17T10:00:02.000001Z","listener":"unix:///run/agents.net/a/boundary.sock","sandbox":"sandbox-a","policy":"2026-09-17T10:00:00Z/3","wire":"h1","transport":"tcp","destination":"evil.example:443","decision":"block","reason":"not-on-allowlist"}
```
