<!-- Informative. Not part of the specification. -->
# Stakeholder Review, Second Round (September 2026): Simulated Personas and Disposition

**Status:** Informative record  
**Date:** September 18, 2026  
**Reviewed revision:** branch `standard-v1` after the restructure, the descriptor-only boundary, the `Proxy-Status` wire, and the HTTP CONNECT ingress  
**Previous round:** [review-2026-09.md](review-2026-09.md)

## 1. Method

The same nine personas as the first round were run again as independent,
read-only agent sessions, each given its earlier positions and their
dispositions and asked to evaluate the current specification, reference, and
conformance suite. No employee of any named organization participated. Every
claim about the reference implementation was rechecked against the source
before it was acted on; claims that did not survive are in Section 4.

## 2. Verdicts

| Persona | Verdict | Stated reason |
| --- | --- | --- |
| P1 Codex CLI / Agents SDK | Adopt with changes | Suffix rules cannot express single-label wildcards; SOCKS5 stays off the wire (accepted) |
| P2 Claude Code / MCP | Adopt | Explicit adapter and HTTP CONNECT ingress make macOS viable; checklist wording was Linux-specific |
| P3 Gemini / gVisor / Kubernetes | Ready | `boundary-multi` and `boundary-tls` give per-pod bindings without a CRD standard |
| P4 Copilot / Hyper-V / SIEM | Not yet for enterprise claims | Hyper-V untested; audit lacks a correlation id |
| P5 Bedrock / Firecracker | Qualified yes | Snapshot partition scheme unspecified; `boundary-multi` unimplemented |
| P6 Envoy, kgateway, Cloudflare | Achievable with an ext_authz-style policy service | Exact reason tokens for malformed requests are too strict for existing proxies |
| P7 Sandbox providers | Policy and wire portability solved | Controller states need measurable definitions; adapter cases need a probe contract |
| P8 Agent frameworks | Spec sound; developer friction | No descriptor generator; single ingress port; denial reasons opaque to the developer |
| P9 IETF + red team | Not yet chartable; reference solid | Missing Security and IANA Considerations; `resolved_addresses` accepted `0.0.0.0/0` |

## 3. Disposition

| # | Request | From | Disposition | Where |
| --- | --- | --- | --- | --- |
| 1 | Reject `resolved_addresses` entries outside the special-purpose table (a `/0` exception defeated the table) | P9 | Accepted; loader and spec | [policy.md §2](../spec/draft/policy.md#2-semantics), `specialPurpose()` in policy.go |
| 2 | Single-label wildcard semantics | P1, P4 | Accepted as optional `depth` on suffix rules | [wire.md §6](../spec/draft/wire.md#6-name-normalization-and-matching), schema, B-CORE-61/62 |
| 3 | Generic malformed-request token so existing proxies can conform without re-parsing | P6 | Accepted: `malformed-request`, permitted for any 4xx other than 403; fixtures accept the specific token or the generic one and the status class | [registries.md §2](../spec/draft/registries.md#2-reason-tokens), [wire.md §4](../spec/draft/wire.md#4-failure-signaling) |
| 4 | Security Considerations and IANA Considerations for the wire document | P9 | Accepted | [wire.md §10, §11](../spec/draft/wire.md#10-security-considerations) |
| 5 | Spec text for IDNA must match the code (STD3 rules relaxed for `_`) | P9 | Accepted | [wire.md §6](../spec/draft/wire.md#6-name-normalization-and-matching) |
| 6 | Connection correlation id in audit records | P4 | Accepted as optional `connection`; the reference emits it | [audit.md](../spec/draft/audit.md), schema |
| 7 | IPv6 loopback and several pinned ports for ingress | P2, P8 | Accepted; launcher accepts `[::1]` and a comma-separated `-ingress-port` | [ingress.md §2](../spec/draft/ingress.md#2-wire) |
| 8 | Platform-neutral runtime audit checklist | P2 | Accepted; items name the control with Linux and macOS evidence | [conformance/README.md §6](../conformance/README.md#6-runtime-audit-checklist) |
| 9 | Measurable Ready and Revoked states | P7 | Accepted | [isolation.md §6.1](../spec/draft/isolation.md#6-controller-conformance) |
| 10 | Snapshot partition scheme declared by the adapter, with an example | P5, P3 | Accepted | [lifecycle.md §3](../spec/draft/lifecycle.md#3-snapshot-and-restore-controller-snapshot), [adapters.md §2](../spec/draft/adapters.md#2-packet-adapter-adapter-packet) |
| 11 | Per-listener budgets are controller-configured in `boundary-multi` | P5 | Accepted as clarification | [identity.md §5](../spec/draft/identity.md#5-shared-process-dedicated-listeners-boundary-multi) |
| 12 | Adapter probe contract (inputs, exit codes, JSON lines) | P7 | Accepted | [conformance/README.md §3.2](../conformance/README.md#32-adapter-role) |
| 13 | Implementation statement: denial latency bound, ready timeout, negative DNS response code, listeners per process | P7 | Accepted | [registries.md §4](../spec/draft/registries.md#4-implementation-statement) |
| 14 | Compatibility promise for the draft descriptor and audit schemas | P7 | Accepted: additive-only while the draft carries version 1 | [spec/README.md](../spec/README.md) |
| 15 | Technology-neutral wording for packet adapters (netstack without a device) | P3 | Accepted | [adapters.md §2](../spec/draft/adapters.md#2-packet-adapter-adapter-packet) |
| 16 | HTTP/3 note: QUIC needs UDP | P8 | Accepted | [adapters.md §2](../spec/draft/adapters.md#2-packet-adapter-adapter-packet) |
| 17 | Optional `suggested_rule` in diagnostics | P8 | Accepted as MAY, derived from the request, not the policy | [adapters.md §5](../spec/draft/adapters.md#5-diagnostics-adapter-diagnostics) |
| 18 | `AGENT_PUBLIC_URL` semantics for OAuth callbacks | P2 | Accepted as one sentence | [ingress.md §1](../spec/draft/ingress.md#1-arrangement) |
| 19 | RFC 9209 grammar checks in the harness | P6 | Accepted | `proxy_status_violations` in run_boundary.py |
| 20 | Suffix matching optional in `boundary-core` | P1, P6 | Rejected: the descriptor is the portable unit; a boundary that cannot evaluate a customer's rules cannot claim the profile. Suffix matching is a string comparison | — |
| 21 | Audit `decision` collapsed to allow/deny | P6 | Rejected: `block` versus `fail` is what distinguishes policy from infrastructure in incident review and costs nothing to emit | — |
| 22 | Policy-decision (ext_authz-style) service contract | P6 | Deferred to open work; a second implementation will define it | [roadmap.md §5](roadmap.md#5-open-work) |
| 23 | Descriptor generator from manifests | P8 | Deferred to open work | roadmap.md §5 |
| 24 | TLS-terminating gateway profile | P1 | Deferred to open work | roadmap.md §5 |
| 25 | Kubernetes integration guide; `boundary-multi` reference | P3, P5 | Deferred to open work | roadmap.md §5 |
| 26 | Byte counts and durations in audit | P4 | Not adopted for version 1: they are known only at tunnel close and would require a second record kind; a follow-on `tunnel-closed` record is a candidate | — |
| 27 | Deny rules inside a suffix, time-bounded rules | P4 | Not adopted for version 1: allow-only keeps evaluation order-independent; carve-outs are expressed as separate policies or narrower suffixes with `depth` | — |
| 28 | 1xx responses with a body must be rejected | P9 | Not adopted: the boundary is trusted; the client parser reads the interim head only and any trailing bytes fail the next parse rather than entering the tunnel | — |
| 29 | Explicit obs-fold rejection in the ingress parser | P9 | Already the behavior: a folded line has no field name and is refused `malformed-header`; a test case was added | dialer_test.go |

## 4. Claims Not Carried Forward

- "`100.64.0.0/10` is missing from the special-purpose table" (P5). It is
  present in [wire.md §5.1](../spec/draft/wire.md#51-special-purpose-addresses)
  and in the reference's `nonPublic` list.
- "The launcher accepts only `127.0.0.1`; IPv6 agents are excluded" (P2).
  True at the time of review; resolved by item 7.
- "Envoy passes only about 7% of `boundary-core` by configuration" (P6).
  A plausible estimate, not a measurement; recorded as motivation for open
  work item 7 in the roadmap.

## 5. Result

After the changes above the reference passes all 60 automated
`boundary-core` cases (two new depth cases), all Go tests, the demo
presubmit, and the Firecracker and QEMU scenarios; fixtures validate against
the updated schemas.
