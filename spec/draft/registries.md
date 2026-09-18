# Profiles, Registries, and Implementation Statement

**Part of:** [agents.net specification, version 1 (draft)](index.md)  
**Status:** Draft

## 1. Roles and Profiles

A conformance claim names a role and one or more profiles. Profiles marked
"core" are prerequisites for the others in the same role. Each profile is
verified by a group of the [conformance suite](../../conformance/README.md).

| Role | Profile | Summary | Defined in |
| --- | --- | --- | --- |
| Boundary | `boundary-core` | HTTP/1.1 CONNECT; names and literals; deny by default; checked-address dialing; failure signaling; audit record | [wire.md](wire.md), [policy.md](policy.md), [audit.md](audit.md) |
| Boundary | `boundary-h2` | HTTP/2 CONNECT with prior knowledge or ALPN; per-session identity; stream budgets | [wire.md §7](wire.md#7-http2) |
| Boundary | `boundary-udp` | connect-udp over HTTP/1.1 upgrade and, with `boundary-h2`, extended CONNECT; capsule bounds | [wire.md §8](wire.md#8-udp) |
| Boundary | `boundary-tls` | TLS on the channel; optional required client certificates; certificate-derived identity mapped to policy | [identity.md §4](identity.md#4-certificate-bound-identity-boundary-tls) |
| Boundary | `boundary-multi` | One process, several dedicated listeners with separate identity, policy, budgets, audit, and revocation | [identity.md §5](identity.md#5-shared-process-dedicated-listeners-boundary-multi) |
| Adapter | `adapter-packet` | Carries every supported TCP (and optionally UDP) connection of an uncooperative workload: TUN, namespace redirect, or VMM packet backend | [adapters.md §2](adapters.md#2-packet-adapter-adapter-packet) |
| Adapter | `adapter-explicit` | Exposes a local CONNECT endpoint for proxy-aware clients; direct connections fail | [adapters.md §3](adapters.md#3-explicit-adapter-adapter-explicit) |
| Adapter | `adapter-udp` | UDP through connect-udp for either adapter type | [adapters.md §4](adapters.md#4-udp-adapter-udp) |
| Adapter | `adapter-diagnostics` | Read-only endpoint listing this sandbox's recent denials | [adapters.md §5](adapters.md#5-diagnostics-adapter-diagnostics) |
| Controller | `controller-local` | Dedicated pathname Unix socket per sandbox lifetime; readiness, revocation, two-sandbox separation | [isolation.md §6](isolation.md#6-controller-conformance) |
| Controller | `controller-vm` | VM channel mapping (Firecracker Unix-backed vsock, host `AF_VSOCK`, Hyper-V sockets) with per-VM listeners | [identity.md §6](identity.md#6-vm-channels-controller-vm) |
| Controller | `controller-snapshot` | Generation binding for adapter state across snapshot and restore | [lifecycle.md §3](lifecycle.md#3-snapshot-and-restore-controller-snapshot) |
| Ingress | `ingress-gateway` | Authenticated caller, route bound to one sandbox generation, HTTP CONNECT to the pinned loopback port | [ingress.md](ingress.md) |

A profile is added to this table only together with conformance fixtures and
at least one passing implementation.

## 2. Reason Tokens

Reason tokens are the `reason` parameter of `Proxy-Status`
([wire.md Section 4](wire.md#4-failure-signaling)) and the `reason` field of
the audit record. Syntax: `[a-z0-9-]{1,32}`. New tokens are registered by a
specification change to this table.

| Token | Status | RFC 9209 `error` | Meaning |
| --- | --- | --- | --- |
| `malformed-request-line` | 400 | `http_request_error` | Request line is not three single-space-separated fields with a token method and HTTP/1.x version |
| `malformed-header` | 400 | `http_request_error` | Invalid field name, obs-fold, or control characters |
| `duplicate-host` | 400 | `http_request_error` | More than one `Host` field |
| `missing-host` | 400 | `http_request_error` | HTTP/1.1 request without `Host` |
| `malformed-target` | 400 | `http_request_error` | Authority has userinfo, path, query, scheme, no port, unbracketed IPv6, or invalid characters |
| `malformed-port` | 400 | `http_request_error` | Port is not a decimal integer in 1-65535 |
| `authority-mismatch` | 400 | `http_request_error` | `Host` names a different destination than the request-target |
| `malformed-upgrade` | 400 | `http_request_error` | `Upgrade: connect-udp` without `Connection: Upgrade` or with conflicting tokens |
| `malformed-template` | 400 | `http_request_error` | connect-udp path does not match the configured URI template or decodes to an invalid host or port |
| `malformed-request` | 4xx except 403 | `http_request_error` | Generic refusal of a malformed request by a boundary that does not distinguish the defect; the specific tokens above are preferred |
| `unsupported-protocol` | 400 or 501 | `http_request_error` | Extended CONNECT `:protocol` value not supported |
| `head-too-large` | 431 | `http_request_error` | Request head exceeds the documented limit |
| `connect-only` | 405 | `http_request_error` | Method other than CONNECT and other than a connect-udp upgrade |
| `unsupported-version` | 505 | `http_protocol_error` | HTTP version other than 1.0 or 1.1 on a cleartext HTTP/1 listener |
| `not-on-allowlist` | 403 | `http_request_denied` | Hostname matches no rule |
| `port-not-allowed` | 403 | `http_request_denied` | Destination matches a rule; the port does not |
| `transport-not-allowed` | 403 | `http_request_denied` | Destination and port match a rule; the transport does not |
| `ip-not-on-allowlist` | 403 | `destination_ip_prohibited` | Literal address matches no rule |
| `resolved-address-denied` | 403 | `destination_ip_prohibited` | Every resolved address is special-purpose or unlisted |
| `scoped-ip` | 403 | `destination_ip_prohibited` | IPv6 literal with a zone identifier |
| `udp-disabled` | 403 | `http_request_denied` | UDP tunneling not enabled on this listener |
| `identity-unknown` | 403 | `http_request_denied` | Authenticated channel identity has no policy mapping (`boundary-tls`) |
| `policy-unavailable` | 503 | `proxy_configuration_error` | Listener has no loaded policy |
| `busy` | 503 | `connection_limit_reached` | Connection or stream budget exhausted |
| `resolve-failed` | 502 | `dns_error` or `dns_timeout` | Resolution of an allowed name failed |
| `dial-failed` | 502 | `destination_unavailable`, `connection_refused`, or `connection_timeout` | No checked address accepted the connection |
| `port-not-permitted` | 403 | `http_request_denied` | Ingress: requested loopback port is not the pinned port |
| `tls-failed` | none | `tls_protocol_error` or `tls_certificate_error` | Audit-only: channel handshake failed before any HTTP exchange |

## 3. Registries

| Registry | Location | Policy |
| --- | --- | --- |
| agents.net reason tokens | Section 2 | Specification required |
| agents.net profile identifiers | Section 1 | Specification required; fixtures and one implementation |
| `reason` parameter for `Proxy-Status` | To be requested in the HTTP Proxy-Status Parameters registry (RFC 9209 Section 2.3) | Per RFC 9209 |
| Policy descriptor and audit record versions | `agents_net_policy`, `agents_net_audit` integer fields | Incremented on incompatible change |

## 4. Implementation Statement

Published with every conformance result:

| Field | Content |
| --- | --- |
| `implementation`, `version`, `commit` | Identification |
| `role`, `profiles` | Claimed profiles from Section 1 |
| `suite_version`, `spec_revision` | What was tested |
| `channels` | Listener types: `unix`, `tcp`, `tls`, `vsock-uds`, `vsock`, `hyperv` |
| `wire` | `h1`, `h2`; TLS versions; ALPN |
| `limits` | Head bytes, head deadline, connections, streams per session, idle timeout, capsule bytes, datagram bytes; for `boundary-multi`, the maximum listeners per process |
| `timing` | `ready_timeout_ms` (controller), `denial_latency_bound_ms` (adapter) |
| `resolver` | System resolver, static mapping, both; IDNA handling; for adapters, the response code returned for names and record types the synthetic resolver does not answer |
| `address_table_deviations` | MUST be empty for conformance |
| `adapter_compatibility` | [adapters.md Section 2](adapters.md#2-packet-adapter-adapter-packet) statement, for adapters |
| `extensions` | Additional reason tokens, template, SOCKS5 endpoint, diagnostics |
| `results` | Path and digest of the results file |
| `environment` | OS, kernel, VMM, and versions used during the run |

Capabilities are declared here, not negotiated in band: an unsupported
request fails with the defined status and reason, and `SETTINGS_ENABLE_CONNECT_PROTOCOL`
(RFC 8441) is the only in-band capability signal.
