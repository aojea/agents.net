<!-- Informative. Not part of the specification. -->
# Roadmap: From Draft to Standard

**Informative.** The normative text is [spec/draft](../spec/draft/index.md);
this document records the goals, the standardization path, design decisions
that shaped version 1, and open work.

## 1. Goals

1. One wire. Every adapter interoperates with every boundary without
   coordination beyond the policy the controller installs.
2. Roles are separately conformant. An adapter, a boundary, a controller, and
   an ingress gateway can be built by different parties and combined.
3. Every normative statement has a black-box observation or an explicit
   entry in the [runtime audit checklist](../conformance/README.md#6-runtime-audit-checklist).
4. Existing proxies conform by configuration or by a small, well-defined
   extension, not by adopting a new protocol.
5. Portable configuration. A policy written for one conformant deployment is
   accepted by another with identical decisions.

## 2. Document Set

| Document | Standardization target |
| --- | --- |
| [wire.md](../spec/draft/wire.md) with [policy.md](../spec/draft/policy.md), [audit.md](../spec/draft/audit.md), [registries.md](../spec/draft/registries.md) | Internet-Draft, *HTTP CONNECT Egress Profile for Confined Workloads*, in the HTTP working group with MASQUE review of the connect-udp parts. Contains no adapter mechanics, socket ownership, capabilities, or product references. |
| [identity.md](../spec/draft/identity.md), [isolation.md](../spec/draft/isolation.md), [lifecycle.md](../spec/draft/lifecycle.md), [adapters.md](../spec/draft/adapters.md), [ingress.md](../spec/draft/ingress.md), [gateway.md](../spec/draft/gateway.md) | Informational or BCP: what a controller and runtime must guarantee so that the wire profile's guarantee holds. |
| [conformance/](../conformance/README.md) | External conformance program, versioned independently; each suite version names the specification revision it tests. |

## 3. Standardization Path

1. Publish suite version 0.1 with the reference boundary's results and
   implementation statement.
2. Bring a second, independently developed boundary to `boundary-core` by
   configuration or a documented extension, and publish its statement. Two
   interoperable implementations are the usual bar for advancing a wire
   document.
3. Submit the wire profile as an Internet-Draft and request registration of
   the `reason` parameter for `Proxy-Status` (RFC 9209 Section 2.3).
4. Freeze `agents_net_policy` 1 and `agents_net_audit` 1 when two
   implementations pass the descriptor and audit fixtures; release
   `spec/v1/` per [spec/README.md](../spec/README.md).
5. Publish the isolation and controller documents as Informational, with the
   runtime audit checklist as an appendix.
6. Add a profile only with fixtures and at least one passing implementation.

## 4. Decisions Recorded for Version 1

| Decision | Choice |
| --- | --- |
| Failure signaling | RFC 9209 `Proxy-Status` with a `reason` parameter; no private header |
| Capability discovery | None in band; the implementation statement declares capabilities, unsupported requests fail with defined reasons, RFC 8441 SETTINGS is the only in-band signal |
| Policy model | Allow rules only, default deny, unordered; literal permissions also admit the same address as a resolution result; `resolved_addresses` never authorizes a literal and must lie within a special-purpose range |
| Name patterns | Exact, suffix (any depth by default, bounded with `depth`, never the suffix itself), and `*` |
| Audit decisions | `block` = the boundary refused (policy or malformed); `fail` = it could not serve (resolution, dial, budget, TLS) |
| Malformed requests | Specific reason tokens preferred; the generic `malformed-request` is permitted so that existing proxies can conform without re-parsing |
| Ingress wire | HTTP CONNECT to a pinned loopback port (IPv4 or IPv6 loopback, one or more ports); no textual handshake; the gateway records the audit |
| SOCKS5 | Only as a local endpoint of an explicit adapter, translated to CONNECT; never on the boundary wire |
| Live policy reload | Not in version 1; restart-based revocation is the baseline |
| Application gateways | Outside the wire profile; requirements stated when used |

## 5. Open Work

1. `boundary-multi` in the reference command, or a second implementation
   that has it; B-MULTI automation in the harness.
2. `adapter-explicit` reference: loopback CONNECT endpoint in the launcher
   with environment setup; a reference probe implementing the
   [adapter probe contract](../conformance/README.md#32-adapter-role).
3. A reload profile (`boundary-reload`) with atomic replacement and
   documented established-flow behavior, once a controller needs it.
4. `connect-ip` (RFC 9484) remains out of scope until a workload requires
   raw IP.
5. A Windows adapter and a Hyper-V channel test.
6. Harness support for HTTP/2, connect-udp, TLS, and the in-sandbox adapter
   and controller groups.
7. A second independent boundary implementation passing `boundary-core`;
   the natural candidate is an Envoy ext_authz service that evaluates the
   descriptor and emits `Proxy-Status` and audit records, which would also
   define a reusable policy-decision interface.
8. A descriptor generator that emits rules from package-manager
   configuration and service manifests, so that frameworks do not write
   descriptors by hand.
9. An informative application-gateway profile for TLS termination with
   host-held credentials, with its own fixtures.
10. A Kubernetes integration guide: per-pod socket exposure, CRD to
    descriptor translation, SPIFFE identity mapping for `boundary-tls`.
