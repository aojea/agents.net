# Egress Wire: HTTP CONNECT Profile

**Part of:** [agents.net specification, version 1 (draft)](index.md)  
**Status:** Draft

This document defines the wire between an adapter and a boundary: request
forms, authority validation, success and failure responses, address policy,
and tunnel content rules. It is written to be publishable on its own as an
HTTP CONNECT profile; it does not depend on any adapter mechanism, channel
type, or isolation technology. Identity binding for the channel is defined in
[identity.md](identity.md); the policy descriptor in [policy.md](policy.md);
the audit record in [audit.md](audit.md); reason tokens and profiles in
[registries.md](registries.md).

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in BCP 14 (RFC 2119, RFC 8174).

## 1. Egress Boundary Interface

The Egress Boundary Interface defines how traffic leaves the sandbox:

1. **TCP:** Supported external TCP flows MUST use HTTP CONNECT (RFC 9110 Section 9.3.6) with the destination hostname or IP address and an explicit port. HTTP/1.1 is the baseline; HTTP/2 multiplexing is optional. Tunnels carry arbitrary TCP byte streams, not raw IP packets.
2. **Names and addresses:** Adapters MUST preserve a hostname when a mapping is available. Otherwise, they MUST forward the destination IP address without requiring a DNS lookup or inventing a hostname. Boundaries MUST support both forms and authorize them according to policy. IP literals MUST NOT be rejected solely because no hostname is available. IPv6 literals use brackets in the CONNECT authority.
3. **Optional UDP:** UDP tunneling MUST be explicitly enabled at the adapter and boundary. RFC 9298 uses an HTTP/1.1 `GET` upgrade or HTTP/2 extended CONNECT with `:protocol: connect-udp`, carrying RFC 9297 capsules on a reliable stream. Disabled or unsupported capabilities MUST NOT fall back to direct networking.
4. **Constrained channel:** The workload MUST reach the boundary through an access-controlled channel, such as a dedicated Unix socket or a restricted VSOCK service. The controller MUST exclude alternative external paths, other workloads' endpoints, and unauthorized host services. A TCP boundary listener is useful for component tests but alone is not sandbox confinement.
5. **External authorization:** Before dialing, the boundary MUST authorize the workload identity, destination, port, and transport under current policy. Hostnames require name policy and checks on each resolved address; literals require IP or CIDR policy. The boundary MUST deny unknown identities and unavailable policy, and dial only checked addresses, including retries, without an unchecked second DNS resolution. Internal services MAY be authorized explicitly; private, loopback, and metadata access must not arise implicitly from a name allowlist.
6. **Explicit refusal:** A denied CONNECT MUST return HTTP `403 Forbidden` with a `Proxy-Status` field (RFC 9209) whose single member carries an `error` parameter from the HTTP Proxy Error Types registry and a `reason` parameter holding a registered reason token (Section 4). Other failures use the same field with their own status class. The adapter MUST expose a connection failure without silently bypassing the boundary. TCP connect refusal, reset, and UDP error semantics differ; an HTTP status is not an application response inside the tunnel.
7. **Failure and limits:** Boundary unavailability MUST NOT create an alternate network path. Setup, failure detection, and idle resource retention MUST be bounded. Implementations MUST document deadlines, connection and buffer quotas, and whether policy revocation terminates established streams. Fail-closed is an isolation property, not a promise of instantaneous failure detection.

The adapter's supported resolver behavior is part of its compatibility
statement ([adapters.md](adapters.md)).

Examples of valid HTTP/1.1 tunnel requests:

```http
CONNECT api.example.com:443 HTTP/1.1
Host: api.example.com:443

CONNECT 203.0.113.10:443 HTTP/1.1
Host: 203.0.113.10:443

CONNECT [2001:db8::10]:443 HTTP/1.1
Host: [2001:db8::10]:443
```

Each request is independently authorized. An IP destination still uses the
boundary channel; it does not give the workload a direct external network path.

## 2. CONNECT Parsing and Authorization

The boundary MUST parse each request before opening an upstream socket or
forwarding any guest payload. Implementations MUST use the parsed destination
consistently for authorization, dialing, and audit.

- Validate the method, HTTP version, authority, explicit numeric port in the range 1-65535, and IPv6 bracket syntax. Reject empty hosts, userinfo, control characters, and ambiguous address encodings. Unsupported scoped IPv6 addresses must fail explicitly.
- For HTTP/1.1, validate the CONNECT request-target and Host field as the same destination. Reject conflicting or duplicate authorities and request framing that creates parser disagreement. Bytes buffered after the request head remain untrusted tunnel data and must not reach upstream before authorization.
- For HTTP/2, enforce the CONNECT pseudo-header rules, including the absence of `:scheme` and `:path` for ordinary CONNECT. Extended CONNECT uses its own required fields and requires advertised support. Reject unsupported `:protocol` values.
- For connect-udp, validate the configured URI template, decode each component exactly once, reject malformed encodings, and validate the resulting host and port. Apply the same workload and destination authorization as TCP.
- Normalize names and addresses consistently, including case, trailing DNS dots, IDNA handling, and IPv4-mapped IPv6 addresses (Section 6). Do not infer authority from PTR records, TLS fingerprints, or guest-provided identity headers.
- Strip or ignore guest tenant, credential-selection, routing-override, and impersonation headers. An authenticated upstream identity must be constructed from trusted state. Proxy authentication headers must not be forwarded as origin credentials.
- Bind every stream to its channel identity. Multiplexing MUST NOT allow a request header to select another tenant. Workload-specific policy and resource limits apply to every stream, including reconnects and retries.

Only a successful tunnel response permits payload forwarding. Standard HTTP
errors describe malformed requests, authentication requirements, policy
denials, and upstream failures; they MUST NOT be treated as successful tunnel
establishment.

## 3. Success and Interim Responses

A CONNECT request succeeds when the response status is in the 2xx class.
Clients MUST treat every 2xx status as tunnel establishment and MUST treat
every other final status as failure. Boundaries SHOULD send 200. Clients MUST
skip 1xx interim responses and wait for the final response. A boundary MUST
NOT send a message body with a 2xx response to CONNECT. The connect-udp
HTTP/1.1 upgrade form succeeds with 101 and an `Upgrade: connect-udp` field;
the HTTP/2 form succeeds with a 2xx status. Clients MUST close failed tunnels
without a direct-network retry.

## 4. Failure Signaling

Every final non-2xx response to a tunnel request MUST include exactly one
`Proxy-Status` field (RFC 9209) with exactly one member. The member name
identifies the boundary and MUST NOT vary with the requesting workload in a
way that reveals other workloads' identifiers. The member MUST carry an
`error` parameter with a type from the HTTP Proxy Error Types registry and a
`reason` parameter whose value is a Token from the agents.net reason token
registry ([registries.md](registries.md#2-reason-tokens)). The `details`
parameter MAY carry text; it MUST NOT contain guest-supplied bytes verbatim,
resolved addresses of denied requests, or policy contents. No other response
field carries the decision.

Policy denials MUST use status 403. Malformed requests MUST use a 4xx status
other than 403 and SHOULD use the specific reason token for the defect; a
boundary that cannot distinguish defects MAY use the generic token
`malformed-request`. Resolution and dial failures MUST use 502. Resource
exhaustion and unavailable policy MUST use 503. Unsupported HTTP versions
MUST use 505. A client MUST NOT infer success from any field when the status
is not 2xx.

```http
HTTP/1.1 403 Forbidden
Proxy-Status: boundary; error=http_request_denied; reason=not-on-allowlist
Content-Length: 0
```

## 5. Address Policy and Checked-Address Dialing

The boundary resolves hostnames using its configured resolver. It MUST check
every address it may dial, including alternate-family results and retries, and
dial the checked address without another unchecked resolution. An allowed name
can resolve to a forbidden address. Cached DNS answers are not cached
authorization and must be checked against the applicable policy.

### 5.1 Special-Purpose Addresses

After removing an IPv4-mapped IPv6 prefix, an address in any of the following
ranges is special-purpose:

- IPv4: `0.0.0.0/8`, `10.0.0.0/8`, `100.64.0.0/10`, `127.0.0.0/8`, `169.254.0.0/16`, `172.16.0.0/12`, `192.0.0.0/24`, `192.0.2.0/24`, `192.168.0.0/16`, `198.18.0.0/15`, `198.51.100.0/24`, `203.0.113.0/24`, `224.0.0.0/4`, `240.0.0.0/4`.
- IPv6: `::/128`, `::1/128`, `64:ff9b::/96`, `64:ff9b:1::/48`, `100::/64`, `2001::/23`, `2001:db8::/32`, `2002::/16`, `3fff::/20`, `5f00::/16`, `fc00::/7`, `fe80::/10`, `fec0::/10`, `ff00::/8`.

The list covers local, private, link-local, metadata, multicast, broadcast,
and documentation destinations for both address families. An address with a
zone identifier is rejected with `scoped-ip`. A literal loopback address means
the boundary's loopback, not the guest's.

### 5.2 Authorization Algorithm

**Literal destinations** are authorized only by a rule whose `ip` or `cidr`
contains the address and whose ports and transports match
([policy.md](policy.md)). The special-purpose table does not apply to
literals; deny-by-default does. No match is `ip-not-on-allowlist`; a match
with a non-matching port is `port-not-allowed`; a match with a non-matching
transport is `transport-not-allowed`.

**Hostname destinations** are authorized in two steps. First the name is
matched against name rules (Section 6); no match is `not-on-allowlist`, a
match with a non-matching port is `port-not-allowed`, a match with a
non-matching transport is `transport-not-allowed`. Second the boundary
obtains the address set from the rule's `resolve` list, if present, or from
its configured resolver. Each address is kept if it is listed in the rule's
`resolve` list, or is authorized as a literal for that port by an `ip` or
`cidr` rule, or matches an entry of `resolved_addresses` for that port, or is
not special-purpose. If no address remains the request is denied with
`resolved-address-denied`. Implementations MAY deny the request when any
address was removed. A literal permission therefore also admits the same
address as a resolution result; the converse does not hold:
`resolved_addresses` never authorizes a literal.

### 5.3 Dialing

The boundary MUST connect only to addresses in the kept set and MUST use the
port from the request. It MAY attempt them in any order and concurrently. It
MUST NOT resolve the name again for the same request, including on connection
failure. When it forwards to a next-hop proxy, the next hop's address is the
dialed address for the purposes of this section, and the next hop MUST apply
this section before its own dial. The audit record's `address` is the address
of the connection that was established, or absent.

Static service mappings and proxy chains require authorization like any
other destination. DNSSEC can authenticate signed DNS records; it does not
establish permission to reach an address. Synthetic DNS in an adapter
preserves a name for policy but is not an attestation of application intent;
the adapter's synthetic ranges must not overlap required literal destinations
([adapters.md](adapters.md)).

For opaque tunnels, upstream TLS or SSH authentication belongs to the client
application. If an application gateway terminates TLS, it MUST independently
validate the upstream certificate and expected service identity before sending
credentials or sensitive data ([gateway.md](gateway.md)). It must not disable
upstream verification to make interception work.

## 6. Name Normalization and Matching

A hostname in a request-target, `Host` field, or connect-udp template is
normalized by lowercasing ASCII letters, removing one trailing `.`, and
converting U-labels to A-labels with the UTS #46 non-transitional lookup
mapping and the Bidi rule, with the STD3 ASCII rules relaxed so that `_` is
permitted. After normalization the name MUST consist of one or more labels
of 1-63 characters from `a-z`, `0-9`, `-`, `_`, separated by `.`, with total
length at most 253; otherwise the request is `malformed-target`.

A rule with `name` matches when the normalized name is equal to it. A rule
with `suffix` matches when the normalized name ends with `.` followed by the
suffix and has at least one label before it; the suffix itself does not
match. A suffix rule with `depth` matches only when the number of labels
before the suffix is at most `depth`, so `{"suffix": "example.com", "depth": 1}`
matches `a.example.com` and not `a.b.example.com`. The rule `name: "*"`
matches every valid name and never a literal address. Policy names and
suffixes are normalized identically at load time; a policy containing an
address in a `name` or `suffix` field is invalid.

## 7. HTTP/2

A `boundary-h2` listener accepts HTTP/2 with prior knowledge on cleartext
channels and requires ALPN `h2` on TLS channels. Every stream on a session
carries the session's identity; a request field MUST NOT select another
identity or policy. A boundary that supports extended CONNECT MUST advertise
`SETTINGS_ENABLE_CONNECT_PROTOCOL = 1` (RFC 8441) and MUST reject a
`:protocol` pseudo-header received before it was advertised or when the value
is unsupported. A client MUST NOT send `:protocol` before receiving that
setting. Ordinary CONNECT MUST NOT carry `:scheme` or `:path`. Per-session
stream budgets apply to every stream, and exhaustion is signaled with
RST_STREAM (REFUSED_STREAM) or a 503 `busy` response.

## 8. UDP

A `boundary-udp` listener accepts the connect-udp request forms of RFC 9298
with the template `/.well-known/masque/udp/{target_host}/{target_port}/`
unless the implementation statement names another template. Each component
is percent-decoded exactly once. Authorization is identical to TCP with
transport `udp`. After success the stream carries RFC 9297 capsules; the
boundary MUST bound capsule length, drop unknown capsule types per RFC 9297,
send datagrams only to the authorized destination, deliver to the client only
datagrams received from that destination, and apply an idle timeout. Failure
to reach the destination after success is reported by closing the stream;
there is no in-band error status.

## 9. Untrusted Tunnel Content

Once CONNECT succeeds, the boundary forwards a byte stream or UDP datagrams.
It MUST NOT interpret payload bytes as new boundary control messages, tenant
identity, channel registration, or credential requests. A payload that looks
like another CONNECT request is data for the already-selected upstream.

Traffic on port 443 is not necessarily TLS. Visible SNI and ALPN can support
consistency checks, but do not authenticate the content or prevent all domain
fronting. Encrypted ClientHello can hide the relevant name. An allowed server
may itself provide a proxy, relay, DoH service, or storage endpoint. An opaque
boundary cannot prevent these uses without additional policy or inspection.

End-to-end TLS preserves confidentiality from the boundary. It also prevents
the boundary from inspecting methods, URLs, credentials, prompts, and responses.
Deployments MUST distinguish destination policy from application policy. They
cannot claim both opaque end-to-end encryption and complete payload inspection
on the same connection.

An inspecting gateway requires bounded protocol parsers and per-request
authorization. It MUST handle connection reuse, HTTP/2 multiplexing, streaming,
redirects, and protocol upgrades explicitly. Authorizing the first request is
not sufficient for later requests on the same connection. Responses and tool
outputs remain untrusted, including instructions received from an allowed
service. Network authentication does not prevent prompt injection or make
downloaded code safe.

## 10. Security Considerations

The boundary is the only component whose decisions the sandbox cannot
influence, so every guest-controlled input it consumes is an attack surface:
the request head, the connect-udp template, DNS answers for allowed names,
and tunnel payload. Section 2 bounds the parser; Section 5 requires that the
address dialed is the address checked, which defeats rebinding and mixed
answers; Section 9 forbids interpreting payload as control messages. The
special-purpose table in Section 5.1 exists because a name allowlist is not
an address allowlist: a permitted name may resolve to a metadata service or
loopback. An exception in `resolved_addresses` reopens exactly the range it
names and nothing else, which is why such an exception MUST be contained in
a special-purpose range ([policy.md](policy.md)).

A denial is visible to the workload only as a connection failure; the
reason token is for the gateway, the operator, and the audit record, not for
the workload. The `details` parameter MUST NOT echo guest bytes because a
response field is the only channel back to the workload other than the
tunnel itself. Resource limits (connection budgets, stream budgets, head
deadlines, idle timeouts) are part of the guarantee: an unbounded boundary
can be held by one sandbox to the detriment of others.

This profile authorizes destinations. It does not authenticate the upstream,
inspect content, or constrain what an allowed service does; those are the
subject of the optional gateway ([gateway.md](gateway.md)). The isolation
that makes the boundary the only path is the runtime's responsibility
([isolation.md](isolation.md)).

## 11. IANA Considerations

This profile requests registration of the `reason` parameter in the HTTP
Proxy-Status Parameters registry (RFC 9209 Section 2.3), with the value
syntax of an sf-token and semantics defined by the agents.net reason token
registry ([registries.md Section 2](registries.md#2-reason-tokens)). It
defines no new HTTP fields, status codes, or Proxy-Status error types; every
`error` value used is already registered.
