# Policy Descriptor

**Part of:** [agents.net specification, version 1 (draft)](index.md)  
**Status:** Draft  
**Schema:** [schema/policy.schema.json](schema/policy.schema.json)

A policy descriptor is the JSON document that a controller installs on a
boundary listener. The same document can be carried from one deployment to
another by a customer or a framework. The boundary evaluates each request
against the descriptor as defined in
[wire.md Section 5](wire.md#5-address-policy-and-checked-address-dialing) and
[Section 6](wire.md#6-name-normalization-and-matching). The descriptor's
`version` string appears in every audit record ([audit.md](audit.md)).

## 1. Example

```json
{
  "agents_net_policy": 1,
  "version": "2026-09-17T10:00:00Z/3",
  "sandbox": "sandbox-a",
  "default": "deny",
  "rules": [
    {"id": "npm", "name": "registry.npmjs.org", "ports": [443]},
    {"id": "gh-pkgs", "suffix": "pkg.github.com", "ports": [443]},
    {"id": "gh-user", "suffix": "github.io", "depth": 1, "ports": [443]},
    {"id": "db", "ip": "203.0.113.10", "ports": [5432]},
    {"id": "v6net", "cidr": "2001:db8::/64", "ports": ["443", "8000-8099"], "transports": ["tcp", "udp"]},
    {"id": "internal", "name": "svc.internal.example", "ports": [443], "resolve": ["10.0.1.50"]}
  ],
  "resolved_addresses": [
    {"cidr": "10.0.0.0/8", "ports": [443]}
  ],
  "features": {"udp": true, "h2": false}
}
```

## 2. Semantics

`agents_net_policy` is the schema version. A boundary MUST reject a
descriptor with an unknown version. `version` is an opaque string, and the
boundary copies it into every audit record. `sandbox` is required; it is
the identity label that appears in audit records, and it does not select
policy. `default` MUST be `deny`.

Each rule has exactly one of `name`, `suffix`, `ip`, `cidr`. `ports` is a
list whose entries are integers, decimal strings, or `"a-b"` ranges within
1-65535; when it is absent, the rule covers every port. `transports` is a
subset of `["tcp", "udp"]` and defaults to `["tcp"]`. `resolve` is
permitted only with a `name` other than `"*"`. It lists the addresses the
boundary uses for that name instead of DNS, and those addresses are
authorized for the rule's ports and transports without a
`resolved_addresses` entry. `depth` is permitted only with `suffix`, takes
a value from 1 to 126, and bounds the number of labels before the suffix
([wire.md Section 6](wire.md#6-name-normalization-and-matching)). `id` is
optional; when present, it appears in the `rule` field of the audit record.
Rules are unordered, and a request is allowed when any rule allows it.

`resolved_addresses` lists special-purpose addresses or prefixes
([wire.md Section 5.1](wire.md#51-special-purpose-addresses)) that resolution
results MAY use, per port. Each entry MUST lie within one special-purpose
range; a descriptor with an entry outside those ranges, such as `0.0.0.0/0`,
is invalid. An entry in `resolved_addresses` does not authorize a literal
destination.

When `features.udp` is false, every connect-udp request is refused with
`udp-disabled`, regardless of the rules. `features.h2` is informational and
intended for controllers.

When the descriptor is absent or invalid, a boundary MUST refuse to start,
or it MUST answer every request with `policy-unavailable`.

## 3. Versioning and Updates

Policy updates MUST be versioned and auditable. In the baseline, a
controller replaces a listener's policy by stopping and restarting the
boundary for that sandbox ([lifecycle.md](lifecycle.md)). A boundary that
replaces policy in place MUST do so atomically with respect to requests and
MUST record decisions under the new `version` from the first request that
the new policy governs.

## 4. Other Control Planes

Kubernetes resources, gateway route types, provider SDK parameters, and host
firewall rule sets are inputs to a controller; this specification does not
define them. A controller conforms by producing a descriptor whose decisions
equal the decisions the controller enforces, so that the same conformance
fixtures produce the same audit decisions under every conforming controller.
