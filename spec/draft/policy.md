# Policy Descriptor

**Part of:** [agents.net specification, version 1 (draft)](index.md)  
**Status:** Draft  
**Schema:** [schema/policy.schema.json](schema/policy.schema.json)

A policy descriptor is the JSON document a controller installs on a boundary
listener, and the unit a customer or framework moves between deployments. A
boundary evaluates requests against it as defined in
[wire.md Section 5](wire.md#5-address-policy-and-checked-address-dialing) and
[Section 6](wire.md#6-name-normalization-and-matching). The `version` string
appears in every audit record ([audit.md](audit.md)).

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

`agents_net_policy` is the schema version; a boundary MUST reject a
descriptor with an unknown version. `version` is an opaque string that the
boundary records in every audit record. `sandbox` is the identity label
recorded in audit records; it does not select policy. `default` MUST be
`deny`.

Each rule has exactly one of `name`, `suffix`, `ip`, `cidr`. `ports` is a
list of integers or `"a-b"` ranges within 1-65535; absent means every port.
`transports` is a subset of `["tcp", "udp"]`; absent means `["tcp"]`.
`resolve` is permitted only with `name` (not `"*"`) and lists the addresses
used instead of DNS for that name; those addresses are authorized for the
rule's ports and transports without a `resolved_addresses` entry. `depth`
is permitted only with `suffix` and bounds the number of labels before the
suffix ([wire.md Section 6](wire.md#6-name-normalization-and-matching)).
`id` is optional and appears in the audit record's `rule` field. Rules are
unordered; a request is allowed when any rule allows it.

`resolved_addresses` lists special-purpose addresses or prefixes
([wire.md Section 5.1](wire.md#51-special-purpose-addresses)) that resolved
results MAY use, per port. Each entry MUST be contained in one
special-purpose range; a descriptor with an entry outside those ranges, such
as `0.0.0.0/0`, is invalid. It does not authorize literals.

`features.udp` false means every connect-udp request is `udp-disabled`
regardless of rules. `features.h2` is informational for controllers.

A boundary MUST refuse to start, or MUST answer every request with
`policy-unavailable`, when the descriptor is absent or invalid.

## 3. Versioning and Updates

Policy updates MUST be versioned and auditable. The baseline replaces a
listener's policy by stopping and restarting the boundary for that sandbox
([lifecycle.md](lifecycle.md)); a boundary that replaces policy in place MUST
do so atomically with respect to requests and MUST record decisions under the
new `version` from the first request it governs.

## 4. Other Control Planes

Kubernetes resources, gateway route types, provider SDK parameters, and host
firewall rule sets are controller inputs. A controller conforms by producing a
descriptor whose decisions equal the ones it enforces, so that the same
conformance fixtures produce the same audit decisions across controllers. This
specification does not define those resources.
