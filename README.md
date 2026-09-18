# agents.net

**Sandbox networking for autonomous agents: one wire, external policy, no bypass.**

Version 1 (draft). Specification: [spec/draft](spec/draft/index.md).

## The Problem

An agent runs untrusted code: the model's plan, the packages it installs, the
tools it calls. It needs the network for exactly the services you allow (a
model API, a package registry, your internal service) and nothing else. Today
each sandbox product solves this differently, with product-specific policy,
proxies clients can ignore, address-based firewalls that go stale behind CDNs,
and no way to move a policy or an audit trail between providers.

## The Answer

Give the sandbox no network path. Put an adapter in front of it that turns
every connection the workload makes into an HTTP `CONNECT` request naming the
destination, and deliver those requests over a channel that belongs to that
sandbox alone. A boundary outside the sandbox decides each request against the
sandbox's policy, resolves the name itself, dials only the address it checked,
and writes one audit record per decision.

```text
agent (ordinary sockets) -> adapter -> CONNECT api.example.com:443 -> boundary -> policy -> upstream
                                          no other path exists
```

What this buys:

| Property | How |
| --- | --- |
| Enforcement the workload cannot opt out of | There is no route; ignoring `HTTP_PROXY` or replacing the adapter changes nothing |
| Policy on the name the application asked for | The boundary sees `api.example.com`, resolves it, and dials the checked address |
| Any TCP client, unmodified | SSH, database drivers, raw sockets, and HTTP all become CONNECT tunnels |
| Any CONNECT-capable proxy as the enforcement point | The wire is RFC 9110 CONNECT with RFC 9209 `Proxy-Status`; no agent-specific protocol |
| Portable policy and audit | One JSON policy descriptor and one JSON audit record work across implementations |
| Conformance you can run | Black-box fixtures, a harness, and a driver contract for any boundary |

The workload's cooperation is never required; the runtime's confinement is.
The guarantee is about which destinations traffic reaches, not about what an
allowed service does with it.

## Repository

| Directory | What it is | Start with |
| --- | --- | --- |
| [spec/](spec/README.md) | The specification: wire, policy descriptor, audit record, identity, isolation, lifecycle, adapters, ingress, gateways, registries, JSON Schemas. `draft/` is the working version; releases are frozen copies. | [spec/draft/index.md](spec/draft/index.md) |
| [conformance/](conformance/README.md) | Conformance suite: profiles per role, fixtures, harness, driver contract, runtime audit checklist, reporting | [conformance/README.md](conformance/README.md) |
| [sdk/](sdk/README.md) | Reference implementation in Go: library, three adapters (in-guest TUN launcher, namespace proxy, QEMU packet backend), and the `connect-proxy` boundary | [sdk/README.md](sdk/README.md) |
| [demo/](demo/README.md) | Runnable tutorial: an unmodified agent in a `--network none` container, confined by the injected launcher, with a Python boundary | [demo/README.md](demo/README.md) |
| [scenarios/](scenarios/README.md) | Executed topologies and measurements: containers, namespaces, Firecracker and QEMU microVMs, revocation, benchmarks | [scenarios/README.md](scenarios/README.md) |
| [docs/](docs/) | Informative material: [rationale and alternatives](docs/rationale.md), [implementations and status](docs/implementations.md), [test evidence](docs/evidence.md), [stakeholder reviews](docs/review-2026-09.md) ([second round](docs/review-2026-09b.md)), [roadmap](docs/roadmap.md) | [docs/roadmap.md](docs/roadmap.md) |

## Roles

Four roles can be built by different parties and combined; each has
conformance profiles ([registries](spec/draft/registries.md)).

- **Adapter**: turns workload connections into CONNECT requests. Packet adapters (TUN, network namespace, VMM backend) carry every connection of an uncooperative workload; an explicit adapter serves proxy-aware clients on hosts without packet interception.
- **Boundary**: any CONNECT-terminating proxy that applies the policy descriptor, resolves and checks addresses, signals failures with `Proxy-Status`, and writes audit records.
- **Controller**: the runtime that creates the sandbox, binds one channel to one policy, and revokes both.
- **Ingress gateway** (optional): delivers authenticated inbound requests to one pinned loopback port.

## Quick Start

```bash
# Build and test the reference implementation
go -C sdk build ./... && go -C sdk test -race ./...

# Run the conformance suite against the reference boundary
python3 conformance/harness/run_boundary.py \
    --driver conformance/harness/drivers/connect-proxy.sh --keep-going

# Run the container demo (Docker required)
demo/test_demo.sh
```

## Status

The specification is a draft of version 1. The reference boundary, adapters,
and launcher implement it; the conformance suite's HTTP/1.1 boundary groups
run in CI. Firecracker and QEMU microVM scenarios execute on hosted runners.
Envoy has been used as an alternative boundary for TCP CONNECT over loopback.
[docs/implementations.md](docs/implementations.md) records what is verified
and what is not. Release rules are in [spec/README.md](spec/README.md).

## License

See [LICENSE](LICENSE) and [COPYRIGHT.md](COPYRIGHT.md).
