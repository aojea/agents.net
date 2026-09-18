# agents.net

agents.net is a network interface between a sandbox and an external
policy-enforcing proxy. It is meant for runtimes that execute autonomous
agents.

Version 1 (draft). Specification: [spec/draft](spec/draft/index.md).

## The Problem

An agent runs untrusted code. The model writes the plan, and carrying it out
means installing packages and calling tools. The agent still needs the network,
but only to reach the few services you pick for it, such as a model API, a
package registry, or a service of your own. Each sandbox product handles this
in its own way today. Policy formats are product-specific, and proxies are
advisory, so a client that ignores the proxy settings goes around them.
Address-based firewalls go stale as soon as a service moves behind a CDN. A
policy or an audit trail written for one provider does not carry over to
another.

## The Answer

The sandbox gets no network path at all. An adapter sits in front of it and
turns each connection the workload opens into an HTTP `CONNECT` request that
names the destination. The adapter sends those requests over a boundary socket
that belongs to this sandbox and no other. Outside the sandbox, a boundary
proxy checks each request against the policy descriptor bound to that socket,
resolves the name itself, dials only the address it checked, and writes one
audit record per decision.

```text
agent (ordinary sockets) -> adapter -> CONNECT api.example.com:443 -> boundary -> policy -> upstream
                                          no other path exists
```

Because there is no other route, the workload can't opt out. Ignoring
`HTTP_PROXY` or replacing the adapter changes nothing. Policy is applied to
the name the application asked for: the boundary sees `api.example.com`,
resolves it, and dials the address it checked. Any TCP client works
unmodified, since SSH, database drivers, raw sockets, and plain HTTP all end
up as CONNECT tunnels.

The wire is RFC 9110 CONNECT with RFC 9209 `Proxy-Status` and nothing
agent-specific, so any CONNECT-capable proxy can act as the boundary. The
policy descriptor and the audit record are each one JSON document that works
across implementations. The conformance suite (black-box fixtures, a harness,
and a driver contract) runs against any boundary.

What the boundary controls is which destinations traffic reaches. It does not
control what an allowed service does with that traffic. It works whether or
not the workload cooperates, but only while the runtime keeps the sandbox
confined.

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

The specification splits the system into four roles. Different parties can
build them and combine them, and each role has its own conformance profiles
([registries](spec/draft/registries.md)).

- **Adapter**: turns workload connections into CONNECT requests. A packet adapter (TUN, network namespace, or VMM packet backend) captures every connection whether or not the workload cooperates. An explicit adapter serves proxy-aware clients on hosts where packet interception isn't available.
- **Boundary**: any CONNECT-terminating proxy that applies the policy descriptor, resolves and checks addresses, reports failures with `Proxy-Status`, and writes audit records.
- **Controller**: the runtime that creates the sandbox, binds its boundary socket to one policy descriptor, and revokes both.
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

The specification is a draft of version 1. The reference boundary, the
adapters, and the launcher implement it. The HTTP/1.1 boundary groups of the
conformance suite run in CI, and the Firecracker and QEMU microVM scenarios
run on hosted runners. Envoy has been used as an alternative boundary for TCP
CONNECT over loopback. [docs/implementations.md](docs/implementations.md)
records what has been verified and what hasn't. Release rules are in
[spec/README.md](spec/README.md).

## License

See [LICENSE](LICENSE) and [COPYRIGHT.md](COPYRIGHT.md).
