# agents.net

`agents.net` defines how an isolated sandbox communicates with a Policy Enforcement Point (PEP) by removing the sandbox's direct network stack, using Unix sockets (or `vsock`) as capabilities, requiring mTLS on network hops, and framing traffic with HTTP `CONNECT`.

Read the specification in [SPEC.md](SPEC.md).

## Overview

Untrusted agent code should not hold API keys or sit directly on a host or cluster network. Removing the direct network stack reduces kernel attack surface and allows userspace security updates without host kernel reboots. The runtime uses dedicated channels for two separate paths:

- **Egress:** Traffic from the sandbox is converted (inside the guest or on the host) into HTTP `CONNECT` and optional RFC 9298 `connect-udp` requests over a capability channel, and forwarded over mTLS to a PEP. Policy evaluation, DNS resolution, L7 inspection, and credential injection stay in the PEP and are implementation-specific.
- **Ingress:** The runtime exposes the sandbox's bridge endpoint, mTLS identity, immutable sandbox ID, and allowed ports so an external inbound proxy can forward authorized traffic into the sandbox over mTLS `CONNECT` without the sandbox having a reachable IP.

```text
Egress:   sandbox -> [converter] -> UDS/vsock --(mTLS + HTTP CONNECT)--> PEP -> upstream
Ingress:  caller -> inbound proxy --(mTLS + CONNECT <id>:<port>)--> bridge -> sandbox:<port>
```

## Repository

| Path | What it is |
| --- | --- |
| [SPEC.md](SPEC.md) | The specification: architecture (PEP model, UDS/`vsock` capabilities, mandatory mTLS, HTTP `CONNECT` egress, exposed ingress) and implementation patterns |
| [sdk/](sdk/README.md) | Go reference implementation: library, converters (`tun2connect`, `netnsproxy`, `qemuproxy`), and reference PEP (`connect-proxy`) |
| [kubernetes/](kubernetes/README.md) | Kubernetes DRA + NRI driver (`dra.agents.net`), stateless ingress gateway, and kind smoke test |
| [conformance/](conformance/README.md) | Black-box boundary test fixtures, harness, JSON schemas for the reference PEP, and runtime audit checklist |
| [demo/](demo/README.md) | Docker tutorial running an agent in a `--network none` container behind `tun2connect` |
| [scenarios/](scenarios/README.md) | Container, namespace, Firecracker, and QEMU experiments and measurements |

## Quick Start

```bash
# Build and test the Go SDK and reference PEP
go -C sdk build ./... && go -C sdk test -race ./...

# Build and test the Kubernetes DRA + NRI driver
make -C kubernetes build test

# Validate conformance fixtures and run the boundary test harness
python3 conformance/harness/check_fixtures.py
python3 conformance/harness/run_boundary.py \
    --driver conformance/harness/drivers/connect-proxy.sh --keep-going

# Run the Docker container demo
demo/test_demo.sh
```

## License

See [LICENSE](LICENSE) and [COPYRIGHT.md](COPYRIGHT.md).
