# AGENTS.NET: The Agent Networking Specification

## Introduction: Back to the Future with Proxies

As AI agents become more autonomous, sandboxing them has evolved into a nightmare of virtual network interfaces, TAP devices, complex NAT rules, and IP routing.

However, the most successful standards in the AI ecosystem—like the Model Context Protocol (MCP) or `AGENTS.md`—succeed because they rely on simple, plain-text conventions rather than over-engineered frameworks. `agents.net` applies this exact philosophy to the network: **use simple conventions to tell the agent *how* to connect, and remove the network from the sandbox equation entirely.**

Instead of giving a sandbox a routed IP address, `agents.net` proposes booting agents in a **Zero-Network Environment** (e.g., only the loopback interface). We return to a battle-tested architecture: **ACLs + Proxies**. By mandating that agents route traffic through a standard `HTTP CONNECT` proxy, we completely decouple the agent's application code from the hypervisor's networking complexities.

Furthermore, standardizing on HTTP turns response traffic into an **in-band metadata and instruction channel**. Because AI agents naturally parse and reason over HTTP status codes, headers, and response bodies during tool execution, host proxies can signal policy decisions (e.g., `403 Forbidden` with block reasons), rate limits (`429`), or instructions (`X-Agent-Instruction`, `Retry-After`) directly in-band—guiding agent behavior without requiring out-of-band side channels or custom SDK extensions.

## The `agents.net` Contract

To guarantee universal compatibility across any programming language or runtime without requiring custom transport code, `agents.net` defines three strict contracts.

### I. The Proxy Contract

The proxy endpoint is defined strictly as a standard HTTP URI. This ensures that standard HTTP libraries (like Python's `requests` or Node's `fetch`) require zero modifications or custom dialers.

```bash
AGENT_HTTP_PROXY=http://127.0.0.1:8080
AGENT_HTTPS_PROXY=http://127.0.0.1:8080
AGENT_NO_PROXY=localhost,127.0.0.1
```

**Sandbox Implementation Requirement:** For legacy toolchains or runtimes that require explicit opt-in for environment proxies (such as Node.js v22.21+ / v24+ native `fetch` support via `NODE_USE_ENV_PROXY=1`), the sandbox initialization process MUST map proxy variables before launching the agent:

- `HTTP_PROXY=$AGENT_HTTP_PROXY`
- `HTTPS_PROXY=$AGENT_HTTPS_PROXY`
- `NO_PROXY=$AGENT_NO_PROXY`
- `NODE_USE_ENV_PROXY=1`

*Note: Sandbox providers are responsible for bridging this local TCP port to the host (e.g., using `socat` to forward `127.0.0.1:8080` to a mounted Unix Domain Socket or `vsock`).*

### II. The Trust Contract (TLS Inspection)

To allow the host harness to terminate TLS for traffic inspection, auditing, and Data Loss Prevention (DLP), the host may optionally mount a custom Root CA certificate into the sandbox.

```bash
AGENT_CA_CERT=/var/run/agent-ca.pem
```

**Sandbox Implementation Requirement:** Because programming languages use different trust stores, the sandbox initialization process MUST map `AGENT_CA_CERT` to runtime-specific variables *before* launching the agent:

- `NODE_EXTRA_CA_CERTS=$AGENT_CA_CERT`
- `REQUESTS_CA_BUNDLE=$AGENT_CA_CERT`
- `SSL_CERT_FILE=$AGENT_CA_CERT`

### III. The Ingress Contract (Inbound Traffic)

To allow isolated agents to receive Webhooks, OAuth callbacks, or direct user prompts without exposing open network ports, `agents.net` treats the host harness as an **Ingress API Gateway**. 

The host owns the public IPs, terminates public TLS, and absorbs all internet attacks (DDoS, malformed payloads). The sandbox remains hermetically sealed.

#### Application Contract
If an agent needs to receive inbound HTTP traffic, it MUST NOT attempt to bind to a public interface (`0.0.0.0`). Instead, it MUST bind its local web server to the loopback interface on the port specified by the environment:

```bash
AGENT_INGRESS_PORT=8081
```

When registering webhooks or providing callback URLs to third-party services, the agent MUST use the public URL provided by the host:

```bash
AGENT_PUBLIC_URL=https://agents.yourdomain.com/callbacks/agent-123
```

#### Infrastructure Contract
The sandbox provider MUST bridge external requests from the Host to the Guest using an inbound transport mechanism. 

The Host Harness MUST act as a Web Application Firewall (WAF) and Reverse Proxy. When the host receives a request on the `AGENT_PUBLIC_URL`, it strips malicious headers, enforces payload limits, and securely streams the raw HTTP request down the Unix socket (or vsock) into the sandbox, routing it to `127.0.0.1:$AGENT_INGRESS_PORT`.

## Reference Implementation: The Zero-Network Sandbox

![agents.net terminal demo](demo/terminal-demo.gif)

This demo proves that a real, unmodified, off-the-shelf agent harness running inside a container with **`--network none`** (no `eth0`, no routing, no DNS) can reach the outside world purely through the `agents.net` contract -- no custom transport code, no vendor-specific patch.

The pattern is intentionally harness-agnostic: this spec doesn't care whether the agent is a Python script, a Node process, or a packaged CLI from any vendor. The only requirement is that the harness runs non-interactively and reads its credentials from its own environment rather than requiring an interactive sign-in -- an interactive OAuth/browser flow simply can't complete inside a disposable `--network none --rm` container with no human attached. [demo/](demo/) wires up one concrete, real, off-the-shelf CLI harness end-to-end as a worked example; swap in any other harness that meets that one requirement and the same contracts and proxy apply unchanged.

**The proxy enforces a real, four-tier ACL, not just relaying.** To make the "ACLs + Proxies" claim from the introduction concrete rather than theoretical, the host proxy allow-lists exactly four kinds of destination. Everything else the agent tries is blocked *and logged* for auditing, and the agent is told why via a normal HTTP `403` response instead of a silent hang -- the same in-band signaling principle DLP/inspection proxies rely on.

1. **Fake-response hosts** (the demo's task target, `example.com`): never forwarded anywhere. The proxy terminates TLS locally with a certificate signed by a demo CA and returns a canned success response, proving both contracts together (the response is only trusted because `AGENT_CA_CERT` was mounted and wired into the runtime's trust store).
2. **Local-provider hosts** (a model server on the operator's own machine, e.g. a local Ollama instance -- the demo's default, requiring no account or paid API key): the sandbox only ever knows a symbolic hostname it can't resolve or route to on its own; the proxy alone maps it to a real `host:port`. Genuinely relayed, no TLS termination, no secret involved -- the same principle as credential-inject below, minus the credential.
3. **Credential-inject hosts**, opt-in (a real hosted model API or other bearer-token backend, for anyone migrating off the local provider): genuinely relayed to the real internet, with the proxy swapping in the real credential -- see [demo/README.md](demo/README.md) for the full mechanism. The sandbox never holds the real secret.
4. **Passthrough hosts** (housekeeping the harness does on its own -- package installs, update checks, telemetry -- that carry no secret and need no canned response): genuinely relayed byte-for-byte, with no TLS termination at all.

**Follow [demo/README.md](demo/README.md) for the full, step-by-step, hands-on walkthrough** -- generating the demo CA, starting the host proxy, building the sandbox image, running it with `--network none`, and reading the resulting audit trail line by line, including how credential injection is proven and how to troubleshoot common failures.

The full reference implementation lives in [demo/](demo/):

- [demo/README.md](demo/README.md) — step-by-step tutorial for building and running the zero-network sandbox.
- [demo/gen_certs.sh](demo/gen_certs.sh) — generates the demo root CA and a single multi-SAN leaf certificate covering every MITM'd host.
- [demo/host_proxy.py](demo/host_proxy.py) — the host-side proxy: enforces the four-tier allow-list, logs every request (allowed, injected, passed through, or blocked) for auditing, answers fake-response hosts itself, relays to local providers, injects real credentials for credential-inject hosts, and routes inbound gateway traffic.
- [demo/entrypoint.sh](demo/entrypoint.sh) — the sandbox bridge that maps the UDS back to TCP and injects the `agents.net` environment variables (both egress and ingress).
- [demo/Dockerfile](demo/Dockerfile) — a concrete, worked example wiring up one specific off-the-shelf CLI harness unmodified as the container's entrypoint command; swap in any other harness by editing this one file.
