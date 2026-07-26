# AGENTS_NET.md: The Agent Networking Specification

## Introduction: Back to the Future with Proxies

As AI agents become more autonomous, sandboxing them has evolved into a nightmare of virtual network interfaces, TAP devices, complex NAT rules, and IP routing.

However, the most successful standards in the AI ecosystem—like the Model Context Protocol (MCP) or `AGENTS.md`—succeed because they rely on simple, plain-text conventions rather than over-engineered frameworks. `AGENTS_NET.md` applies this exact philosophy to the network: **use simple conventions to tell the agent *how* to connect, and remove the network from the sandbox equation entirely.**

Instead of giving a sandbox a routed IP address, `agents.net` proposes booting agents in a **Zero-Network Environment** (e.g., only the loopback interface). We return to a battle-tested architecture: **ACLs + Proxies**. By mandating that agents route traffic through a standard `HTTP CONNECT` proxy, we completely decouple the agent's application code from the hypervisor's networking complexities.

## The `agents.net` Contract

To guarantee universal compatibility across Python, Node.js, Go, Java, and Rust without requiring custom transport code, `agents.net` defines two strict contracts.

### I. The Proxy Contract

The proxy endpoint is defined strictly as a standard HTTP URI. This ensures that standard HTTP libraries (like Python's `requests` or Node's `fetch`) require zero modifications or custom dialers.

```bash
AGENT_HTTP_PROXY=http://127.0.0.1:8080
AGENT_HTTPS_PROXY=http://127.0.0.1:8080
AGENT_NO_PROXY=localhost,127.0.0.1
```

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

### III. Agent Discovery & Sandbox Limitations

The following concrete examples illustrate how an agent navigates outbound connectivity and how the architecture restricts unauthorized operations:

#### 1. How the Agent Discovers Outbound Egress
Because the sandbox environment exports standard variables, an autonomous agent (or an unmodified off-the-shelf CLI tool) can inspect its environment and discover how to route egress traffic:
- **Environment Discovery**: Upon startup, an agent inspecting its shell environment reads `AGENT_HTTP_PROXY=http://127.0.0.1:8080` (or `HTTPS_PROXY` in legacy compatibility mode).
- **Outbound HTTP / HTTPS Egress**: Standard runtime libraries (Python `requests`, Node `fetch`, Go `net/http`, or CLI tools like `curl`) automatically direct `HTTP CONNECT` traffic to `127.0.0.1:8080` (which `socat` bridges to the host Unix Domain Socket `/var/run/agent-proxy.sock`):
  ```bash
  # Example prompt given to the agent harness in the reference demo:
  opencode run --model ollama/qwen3-coder:latest --auto \
    "Inspect your environment to figure out how networking is configured. Fetch https://example.com and then fetch https://google.com..."
  ```
- **Seamless TLS Validation**: Any HTTPS request to an inspection target validates smoothly because runtime CA variables (`REQUESTS_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE`) direct language trust stores to validate certificates using `AGENT_CA_CERT`.

#### 2. How the Agent is Limited by the Setup
The zero-network architecture enforces strict isolation and prevents unauthorized network operations or data exfiltration:
- **Zero Direct IP / Raw Socket Access**: Booted with `--network none`, the container has no network interface (other than loopback `lo`), no routing table, and no DNS resolver. Any attempt to bypass the proxy or open raw TCP/UDP sockets fails instantly at the OS kernel level (`Network is unreachable`).
- **Explicit Host Allow-List & 403 Feedback**: All outbound traffic must pass through the `agents.net` proxy. When the agent attempts to reach an unauthorized domain (`google.com`), the host proxy blocks the connection, logs it in the audit log, and returns an immediate in-band `403 Forbidden` response:
  ```text
  Audit Log:
  2026-07-25 23:19:01,067 [ALLOW-FAKE]         example.com:443 -> canned response (no upstream traffic)
  2026-07-25 23:19:01,119 [BLOCK]              google.com:443 -> 403 Forbidden

  Agent Output:
  1. Inspected environment: Proxy variables set to http://127.0.0.1:8080.
  2. Fetched https://example.com: Success (HTTP 200).
  3. Fetched https://google.com: Failed (Blocked by sandbox ACL: host 'google.com' is not on the allow-list).
  ```
- **Zero Secret Access inside Sandbox**: For cloud model providers or external APIs (Tier 3 `CREDENTIAL_HOSTS`), the container's environment and filesystem contain no real secrets. The host proxy injects the `Authorization: Bearer <token>` header during host-side TLS termination, ensuring that memory dumps or file exfiltration within the sandbox expose no sensitive API keys.

## Reference Implementation: The Zero-Network Sandbox

![agents.net terminal demo](demo/terminal-demo.gif)

This demo proves that a real, unmodified, off-the-shelf agent harness running inside a container with **`--network none`** (no `eth0`, no routing, no DNS) can reach the outside world purely through the `agents.net` contract -- no custom transport code, no vendor-specific patch.

The pattern is intentionally harness-agnostic: this spec doesn't care whether the agent is a Python script, a Node process, or a packaged CLI from any vendor. The only requirement is that the harness runs non-interactively and reads its credentials from its own environment rather than requiring an interactive sign-in -- an interactive OAuth/browser flow simply can't complete inside a disposable `--network none --rm` container with no human attached. [demo/](demo/) wires up one concrete, real, off-the-shelf CLI harness end-to-end as a worked example; swap in any other harness that meets that one requirement and the same contracts and proxy apply unchanged.

**The proxy enforces a real, four-tier ACL, not just relaying.** To make the "ACLs + Proxies" claim from the introduction concrete rather than theoretical, the host proxy allow-lists exactly four kinds of destination. Everything else the agent tries is blocked *and logged* for auditing, and the agent is told why via a normal HTTP `403` response instead of a silent hang -- the same in-band signaling principle DLP/inspection proxies rely on.

1. **Fake-response hosts** (the demo's task target, `example.com`): never forwarded anywhere. The proxy terminates TLS locally with a certificate signed by a demo CA and returns a canned success response, proving both contracts together (the response is only trusted because `AGENT_CA_CERT` was mounted and wired into the runtime's trust store).
2. **Local-provider hosts** (a model server on the operator's own machine, e.g. a local Ollama instance -- the demo's default, requiring no account or paid API key): the sandbox only ever knows a symbolic hostname it can't resolve or route to on its own; the proxy alone maps it to a real `host:port`. Genuinely relayed, no TLS termination, no secret involved -- the same principle as credential-inject below, minus the credential.
3. **Credential-inject hosts**, opt-in (a real hosted model API or other bearer-token backend, for anyone migrating off the local provider): genuinely relayed to the real internet, with the proxy swapping in the real credential -- see [AGENTS_NET_THE_HARD_WAY.md](AGENTS_NET_THE_HARD_WAY.md) for the full mechanism. The sandbox never holds the real secret.
4. **Passthrough hosts** (housekeeping the harness does on its own -- package installs, update checks, telemetry -- that carry no secret and need no canned response): genuinely relayed byte-for-byte, with no TLS termination at all.

**Follow [AGENTS_NET_THE_HARD_WAY.md](AGENTS_NET_THE_HARD_WAY.md) for the full, step-by-step, hands-on walkthrough** -- generating the demo CA, starting the host proxy, building the sandbox image, running it with `--network none`, and reading the resulting audit trail line by line, including how credential injection is proven and how to troubleshoot common failures.

The full reference implementation lives in [demo/](demo/):

- [demo/gen_certs.sh](demo/gen_certs.sh) — generates the demo root CA and a single multi-SAN leaf certificate covering every MITM'd host.
- [demo/host_proxy.py](demo/host_proxy.py) — the host-side proxy: enforces the four-tier allow-list, logs every request (allowed, injected, passed through, or blocked) for auditing, answers fake-response hosts itself, relays to local providers, and injects real credentials for credential-inject hosts.
- [demo/entrypoint.sh](demo/entrypoint.sh) — the sandbox bridge that maps the UDS back to TCP and injects the `agents.net` environment variables.
- [demo/Dockerfile](demo/Dockerfile) — a concrete, worked example wiring up one specific off-the-shelf CLI harness unmodified as the container's entrypoint command; swap in any other harness by editing this one file.

## Future Scope: Ingress Traffic

*Status: Open Discussion*
While `HTTP CONNECT` solves agent egress, ingress (such as inbound Webhooks or OAuth callbacks) introduces distinct isolation challenges. Future versions of this specification will define a Zero-Trust Gateway pattern, where the host harness holds the public URL and streams validated events down into the sandbox, ensuring the agent never exposes an open port directly to the internet.
