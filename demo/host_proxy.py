#!/usr/bin/env python3
"""Host-side agents.net demo boundary.

A minimal HTTP CONNECT proxy (RFC 9110 section 9.3.6) on the sandbox
boundary socket -- the demo implementation of the spec's egress boundary,
kept in one small file so the whole ACL/audit story is auditable at a
glance:

1. The sandboxed agent has no network. Its launcher (`tun2connect run`)
   terminates the sandbox's TCP in userspace and delivers every flow
   here, over a Unix Domain Socket, as an HTTP CONNECT request naming its
   destination in the authority (`CONNECT api.example.com:443`) -- a
   *name*, never a resolved IP, because the launcher's virtual DNS never
   resolves it away.
2. Policy is deny-by-default on that name. Anything not on the allow-list
   is refused with `403 Forbidden` and a `Boundary-Reason` header, which
   the guest stack turns into an ordinary ECONNREFUSED -- and the attempt
   is logged. IP literals are refused the same way: policy reasons about
   names, so a flow that arrives without one was never authorized.
3. Every flow -- relayed, injected, answered, or refused -- is written to
   an audit log, the auditing/DLP hook called out in the spec's TLS
   inspection models.
4. The allow-list has four tiers:
   - FAKE_RESPONSE_HOSTS (the demo's task target, example.com) are NOT
     forwarded anywhere. This boundary terminates TLS locally using a
     certificate signed by the demo CA (see gen_certs.sh) and returns a
     canned success response. This keeps that part of the demo
     deterministic and network-independent, while still requiring the
     agent to complete a real, encrypted HTTPS request that only validates
     because of the mounted `AGENT_CA_CERT` (the spec's trust-store
     coordination).
   - LOCAL_PROVIDER_HOSTS (default: a local Ollama server) let the sandbox
     reach a model backend running on the OPERATOR's own machine, by a
     purely symbolic hostname (e.g. "ollama") it can never resolve or
     route to on its own -- the launcher's virtual DNS invents the answer
     and only this boundary knows the real loopback address. No secret is
     involved (Ollama accepts any API key), so this is genuinely relayed
     byte-for-byte with no TLS termination -- see
     AGENT_PROXY_LOCAL_PROVIDERS below. This is what makes the reference
     demo runnable end-to-end for free, with no cloud subscription and no
     vendor lock-in.
   - CREDENTIAL_HOSTS are a real cloud model backend the harness needs to
     reach to reason at all (e.g. api.openai.com) -- opt-in, for anyone
     who wants to swap the free local model for a paid one. These are
     genuinely relayed to the real internet, but this boundary *also*
     terminates TLS for them and injects the real `Authorization` header
     itself, sourced only from the HOST's own environment (see
     AGENT_PROXY_TOKENS below). The sandboxed agent is never given the
     real credential -- it can hold an empty or placeholder value, or none
     at all. This decouples the agent from the secret entirely: an admin
     can mint, scope, and revoke a distinct token per sandbox instance
     without ever baking a real secret into the sandboxed image, its
     environment, or its filesystem, shrinking the credential's blast
     radius to "whatever this one boundary process was handed." Switching
     from the local model to a real cloud one changes nothing about the
     sandbox, the Dockerfile, or the `docker run` command -- only this
     host-side config and the harness's own config file.
   - PASSTHROUGH_HOSTS (see AGENT_PROXY_PASSTHROUGH below; default:
     registry.npmjs.org, which AI frameworks may need when installing
     packages) are hosts the harness needs for its own housekeeping --
     package installs, update checks, telemetry -- that carry no secret
     and need no canned response. These are genuinely relayed
     byte-for-byte with NO TLS termination on our end at all: the agent's
     own TLS session runs straight through the tunnel to the real server,
     verified against the container's own system trust store.

It also serves the spec's ingress interface: a public TCP port on the host
is reverse-proxied into the sandbox over a second Unix socket served by the
launcher from inside, using the Firecracker hybrid-vsock handshake
("CONNECT <port>\\n" -> "OK\\n"), so a microVM offers the identical
protocol with no code change.

This file is deliberately independent of any production implementation:
it interoperates with the launcher purely through the boundary protocol,
which is the point of having a spec.
"""
import datetime
import hashlib
import ipaddress
import os
import select
import socket
import ssl
import threading

SOCKET_DIR = "/tmp/agent-sockets"
EGRESS_UDS = f"{SOCKET_DIR}/egress-proxy.sock"
INGRESS_UDS = f"{SOCKET_DIR}/ingress-proxy.sock"
PUBLIC_INGRESS_PORT = int(os.environ.get("PUBLIC_INGRESS_PORT", 9000))
# The loopback port the agent serves inside the sandbox (its
# AGENT_INGRESS_PORT); the launcher connects each inbound stream to it.
AGENT_INGRESS_PORT = int(os.environ.get("AGENT_INGRESS_PORT", 8081))

UDS_PATH = EGRESS_UDS
AUDIT_LOG_PATH = "/tmp/agent-proxy-audit.log"

CERT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "certs")
# A single leaf cert with a SAN entry per TLS-inspected host (see
# gen_certs.sh), used for both fake-response and credential-inject
# termination.
MITM_CERT = os.path.join(CERT_DIR, "agent-mitm.pem")
MITM_KEY = os.path.join(CERT_DIR, "agent-mitm.key")


# Tier 1: the demo's actual task target. Answered locally, never forwarded.
FAKE_RESPONSE_HOSTS = {"example.com", "httpbin.org"}


def _load_credential_hosts() -> dict:
    """Tier 3: hosts genuinely relayed to the real internet, with the real
    bearer token injected by the boundary itself.

    Configured via AGENT_PROXY_TOKENS, a comma-separated list of
    "host=ENV_VAR_NAME" pairs, e.g. "api.openai.com=OPENAI_API_KEY". The
    ENV_VAR_NAME is read from *this process's* (the host's) environment --
    never from inside the sandbox -- so the real secret never has to be
    passed into the container at all.

    A host is only added to the allow-list if its token env var is
    actually set on the host; otherwise it's logged as unconfigured and
    left off the allow-list (fails closed). Empty by default -- the demo
    runs entirely against the free local Ollama provider unless you opt in
    to a real cloud backend by setting this.
    """
    spec = os.environ.get("AGENT_PROXY_TOKENS", "")
    hosts = {}
    for entry in spec.split(","):
        entry = entry.strip()
        if not entry or "=" not in entry:
            continue
        host, env_var = (p.strip() for p in entry.split("=", 1))
        token = os.environ.get(env_var)
        if token:
            hosts[host] = token
        else:
            print(
                f"[!] AGENT_PROXY_TOKENS: '{env_var}' is not set on the host -- "
                f"'{host}' will NOT be reachable from the sandbox."
            )
    return hosts


CREDENTIAL_HOSTS = _load_credential_hosts()  # host -> real bearer token


def _load_local_providers() -> dict:
    """Tier 2: local model providers (e.g. Ollama) the sandbox reaches by a
    purely symbolic hostname it can never resolve or route to on its own.
    The boundary is the only thing that knows the real address, exactly
    mirroring how it -- not the sandbox -- holds the real credential for
    CREDENTIAL_HOSTS. No secret is involved here: Ollama's
    OpenAI-compatible API accepts any API key string.

    Configured via AGENT_PROXY_LOCAL_PROVIDERS, a comma-separated list of
    "symbolic-host=real-host:real-port" entries, e.g.
    "ollama=127.0.0.1:11434". Genuinely relayed as plain, uninspected
    bytes -- Ollama serves plain HTTP, so no TLS termination is needed.
    """
    spec = os.environ.get("AGENT_PROXY_LOCAL_PROVIDERS", "ollama=127.0.0.1:11434")
    providers = {}
    for entry in spec.split(","):
        entry = entry.strip()
        if not entry or "=" not in entry:
            continue
        symbolic, _, addr = entry.partition("=")
        symbolic = symbolic.strip()
        real_host, _, real_port_s = addr.strip().partition(":")
        try:
            real_port = int(real_port_s) if real_port_s else 80
        except ValueError:
            continue
        if symbolic and real_host:
            providers[symbolic] = (real_host, real_port)
    return providers


LOCAL_PROVIDER_HOSTS = _load_local_providers()  # symbolic host -> (real host, real port)

# Tier 4: hosts the harness talks to that need neither a canned response nor
# credential injection nor a local-address rewrite (e.g. package registry
# pulls or telemetry). Configured via AGENT_PROXY_PASSTHROUGH, a
# comma-separated list of hostnames. Unlike CREDENTIAL_HOSTS, no token or env
# var is involved -- these are just allow-listed for genuine, uninspected
# egress. Leave this empty (AGENT_PROXY_PASSTHROUGH="") to instead REFUSE and
# audit these hosts, which is equally valid and demonstrates the ACL catching
# unexpected egress.
PASSTHROUGH_HOSTS = {
    h.strip()
    for h in os.environ.get(
        "AGENT_PROXY_PASSTHROUGH", "registry.npmjs.org,models.dev"
    ).split(",")
    if h.strip()
}

ALL_ALLOWED = (
    FAKE_RESPONSE_HOSTS
    | set(CREDENTIAL_HOSTS)
    | set(LOCAL_PROVIDER_HOSTS)
    | PASSTHROUGH_HOSTS
)


def fingerprint_token(token: str) -> str:
    """A short, non-reversible, non-secret reference to a credential, safe
    to write to the audit log. Deliberately a full hash (not a masked
    prefix/suffix of the real characters) so it carries zero entropy about
    the actual secret -- it only lets an operator correlate log lines with
    "which configured token was used" (e.g. to confirm rotation took
    effect), never reconstruct or brute-force the credential itself.
    """
    return "sha256:" + hashlib.sha256(token.encode()).hexdigest()[:12]


# host -> non-secret fingerprint of the real token, for audit correlation only.
CREDENTIAL_FINGERPRINTS = {
    host: fingerprint_token(token) for host, token in CREDENTIAL_HOSTS.items()
}

SUCCESS_BODY = (
    b"Congratulations -- you escaped the zero-network sandbox.\n"
    b"This response was served locally by the agents.net host boundary over\n"
    b"a real TLS connection, trusted only because AGENT_CA_CERT was wired\n"
    b"into your runtime's trust store. Every byte of it crossed one Unix\n"
    b"socket as a named HTTP CONNECT tunnel.\n"
    b"No network interface was used to get here.\n"
)


def audit(decision: str, target: str, detail: str = "") -> None:
    """Append one line to the audit trail. `detail` is for non-secret,
    correlatable metadata only (e.g. a credential fingerprint) -- NEVER
    pass a real token, header value, or request/response body here."""
    line = f"{datetime.datetime.now(datetime.timezone.utc).isoformat()} {decision} {target}"
    if detail:
        line += f" {detail}"
    print(f"[boundary] {line}")
    with open(AUDIT_LOG_PATH, "a", encoding="utf-8") as f:
        f.write(line + "\n")


# ---------------------------------------------------------------------------
# HTTP CONNECT codec (RFC 9110 section 9.3.6). CONNECT only -- the
# deliberate minimum: the only way out is a named TCP tunnel. Refusals are
# `403 Forbidden` with a `Boundary-Reason` header, upstream failures `502`.
# ---------------------------------------------------------------------------


def send_response(sock: socket.socket, status: str, reason: str = "") -> None:
    head = f"HTTP/1.1 {status}\r\n"
    if reason:
        head += f"Boundary-Reason: {reason}\r\n"
    head += "Content-Length: 0\r\n\r\n"
    try:
        sock.sendall(head.encode("latin1"))
    except OSError:
        pass


def refuse(sock: socket.socket, reason: str) -> None:
    send_response(sock, "403 Forbidden", reason)


def tunnel_established(sock: socket.socket) -> None:
    sock.sendall(b"HTTP/1.1 200 OK\r\n\r\n")


def read_connect(sock: socket.socket):
    """Read one CONNECT request head. Returns (host, port, is_name) or
    raises ValueError/ConnectionError with the response already sent.
    Lowercases the host: DNS names are case-insensitive and so is the ACL."""
    buf = b""
    while b"\r\n\r\n" not in buf:
        if len(buf) > 8192:
            send_response(sock, "400 Bad Request", "oversized-head")
            raise ValueError("oversized request head")
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("client closed mid-request")
        buf += chunk
    head = buf.partition(b"\r\n\r\n")[0]
    request_line = head.split(b"\r\n", 1)[0].decode("latin1")
    parts = request_line.split()
    if len(parts) != 3 or parts[0].upper() != "CONNECT":
        send_response(sock, "405 Method Not Allowed", "connect-only")
        raise ValueError(f"not a CONNECT request: {request_line!r}")

    authority = parts[1]
    host, sep, port_s = authority.rpartition(":")
    if not sep:
        refuse(sock, "malformed-target")
        raise ValueError(f"no port in authority {authority!r}")
    host = host.strip("[]").lower()  # v6 literals arrive bracketed
    try:
        port = int(port_s)
    except ValueError:
        refuse(sock, "malformed-target")
        raise ValueError(f"bad port in authority {authority!r}")

    is_name = True
    try:
        ipaddress.ip_address(host)
        is_name = False
    except ValueError:
        pass
    return host, port, is_name


# ---------------------------------------------------------------------------
# Flow plumbing shared by the tiers.
# ---------------------------------------------------------------------------


def relay(client_sock, out_sock) -> None:
    """Genuine bidirectional byte relay, used once a flow is established
    (and, for injected flows, once the rewritten request has been sent)."""
    sockets = [client_sock, out_sock]
    while True:
        r, _, _ = select.select(sockets, [], [], 30)
        if not r:
            break
        for s in r:
            other = out_sock if s is client_sock else client_sock
            try:
                chunk = s.recv(8192)
            except OSError:
                return
            if not chunk:
                return
            other.sendall(chunk)


def read_http_message(sock, initial: bytes = b""):
    """Read one HTTP request (headers + body) from sock, starting from any
    bytes already read (`initial`). Returns (request_line, headers, body)
    where headers is a list of (name, value) tuples. Inside a CONNECT
    tunnel the agent believes it is talking directly to the origin server,
    so the inner request line is already origin-form -- nothing to
    rewrite."""
    buf = initial
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
    head, _, rest = buf.partition(b"\r\n\r\n")
    lines = head.decode("latin1").split("\r\n")
    request_line = lines[0] if lines else ""
    headers = []
    for line in lines[1:]:
        if ":" in line:
            k, _, v = line.partition(":")
            headers.append((k.strip(), v.strip()))
    content_length = 0
    for k, v in headers:
        if k.lower() == "content-length":
            try:
                content_length = int(v)
            except ValueError:
                content_length = 0
            break
    body = rest
    while len(body) < content_length:
        chunk = sock.recv(4096)
        if not chunk:
            break
        body += chunk
    return request_line, headers, body


def build_request(request_line: str, headers: list, body: bytes) -> bytes:
    header_block = "".join(f"{k}: {v}\r\n" for k, v in headers)
    return f"{request_line}\r\n{header_block}\r\n".encode("latin1") + body


def inject_auth(request_line: str, headers: list, body: bytes, token: str) -> bytes:
    headers = [(k, v) for k, v in headers if k.lower() != "authorization"]
    headers.append(("Authorization", f"Bearer {token}"))
    return build_request(request_line, headers, body)


def http_response(status_line: bytes, body: bytes) -> bytes:
    return (
        status_line + b"\r\n"
        b"Content-Type: text/plain\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n"
        b"Connection: close\r\n\r\n" + body
    )


def dial_or_reply(client_sock: socket.socket, addr: tuple, target: str):
    """Dial upstream before confirming the tunnel, so a dead backend
    surfaces to the agent as an accurate 502 instead of a broken pipe."""
    try:
        out_sock = socket.create_connection(addr, timeout=15)
    except ConnectionRefusedError:
        print(f"[!] upstream {target} ({addr}) refused")
        send_response(client_sock, "502 Bad Gateway", "upstream-refused")
        return None
    except OSError as exc:
        print(f"[!] upstream {target} ({addr}) unreachable: {exc}")
        send_response(client_sock, "502 Bad Gateway", "upstream-unreachable")
        return None
    tunnel_established(client_sock)
    return out_sock


# ---------------------------------------------------------------------------
# The four tiers.
# ---------------------------------------------------------------------------


def serve_fake(client_sock: socket.socket, target: str, port: int) -> None:
    audit("ALLOW-FAKE", target)
    tunnel_established(client_sock)
    if port == 443:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(MITM_CERT, MITM_KEY)
        tls_sock = ctx.wrap_socket(client_sock, server_side=True)
        try:
            tls_sock.recv(4096)  # drain the client's inner HTTP request
            tls_sock.sendall(http_response(b"HTTP/1.1 200 OK", SUCCESS_BODY))
        finally:
            tls_sock.close()
    else:
        client_sock.recv(4096)
        client_sock.sendall(http_response(b"HTTP/1.1 200 OK", SUCCESS_BODY))


def serve_inject(client_sock: socket.socket, target: str, host: str, port: int, token: str) -> None:
    # NOTE: `token` is the real secret and MUST NEVER be passed to audit()
    # or printed -- only its non-reversible fingerprint is logged.
    audit("ALLOW-INJECT", target, detail=f"cred={CREDENTIAL_FINGERPRINTS.get(host, '?')}")

    if port == 443 and not os.path.exists(MITM_CERT):
        print("[!] no demo MITM cert (run gen_certs.sh) -- refusing")
        audit("BLOCK", target, detail="missing-mitm-cert")
        refuse(client_sock, "missing-mitm-cert")
        return

    tunnel_established(client_sock)
    if port == 443:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(MITM_CERT, MITM_KEY)
        agent_side = ctx.wrap_socket(client_sock, server_side=True)
    else:
        agent_side = client_sock
    try:
        request_line, headers, body = read_http_message(agent_side)
        if not request_line:
            return
        out_request = inject_auth(request_line, headers, body, token)
        with socket.create_connection((host, port), timeout=15) as raw:
            if port == 443:
                upstream_ctx = ssl.create_default_context()  # verify against the REAL trust store
                with upstream_ctx.wrap_socket(raw, server_hostname=host) as upstream:
                    upstream.sendall(out_request)
                    relay(agent_side, upstream)
            else:
                raw.sendall(out_request)
                relay(agent_side, raw)
    finally:
        if agent_side is not client_sock:
            agent_side.close()


def serve_local_provider(client_sock: socket.socket, target: str, real_addr: tuple) -> None:
    """Genuine relay to a local model provider (e.g. Ollama) on the
    operator's own machine. No TLS termination, no credential injection --
    just a plain byte relay to the real address the boundary maps the
    sandbox's symbolic hostname to."""
    audit("ALLOW-LOCAL", target)
    out_sock = dial_or_reply(client_sock, real_addr, target)
    if out_sock is None:
        return
    try:
        relay(client_sock, out_sock)
    finally:
        out_sock.close()


def serve_passthrough(client_sock: socket.socket, target: str, host: str, port: int) -> None:
    """Genuine, uninspected relay: no TLS termination, no injection. The
    agent's own TLS session runs straight through to the real server."""
    audit("ALLOW-PASSTHROUGH", target)
    out_sock = dial_or_reply(client_sock, (host, port), target)
    if out_sock is None:
        return
    try:
        relay(client_sock, out_sock)
    finally:
        out_sock.close()


# ---------------------------------------------------------------------------
# Dispatch: one flow, one name, one decision.
# ---------------------------------------------------------------------------


def handle(client_sock: socket.socket) -> None:
    try:
        host, port, is_name = read_connect(client_sock)
    except (ValueError, ConnectionError, OSError):
        return  # response (if any) already sent

    target = f"{host}:{port}"
    if not is_name:
        # Policy reasons about names. A literal address means the agent
        # bypassed the resolver, so there is no name to authorize.
        audit("BLOCK-IP-LITERAL", target)
        refuse(client_sock, "ip-literal")
        return

    if host in FAKE_RESPONSE_HOSTS:
        serve_fake(client_sock, target, port)
    elif host in CREDENTIAL_HOSTS:
        serve_inject(client_sock, target, host, port, CREDENTIAL_HOSTS[host])
    elif host in LOCAL_PROVIDER_HOSTS:
        serve_local_provider(client_sock, target, LOCAL_PROVIDER_HOSTS[host])
    elif host in PASSTHROUGH_HOSTS:
        serve_passthrough(client_sock, target, host, port)
    else:
        audit("BLOCK", target)
        refuse(client_sock, "not-on-allowlist")


# ---------------------------------------------------------------------------
# Ingress: public port -> launcher's ingress socket -> agent's loopback.
# ---------------------------------------------------------------------------


def handle_ingress() -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind(("0.0.0.0", PUBLIC_INGRESS_PORT))
    except OSError as e:
        print(f"[!] Ingress Gateway bind error on port {PUBLIC_INGRESS_PORT}: {e}")
        return
    server.listen(32)
    print(f"[*] Ingress Gateway listening on public port: {PUBLIC_INGRESS_PORT}")

    while True:
        try:
            client_sock, _ = server.accept()
        except OSError:
            break
        threading.Thread(target=_handle_ingress_conn, args=(client_sock,), daemon=True).start()


def _dial_sandbox(port: int) -> socket.socket:
    """The Firecracker hybrid-vsock handshake the launcher serves: connect,
    send "CONNECT <port>", read "OK". An "ERR ..." line is a refusal."""
    agent_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    agent_sock.settimeout(10)
    agent_sock.connect(INGRESS_UDS)
    agent_sock.sendall(f"CONNECT {port}\n".encode())
    line = b""
    while not line.endswith(b"\n"):
        chunk = agent_sock.recv(1)
        if not chunk:
            raise ConnectionError("launcher closed during ingress handshake")
        line += chunk
        if len(line) > 64:
            raise ConnectionError("oversized ingress handshake reply")
    if not line.startswith(b"OK"):
        raise ConnectionError(f"ingress refused: {line.decode(errors='replace').strip()}")
    agent_sock.settimeout(None)
    return agent_sock


def _handle_ingress_conn(client_sock: socket.socket) -> None:
    try:
        data = client_sock.recv(4096)
        if not data:
            return

        req_line = data.decode("latin1").split("\r\n")[0]
        audit("INGRESS", req_line)

        agent_sock = _dial_sandbox(AGENT_INGRESS_PORT)
        try:
            agent_sock.sendall(data)
            relay(client_sock, agent_sock)
        finally:
            agent_sock.close()
    except Exception as e:
        print(f"[INGRESS ERROR] Is the agent listening? {e}")
        try:
            client_sock.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\nAgent Unreachable")
        except OSError:
            pass
    finally:
        try:
            client_sock.close()
        except OSError:
            pass


def main() -> None:
    os.makedirs(SOCKET_DIR, exist_ok=True)
    if os.path.exists(EGRESS_UDS):
        os.unlink(EGRESS_UDS)
    # The launcher binds the ingress socket from inside the sandbox; a stale
    # file from a previous run would make that bind fail.
    if os.path.exists(INGRESS_UDS):
        os.unlink(INGRESS_UDS)

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(EGRESS_UDS)
    os.chmod(EGRESS_UDS, 0o777)
    server.listen(32)

    print(f"[*] Host Boundary (HTTP CONNECT) listening on: {EGRESS_UDS}")
    print(f"[*] Fake-response allow-list: {sorted(FAKE_RESPONSE_HOSTS)}")
    print(f"[*] Local-provider allow-list: {LOCAL_PROVIDER_HOSTS}")
    print(f"[*] Credential-inject allow-list: {CREDENTIAL_FINGERPRINTS}")
    print(f"[*] Passthrough allow-list: {sorted(PASSTHROUGH_HOSTS)}")
    print(f"[*] Audit log: {AUDIT_LOG_PATH}")

    threading.Thread(target=handle_ingress, daemon=True).start()

    def _serve(client_sock: socket.socket) -> None:
        try:
            handle(client_sock)
        except Exception as exc:
            print(f"[!] error handling flow: {exc}")
        finally:
            try:
                client_sock.close()
            except OSError:
                pass

    # One thread per flow: with the launcher, every TCP connection in the
    # sandbox is its own CONNECT tunnel, and several are open at once.
    while True:
        client_sock, _ = server.accept()
        threading.Thread(target=_serve, args=(client_sock,), daemon=True).start()


if __name__ == "__main__":
    main()
