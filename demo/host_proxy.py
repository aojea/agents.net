#!/usr/bin/env python3
"""Host-side agents.net demo proxy.

Responsibilities, on purpose kept in one small file so the whole ACL/audit
story is auditable at a glance:

1. Bridges the sandboxed agent (talking HTTP CONNECT over a Unix Domain
   Socket) out to the world -- but only to an explicit allow-list.
2. Anything not on the allow-list is BLOCKED and logged, and the agent is
   told why via a normal HTTP 403 response (in-band, standard semantics)
   rather than a silent hang or connection reset.
3. Every request -- allowed or blocked -- is written to an audit log, the
   kind of auditing/DLP hook called out in the Trust Contract section.
4. The allow-list has four tiers:
   - FAKE_RESPONSE_HOSTS (the demo's task target, example.com) are NOT
     forwarded anywhere. This proxy terminates TLS locally using a
     certificate signed by the demo CA (see gen_certs.sh) and returns a
     canned success response. This keeps that part of the demo
     deterministic and network-independent, while still requiring the
     agent to complete a real, encrypted HTTPS request that only validates
     because of the mounted `AGENT_CA_CERT` (the Trust Contract).
   - LOCAL_PROVIDER_HOSTS (default: a local Ollama server) let the sandbox
     reach a model backend running on the OPERATOR's own machine, by a
     purely symbolic hostname (e.g. "ollama") it can never resolve or
     route to on its own -- the container has no network at all. Only the
     proxy knows the real loopback address. No secret is involved (Ollama
     accepts any API key), so this is genuinely relayed byte-for-byte with
     no TLS termination -- see AGENT_PROXY_LOCAL_PROVIDERS below. This is
     what makes the reference demo runnable end-to-end for free, with no
     cloud subscription and no vendor lock-in.
   - CREDENTIAL_HOSTS are a real cloud model backend the harness needs to
     reach to reason at all (e.g. api.openai.com) -- opt-in, for anyone
     who wants to swap the free local model for a paid one. These are
     genuinely relayed to the real internet, but this proxy *also*
     terminates TLS for them and injects the real `Authorization` header
     itself, sourced only from the HOST's own environment (see
     AGENT_PROXY_TOKENS below). The sandboxed agent is never given the
     real credential -- it can hold an empty or placeholder value, or none
     at all. This decouples the agent from the secret entirely: an admin
     can mint, scope, and revoke a distinct token per sandbox instance
     without ever baking a real secret into the sandboxed image, its
     environment, or its filesystem, shrinking the credential's blast
     radius to "whatever this one proxy process was handed." Notice that
     switching from the local model to a real cloud one changes nothing
     about the sandbox, the Dockerfile, or the `docker run` command --
     only this host-side proxy config and the harness's own config file.
   - PASSTHROUGH_HOSTS (see AGENT_PROXY_PASSTHROUGH below; default:
     registry.npmjs.org, which OpenCode needs the first time it lazily
     installs an AI SDK provider package) are hosts the harness needs for
     its own housekeeping -- package installs, update checks, telemetry --
     that carry no secret and need no canned response. These are
     genuinely relayed byte-for-byte with NO TLS termination on our end at
     all: the agent's own TLS session runs straight through the tunnel to
     the real server, verified against the container's own system trust
     store. Nothing to inject or fake here, just real, unmodified bytes to
     an allow-listed destination.
"""
import datetime
import hashlib
import os
import select
import socket
import ssl
import threading
import urllib.parse

SOCKET_DIR = "/tmp/agent-sockets"
EGRESS_UDS = f"{SOCKET_DIR}/egress-proxy.sock"
INGRESS_UDS = f"{SOCKET_DIR}/ingress-proxy.sock"
PUBLIC_INGRESS_PORT = int(os.environ.get("PUBLIC_INGRESS_PORT", 9000))

UDS_PATH = EGRESS_UDS
AUDIT_LOG_PATH = "/tmp/agent-proxy-audit.log"

CERT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "certs")
# A single leaf cert with a SAN entry per MITM'd host (see gen_certs.sh),
# used for both fake-response and credential-inject TLS termination.
MITM_CERT = os.path.join(CERT_DIR, "agent-mitm.pem")
MITM_KEY = os.path.join(CERT_DIR, "agent-mitm.key")


# Tier 1: the demo's actual task target. Answered locally, never forwarded.
FAKE_RESPONSE_HOSTS = {"example.com", "httpbin.org"}


def _load_credential_hosts() -> dict:
    """Tier 2: hosts genuinely relayed to the real internet, with the real
    bearer token injected by the proxy itself.

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
    """Local model providers (e.g. Ollama) the sandbox reaches by a purely
    symbolic hostname it can never resolve or route to on its own -- the
    container has no network. The proxy is the only thing that knows the
    real address, exactly mirroring how it -- not the sandbox -- holds the
    real credential for CREDENTIAL_HOSTS. No secret is involved here:
    Ollama's OpenAI-compatible API accepts any API key string.

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
# credential injection nor a local-address rewrite (e.g. OpenCode's own
# npm-registry pull the first time it lazily installs an AI SDK provider
# package -- see https://opencode.ai/docs/troubleshooting). Configured via
# AGENT_PROXY_PASSTHROUGH, a comma-separated list of hostnames. Unlike
# CREDENTIAL_HOSTS, no token or env var is involved -- these are just
# allow-listed for genuine, uninspected egress. Leave this empty
# (AGENT_PROXY_PASSTHROUGH="") to instead BLOCK and audit these hosts, which
# is equally valid and demonstrates the ACL catching unexpected egress
PASSTHROUGH_HOSTS = {
    h.strip()
    for h in os.environ.get(
        "AGENT_PROXY_PASSTHROUGH", "registry.npmjs.org"
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
    b"This response was served locally by the agents.net host proxy over a\n"
    b"real TLS connection, trusted only because AGENT_CA_CERT (the Trust\n"
    b"Contract) was mounted into the sandbox and wired into your runtime's\n"
    b"trust store. No direct network interface was used to get here.\n"
)


def audit(decision: str, method: str, target: str, detail: str = "") -> None:
    """Append one line to the audit trail. `detail` is for non-secret,
    correlatable metadata only (e.g. a credential fingerprint) -- NEVER
    pass a real token, header value, or request/response body here."""
    line = f"{datetime.datetime.now(datetime.timezone.utc).isoformat()} {decision} {method} {target}"
    if detail:
        line += f" {detail}"
    print(f"[proxy] {line}")
    with open(AUDIT_LOG_PATH, "a") as f:
        f.write(line + "\n")


def http_response(status_line: bytes, body: bytes) -> bytes:
    return (
        status_line + b"\r\n"
        b"Content-Type: text/plain\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n"
        b"Connection: close\r\n\r\n" + body
    )


def deny(client_sock: socket.socket, method: str, target: str, host: str) -> None:
    audit("BLOCK", method, target)
    body = (
        f"Blocked by agents.net sandbox ACL: host '{host}' is not on the "
        f"allow-list ({sorted(ALL_ALLOWED)}).\n"
    ).encode()
    try:
        client_sock.sendall(http_response(b"HTTP/1.1 403 Forbidden", body))
    except OSError:
        pass


def relay(client_sock, out_sock) -> None:
    """Genuine bidirectional byte relay, used once the initial (possibly
    header-rewritten) request has already been forwarded upstream."""
    sockets = [client_sock, out_sock]
    while True:
        r, _, _ = select.select(sockets, [], [], 30)
        if not r:
            break
        for s in r:
            other = out_sock if s is client_sock else client_sock
            chunk = s.recv(8192)
            if not chunk:
                return
            other.sendall(chunk)


def read_http_message(sock, initial: bytes = b""):
    """Read one HTTP request (headers + body) from sock, starting from any
    bytes already read (`initial`). Returns (request_line, headers, body)
    where headers is a list of (name, value) tuples."""
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


def to_origin_form(request_line: str) -> str:
    """Rewrite a proxy-style absolute-form request line ("GET
    http://host:port/path HTTP/1.1", what a client sends when it's
    configured with an HTTP proxy) into origin-form ("GET /path HTTP/1.1")
    -- what a normal origin server (not itself a proxy) expects. Required
    whenever this proxy relays a plain (non-CONNECT) request directly to a
    real backend instead of hopping to another proxy.
    """
    parts = request_line.split(" ")
    if len(parts) != 3:
        return request_line
    method, target, version = parts
    if target.startswith("http://") or target.startswith("https://"):
        parsed = urllib.parse.urlparse(target)
        target = parsed.path or "/"
        if parsed.query:
            target += "?" + parsed.query
    return f"{method} {target} {version}"


def build_request(request_line: str, headers: list, body: bytes) -> bytes:
    """Reassemble a (possibly rewritten) request line + headers + body into
    the raw bytes to send upstream, always in origin-form."""
    request_line = to_origin_form(request_line)
    header_block = "".join(f"{k}: {v}\r\n" for k, v in headers)
    return f"{request_line}\r\n{header_block}\r\n".encode("latin1") + body


def inject_auth(request_line: str, headers: list, body: bytes, token: str) -> bytes:
    headers = [(k, v) for k, v in headers if k.lower() != "authorization"]
    headers.append(("Authorization", f"Bearer {token}"))
    return build_request(request_line, headers, body)


def serve_fake_connect(client_sock: socket.socket, method: str, target: str) -> None:
    audit("ALLOW-FAKE", method, target)
    client_sock.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(MITM_CERT, MITM_KEY)
    tls_sock = ctx.wrap_socket(client_sock, server_side=True)
    try:
        tls_sock.recv(4096)  # drain the client's inner HTTP request
        tls_sock.sendall(http_response(b"HTTP/1.1 200 OK", SUCCESS_BODY))
    finally:
        tls_sock.close()


def serve_fake_plain(client_sock: socket.socket, method: str, target: str) -> None:
    audit("ALLOW-FAKE", method, target)
    client_sock.sendall(http_response(b"HTTP/1.1 200 OK", SUCCESS_BODY))


def serve_inject_connect(client_sock: socket.socket, method: str, target: str, token: str) -> None:
    host, _, port_s = target.partition(":")
    port = int(port_s) if port_s else 443
    # NOTE: `token` is the real secret and MUST NEVER be passed to audit()
    # or printed -- only its non-reversible fingerprint is logged.
    audit("ALLOW-INJECT", method, target, detail=f"cred={CREDENTIAL_FINGERPRINTS.get(host, '?')}")

    if not os.path.exists(MITM_CERT):
        print("[!] no demo MITM cert (run gen_certs.sh) -- blocking")
        deny(client_sock, method, target, host)
        return

    client_sock.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(MITM_CERT, MITM_KEY)
    tls_sock = ctx.wrap_socket(client_sock, server_side=True)
    try:
        request_line, headers, body = read_http_message(tls_sock)
        if not request_line:
            return
        out_request = inject_auth(request_line, headers, body, token)

        upstream_ctx = ssl.create_default_context()  # verify against the REAL trust store
        with socket.create_connection((host, port), timeout=15) as raw:
            with upstream_ctx.wrap_socket(raw, server_hostname=host) as upstream:
                upstream.sendall(out_request)
                relay(tls_sock, upstream)
    finally:
        tls_sock.close()


def serve_local_provider_connect(client_sock: socket.socket, method: str, target: str, real_addr: tuple) -> None:
    """Genuine relay to a local model provider (e.g. Ollama) running on the
    operator's own machine. No MITM, no credential injection -- just a
    plain byte relay to the real address the proxy maps the sandbox's
    symbolic hostname to."""
    audit("ALLOW-LOCAL", method, target)
    try:
        out_sock = socket.create_connection(real_addr, timeout=15)
    except OSError as exc:
        print(f"[!] local-provider CONNECT to {target} ({real_addr}) failed: {exc}")
        try:
            client_sock.sendall(
                http_response(b"HTTP/1.1 502 Bad Gateway", b"local provider unreachable\n")
            )
        except OSError:
            pass
        return
    try:
        client_sock.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        relay(client_sock, out_sock)
    finally:
        out_sock.close()


def serve_local_provider_plain(client_sock: socket.socket, method: str, target: str, real_addr: tuple, initial: bytes) -> None:
    audit("ALLOW-LOCAL", method, target)
    request_line, headers, body = read_http_message(client_sock, initial=initial)
    out_request = build_request(request_line, headers, body)
    out_sock = socket.create_connection(real_addr, timeout=15)
    try:
        out_sock.sendall(out_request)
        relay(client_sock, out_sock)
    finally:
        out_sock.close()


def serve_passthrough_connect(client_sock: socket.socket, method: str, target: str) -> None:
    """Genuine, uninspected relay: no MITM, no credential injection. Used
    for hosts the harness needs for its own housekeeping (update checks,
    telemetry, auth pings) that carry no secret and need no canned
    response -- just real, unmodified bytes to the real host."""
    audit("ALLOW-PASSTHROUGH", method, target)
    host, _, port_s = target.partition(":")
    port = int(port_s) if port_s else 443
    try:
        out_sock = socket.create_connection((host, port), timeout=15)
    except OSError as exc:
        print(f"[!] passthrough CONNECT to {target} failed: {exc}")
        try:
            client_sock.sendall(
                http_response(b"HTTP/1.1 502 Bad Gateway", b"upstream connect failed\n")
            )
        except OSError:
            pass
        return
    try:
        client_sock.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        relay(client_sock, out_sock)
    finally:
        out_sock.close()


def serve_passthrough_plain(client_sock: socket.socket, method: str, target: str, initial: bytes) -> None:
    audit("ALLOW-PASSTHROUGH", method, target)
    url = urllib.parse.urlparse(target)
    host = url.hostname
    port = url.port or 80
    request_line, headers, body = read_http_message(client_sock, initial=initial)
    out_request = build_request(request_line, headers, body)
    out_sock = socket.create_connection((host, port), timeout=15)
    try:
        out_sock.sendall(out_request)
        relay(client_sock, out_sock)
    finally:
        out_sock.close()


def serve_inject_plain(client_sock: socket.socket, method: str, target: str, token: str, initial: bytes) -> None:
    url = urllib.parse.urlparse(target)
    host = url.hostname
    port = url.port or 80
    # NOTE: `token` is the real secret and MUST NEVER be passed to audit()
    # or printed -- only its non-reversible fingerprint is logged.
    audit("ALLOW-INJECT", method, target, detail=f"cred={CREDENTIAL_FINGERPRINTS.get(host, '?')}")
    request_line, headers, body = read_http_message(client_sock, initial=initial)
    out_request = inject_auth(request_line, headers, body, token)
    out_sock = socket.create_connection((host, port), timeout=15)
    try:
        out_sock.sendall(out_request)
        relay(client_sock, out_sock)
    finally:
        out_sock.close()


def handle(client_sock: socket.socket) -> None:
    data = client_sock.recv(4096)
    if not data:
        return
    req_line = data.decode("latin1").split("\r\n")[0]
    parts = req_line.split(" ")
    if len(parts) < 2:
        return
    method, target = parts[0], parts[1]

    if method == "CONNECT":
        host = target.split(":")[0]
        if host in FAKE_RESPONSE_HOSTS:
            serve_fake_connect(client_sock, method, target)
        elif host in CREDENTIAL_HOSTS:
            serve_inject_connect(client_sock, method, target, CREDENTIAL_HOSTS[host])
        elif host in LOCAL_PROVIDER_HOSTS:
            serve_local_provider_connect(client_sock, method, target, LOCAL_PROVIDER_HOSTS[host])
        elif host in PASSTHROUGH_HOSTS:
            serve_passthrough_connect(client_sock, method, target)
        else:
            deny(client_sock, method, target, host)
        return

    url = urllib.parse.urlparse(target)
    host = url.hostname or ""
    if host in FAKE_RESPONSE_HOSTS:
        serve_fake_plain(client_sock, method, target)
    elif host in CREDENTIAL_HOSTS:
        serve_inject_plain(client_sock, method, target, CREDENTIAL_HOSTS[host], data)
    elif host in LOCAL_PROVIDER_HOSTS:
        serve_local_provider_plain(client_sock, method, target, LOCAL_PROVIDER_HOSTS[host], data)
    elif host in PASSTHROUGH_HOSTS:
        serve_passthrough_plain(client_sock, method, target, data)
    else:
        deny(client_sock, method, target, host)


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


def _handle_ingress_conn(client_sock: socket.socket) -> None:
    try:
        data = client_sock.recv(4096)
        if not data:
            return

        req_line = data.decode("latin1").split("\r\n")[0]
        parts = req_line.split(" ")
        method = parts[0] if len(parts) > 0 else "UNKNOWN"
        target = parts[1] if len(parts) > 1 else "/"

        print(f"[INGRESS] {req_line}")
        audit("INGRESS", method, target)

        if not os.path.exists(INGRESS_UDS):
            raise FileNotFoundError(f"Ingress socket {INGRESS_UDS} does not exist")

        agent_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        agent_sock.connect(INGRESS_UDS)
        agent_sock.sendall(data)

        while True:
            chunk = agent_sock.recv(8192)
            if not chunk:
                break
            client_sock.sendall(chunk)
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

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(EGRESS_UDS)
    os.chmod(EGRESS_UDS, 0o777)
    server.listen(32)

    print(f"[*] Host Proxy listening on: {EGRESS_UDS}")
    print(f"[*] Ingress Gateway listening on public port: {PUBLIC_INGRESS_PORT}")
    print(f"[*] Fake-response allow-list: {sorted(FAKE_RESPONSE_HOSTS)}")
    print(f"[*] Local-provider allow-list: {LOCAL_PROVIDER_HOSTS}")
    print(f"[*] Credential-inject allow-list: {CREDENTIAL_FINGERPRINTS}")
    print(f"[*] Passthrough allow-list: {sorted(PASSTHROUGH_HOSTS)}")
    print(f"[*] Audit log: {AUDIT_LOG_PATH}")

    threading.Thread(target=handle_ingress, daemon=True).start()

    while True:
        client_sock, _ = server.accept()
        try:
            handle(client_sock)
        except Exception as exc:
            print(f"[!] error handling connection: {exc}")
        finally:
            client_sock.close()


if __name__ == "__main__":
    main()

