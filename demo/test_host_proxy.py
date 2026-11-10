#!/usr/bin/env python3
"""Unit tests for demo/host_proxy.py -- the HTTP CONNECT boundary.

The codec and dispatch tests drive a real server thread over a real Unix
socket in a temp dir: the boundary's contract is a wire protocol, so the
tests speak the wire protocol.
"""

import os
import socket
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# Add demo directory to sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import host_proxy


def read_response_head(sock: socket.socket):
    """Read one HTTP response head; returns (status_code, headers dict)."""
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
    head = buf.partition(b"\r\n\r\n")[0].decode("latin1")
    lines = head.split("\r\n")
    status = int(lines[0].split()[1])
    headers = {}
    for line in lines[1:]:
        name, _, value = line.partition(":")
        headers[name.strip().lower()] = value.strip()
    if "proxy-status" in headers:
        headers["reason"] = host_proxy.proxy_status_reason(headers["proxy-status"])
    return status, headers


def connect_request(sock: socket.socket, authority: str):
    """Send `CONNECT <authority>` and read the response head."""
    sock.sendall(
        f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n".encode()
    )
    return read_response_head(sock)


class BoundaryTestCase(unittest.TestCase):
    """Runs handle() against a real socketpair-backed listener."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.socket_path = os.path.join(self.tmp.name, "egress.sock")
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server.bind(self.socket_path)
        self.server.listen(4)
        self.addCleanup(self.server.close)
        self.addCleanup(self.tmp.cleanup)
        # Keep test runs from writing to the real audit path.
        self._audit = host_proxy.AUDIT_LOG_PATH
        host_proxy.AUDIT_LOG_PATH = os.path.join(self.tmp.name, "audit.log")
        self.addCleanup(setattr, host_proxy, "AUDIT_LOG_PATH", self._audit)

    def connect(self) -> socket.socket:
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.settimeout(5)
        client.connect(self.socket_path)
        server_side, _ = self.server.accept()

        def serve():
            try:
                host_proxy.handle(server_side)
            finally:
                server_side.close()

        t = threading.Thread(target=serve, daemon=True)
        t.start()
        # LIFO: close the client first so a relaying handler sees EOF and the
        # join below returns immediately instead of waiting out its timeout.
        self.addCleanup(t.join, 5)
        self.addCleanup(client.close)
        return client

    def test_unknown_host_is_refused_with_403(self):
        client = self.connect()
        status, headers = connect_request(client, "evil.example:443")
        self.assertEqual(status, 403)
        self.assertEqual(headers.get("reason"), "not-on-allowlist")
        self.assertIn("error=http_request_denied", headers.get("proxy-status", ""))

    def test_ipv4_literal_is_refused(self):
        client = self.connect()
        status, headers = connect_request(client, "1.2.3.4:443")
        self.assertEqual(status, 403)
        self.assertEqual(headers.get("reason"), "ip-literal")

    def test_ipv6_literal_is_refused(self):
        client = self.connect()
        status, headers = connect_request(client, "[2001:db8::1]:443")
        self.assertEqual(status, 403)
        self.assertEqual(headers.get("reason"), "ip-literal")

    def test_non_connect_method_is_refused_with_405(self):
        client = self.connect()
        client.sendall(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        status, headers = read_response_head(client)
        self.assertEqual(status, 405)
        self.assertEqual(headers.get("reason"), "connect-only")

    def test_missing_port_is_refused(self):
        client = self.connect()
        status, headers = connect_request(client, "example.com")
        self.assertEqual(status, 403)
        self.assertEqual(headers.get("reason"), "malformed-target")

    def test_host_names_are_case_insensitive(self):
        client = self.connect()
        status, _ = connect_request(client, "EXAMPLE.COM:80")
        self.assertEqual(status, 200)

    def test_fake_host_serves_canned_response_on_port_80(self):
        client = self.connect()
        status, _ = connect_request(client, "example.com:80")
        self.assertEqual(status, 200)
        client.sendall(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        data = b""
        while True:
            try:
                chunk = client.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            data += chunk
        self.assertIn(b"HTTP/1.1 200 OK", data)
        self.assertIn(b"escaped the zero-network sandbox", data)

    def test_local_provider_relays_to_real_backend(self):
        backend = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        backend.bind(("127.0.0.1", 0))
        backend.listen(1)
        self.addCleanup(backend.close)
        port = backend.getsockname()[1]

        original = dict(host_proxy.LOCAL_PROVIDER_HOSTS)
        host_proxy.LOCAL_PROVIDER_HOSTS["fakeollama"] = ("127.0.0.1", port)
        self.addCleanup(
            lambda: (host_proxy.LOCAL_PROVIDER_HOSTS.clear(),
                     host_proxy.LOCAL_PROVIDER_HOSTS.update(original))
        )

        client = self.connect()
        status, _ = connect_request(client, "fakeollama:11434")
        self.assertEqual(status, 200)

        upstream, _ = backend.accept()
        self.addCleanup(upstream.close)
        client.sendall(b"ping")
        self.assertEqual(upstream.recv(4), b"ping")
        upstream.sendall(b"pong")
        self.assertEqual(client.recv(4), b"pong")

    def test_dead_local_provider_reports_502(self):
        # Bind and close to get a port that is certainly not listening.
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.bind(("127.0.0.1", 0))
        dead_port = probe.getsockname()[1]
        probe.close()

        original = dict(host_proxy.LOCAL_PROVIDER_HOSTS)
        host_proxy.LOCAL_PROVIDER_HOSTS["deadollama"] = ("127.0.0.1", dead_port)
        self.addCleanup(
            lambda: (host_proxy.LOCAL_PROVIDER_HOSTS.clear(),
                     host_proxy.LOCAL_PROVIDER_HOSTS.update(original))
        )

        client = self.connect()
        status, headers = connect_request(client, "deadollama:11434")
        self.assertEqual(status, 502)
        self.assertEqual(headers.get("reason"), "upstream-refused")


class ConfigTestCase(unittest.TestCase):

    def test_fingerprint_token(self):
        fp = host_proxy.fingerprint_token("test-secret-token")
        self.assertTrue(fp.startswith("sha256:"))
        self.assertEqual(len(fp), 7 + 12)  # "sha256:" + 12 hex chars

    def test_load_credential_hosts(self):
        os.environ["TEST_SECRET_VAR"] = "my-secret-key"
        os.environ["AGENT_PROXY_TOKENS"] = "api.openai.com=TEST_SECRET_VAR,api.anthropic.com=UNSET_VAR"
        hosts = host_proxy._load_credential_hosts()
        self.assertIn("api.openai.com", hosts)
        self.assertEqual(hosts["api.openai.com"], "my-secret-key")
        self.assertNotIn("api.anthropic.com", hosts)

    def test_load_local_providers(self):
        os.environ["AGENT_PROXY_LOCAL_PROVIDERS"] = "ollama=127.0.0.1:11434, custom=localhost:8080"
        providers = host_proxy._load_local_providers()
        self.assertEqual(providers["ollama"], ("127.0.0.1", 11434))
        self.assertEqual(providers["custom"], ("localhost", 8080))

    def test_http_response(self):
        resp = host_proxy.http_response(b"HTTP/1.1 200 OK", b"Hello World")
        self.assertTrue(resp.startswith(b"HTTP/1.1 200 OK\r\n"))
        self.assertIn(b"Content-Length: 11\r\n", resp)
        self.assertTrue(resp.endswith(b"Hello World"))

    def test_inject_auth_replaces_placeholder(self):
        fields = host_proxy.inject_auth(
            [("Host", "api.openai.com"), ("authorization", "Bearer placeholder")],
            "real-token",
        )
        self.assertEqual(
            fields, [("Host", "api.openai.com"), ("Authorization", "Bearer real-token")]
        )


class RecordingBackend(BaseHTTPRequestHandler):
    """An HTTP/1.1 upstream that answers with what it received."""

    protocol_version = "HTTP/1.1"

    def do_GET(self):
        self.server.seen.append(
            (self.command, self.path, self.headers.get("Authorization"))
        )
        if self.path == "/stream":
            self.send_response(200)
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            for part in (b"first ", b"second"):
                self.wfile.write(b"%x\r\n%s\r\n" % (len(part), part))
            self.wfile.write(b"0\r\n\r\n")
            return
        body = self.headers.get("Authorization", "").encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        self.server.seen.append(
            (self.command, self.path, self.headers.get("Authorization"))
        )
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class InjectTestCase(BoundaryTestCase):
    """The credential-inject tier over plain HTTP, which takes the same
    per-request path as the TLS-terminated one."""

    def setUp(self):
        super().setUp()
        self.backend = ThreadingHTTPServer(("127.0.0.1", 0), RecordingBackend)
        self.backend.seen = []
        threading.Thread(target=self.backend.serve_forever, daemon=True).start()
        self.addCleanup(self.backend.server_close)
        self.addCleanup(self.backend.shutdown)
        self.port = self.backend.server_address[1]
        self.authority = f"localhost:{self.port}"
        original = dict(host_proxy.CREDENTIAL_HOSTS)
        host_proxy.CREDENTIAL_HOSTS["localhost"] = "real-token"
        self.addCleanup(
            lambda: (
                host_proxy.CREDENTIAL_HOSTS.clear(),
                host_proxy.CREDENTIAL_HOSTS.update(original),
            )
        )

    def tunnel(self):
        client = self.connect()
        status, _ = connect_request(client, self.authority)
        self.assertEqual(status, 200)
        return client, host_proxy.Reader(client)

    def exchange(self, client, reader, request: bytes):
        client.sendall(request)
        status_line, fields = host_proxy.parse_head(reader.head())
        framing = host_proxy.body_framing(fields)

        class Sink:
            data = b""

            def sendall(self, b):
                self.data += b

        sink = Sink()
        host_proxy.copy_body(reader, sink, framing)
        return int(status_line.split(" ")[1]), sink.data

    def test_every_request_on_a_reused_connection_gets_the_credential(self):
        client, reader = self.tunnel()
        for _ in range(2):
            status, body = self.exchange(
                client,
                reader,
                (
                    f"GET /v1/models HTTP/1.1\r\nHost: {self.authority}\r\n"
                    "Authorization: Bearer placeholder\r\n\r\n"
                ).encode(),
            )
            self.assertEqual((status, body), (200, b"Bearer real-token"))
        status, body = self.exchange(
            client,
            reader,
            (
                f"POST /v1/chat HTTP/1.1\r\nHost: {self.authority}\r\n"
                "Content-Length: 5\r\n\r\nhello"
            ).encode(),
        )
        self.assertEqual((status, body), (200, b"hello"))
        self.assertEqual(
            self.backend.seen,
            [
                ("GET", "/v1/models", "Bearer real-token"),
                ("GET", "/v1/models", "Bearer real-token"),
                ("POST", "/v1/chat", "Bearer real-token"),
            ],
        )

    def test_chunked_response_is_streamed(self):
        client, reader = self.tunnel()
        status, body = self.exchange(
            client,
            reader,
            (f"GET /stream HTTP/1.1\r\nHost: {self.authority}\r\n\r\n").encode(),
        )
        self.assertEqual(status, 200)
        self.assertEqual(body, b"6\r\nfirst \r\n6\r\nsecond\r\n0\r\n\r\n")

    def test_refused_requests_get_no_credential(self):
        tests = [
            (
                "another host",
                f"GET / HTTP/1.1\r\nHost: other.example:{self.port}\r\n\r\n",
                421,
            ),
            ("another port", "GET / HTTP/1.1\r\nHost: localhost:1\r\n\r\n", 421),
            ("no host", "GET / HTTP/1.1\r\n\r\n", 400),
            (
                "two hosts",
                f"GET / HTTP/1.1\r\nHost: {self.authority}\r\nHost: {self.authority}\r\n\r\n",
                400,
            ),
            (
                "absolute form",
                f"GET http://other.example/ HTTP/1.1\r\nHost: {self.authority}\r\n\r\n",
                400,
            ),
            (
                "upgrade",
                f"GET / HTTP/1.1\r\nHost: {self.authority}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
                501,
            ),
            (
                "two framings",
                f"POST / HTTP/1.1\r\nHost: {self.authority}\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
                400,
            ),
        ]
        for name, request, want in tests:
            with self.subTest(name):
                client, reader = self.tunnel()
                status, _ = self.exchange(client, reader, request.encode())
                self.assertEqual(status, want)
                self.assertEqual(client.recv(1), b"")
        self.assertEqual(self.backend.seen, [])

    def test_refusal_after_an_allowed_request_closes_the_tunnel(self):
        client, reader = self.tunnel()
        status, _ = self.exchange(
            client,
            reader,
            (f"GET / HTTP/1.1\r\nHost: {self.authority}\r\n\r\n").encode(),
        )
        self.assertEqual(status, 200)
        status, _ = self.exchange(
            client,
            reader,
            (f"GET / HTTP/1.1\r\nHost: other.example:{self.port}\r\n\r\n").encode(),
        )
        self.assertEqual(status, 421)
        self.assertEqual(len(self.backend.seen), 1)


if __name__ == "__main__":
    unittest.main()
