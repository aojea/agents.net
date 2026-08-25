#!/usr/bin/env python3
"""Unit tests for demo/host_proxy.py -- the SOCKS5 boundary.

The codec and dispatch tests drive a real server thread over a real Unix
socket in a temp dir: the boundary's contract is a wire protocol, so the
tests speak the wire protocol.
"""

import os
import socket
import struct
import sys
import tempfile
import threading
import unittest

# Add demo directory to sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import host_proxy


def socks5_request(sock: socket.socket, host: str, port: int) -> int:
    """Greeting + CONNECT for a domain-name destination; returns REP."""
    sock.sendall(b"\x05\x01\x00")
    assert sock.recv(2) == b"\x05\x00"
    req = (
        b"\x05\x01\x00\x03"
        + bytes([len(host)])
        + host.encode()
        + struct.pack("!H", port)
    )
    sock.sendall(req)
    reply = sock.recv(10)
    return reply[1]


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

    def test_unknown_host_is_refused_with_0x02(self):
        client = self.connect()
        rep = socks5_request(client, "evil.example", 443)
        self.assertEqual(rep, host_proxy.REP_NOT_ALLOWED)

    def test_ipv4_literal_is_refused(self):
        client = self.connect()
        client.sendall(b"\x05\x01\x00")
        self.assertEqual(client.recv(2), b"\x05\x00")
        client.sendall(
            b"\x05\x01\x00\x01" + socket.inet_aton("1.2.3.4") + struct.pack("!H", 443)
        )
        self.assertEqual(client.recv(10)[1], host_proxy.REP_NOT_ALLOWED)

    def test_ipv6_literal_is_refused(self):
        client = self.connect()
        client.sendall(b"\x05\x01\x00")
        self.assertEqual(client.recv(2), b"\x05\x00")
        client.sendall(
            b"\x05\x01\x00\x04"
            + socket.inet_pton(socket.AF_INET6, "2001:db8::1")
            + struct.pack("!H", 443)
        )
        self.assertEqual(client.recv(10)[1], host_proxy.REP_NOT_ALLOWED)

    def test_udp_associate_is_refused_with_0x07(self):
        client = self.connect()
        client.sendall(b"\x05\x01\x00")
        self.assertEqual(client.recv(2), b"\x05\x00")
        client.sendall(b"\x05\x03\x00\x01" + b"\x00" * 6)
        self.assertEqual(client.recv(10)[1], host_proxy.REP_COMMAND_NOT_SUPPORTED)

    def test_client_refusing_no_auth_is_rejected(self):
        client = self.connect()
        client.sendall(b"\x05\x01\x02")  # offers only username/password
        self.assertEqual(client.recv(2), b"\x05\xff")

    def test_host_names_are_case_insensitive(self):
        client = self.connect()
        rep = socks5_request(client, "EXAMPLE.COM", 80)
        self.assertEqual(rep, host_proxy.REP_SUCCESS)

    def test_fake_host_serves_canned_response_on_port_80(self):
        client = self.connect()
        rep = socks5_request(client, "example.com", 80)
        self.assertEqual(rep, host_proxy.REP_SUCCESS)
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
        rep = socks5_request(client, "fakeollama", 11434)
        self.assertEqual(rep, host_proxy.REP_SUCCESS)

        upstream, _ = backend.accept()
        self.addCleanup(upstream.close)
        client.sendall(b"ping")
        self.assertEqual(upstream.recv(4), b"ping")
        upstream.sendall(b"pong")
        self.assertEqual(client.recv(4), b"pong")

    def test_dead_local_provider_reports_connection_refused(self):
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
        rep = socks5_request(client, "deadollama", 11434)
        self.assertEqual(rep, host_proxy.REP_CONNECTION_REFUSED)


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
        raw = host_proxy.inject_auth(
            "POST /v1/chat HTTP/1.1",
            [("Host", "api.openai.com"), ("Authorization", "Bearer placeholder")],
            b"{}",
            "real-token",
        )
        self.assertIn(b"Authorization: Bearer real-token\r\n", raw)
        self.assertNotIn(b"placeholder", raw)
        self.assertTrue(raw.startswith(b"POST /v1/chat HTTP/1.1\r\n"))


if __name__ == "__main__":
    unittest.main()
