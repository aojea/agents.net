#!/usr/bin/env python3
"""Unit tests for demo/host_proxy.py."""

import unittest
import os
import sys

# Add demo directory to sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import host_proxy


class TestHostProxy(unittest.TestCase):

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

    def test_to_origin_form(self):
        request_line = "GET http://ollama:11434/v1/chat/completions?query=1 HTTP/1.1"
        rewritten = host_proxy.to_origin_form(request_line)
        self.assertEqual(rewritten, "GET /v1/chat/completions?query=1 HTTP/1.1")

    def test_http_response(self):
        resp = host_proxy.http_response(b"HTTP/1.1 200 OK", b"Hello World")
        self.assertTrue(resp.startswith(b"HTTP/1.1 200 OK\r\n"))
        self.assertIn(b"Content-Length: 11\r\n", resp)
        self.assertTrue(resp.endswith(b"Hello World"))


if __name__ == "__main__":
    unittest.main()
