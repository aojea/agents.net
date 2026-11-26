#!/usr/bin/env python3
# Copyright 2026 The Kubernetes Authors.
# Licensed under the Apache License, Version 2.0.
"""In-guest E2E test workload for agents.net KVM microVM models (tap and vsock)."""

import http.server
import ipaddress
import os
import socket
import sys
import threading
import time
import urllib.request

mode = os.environ.get("AGENT_MODE", "tap")
tcp_port = int(os.environ["ECHO_TCP_PORT"])
udp_port = int(os.environ["ECHO_UDP_PORT"])

# 1. Verify expected network interfaces for each microVM model.
ifaces = sorted(os.listdir("/sys/class/net"))
print(f"guest[{mode}]: interfaces={ifaces}", flush=True)
if mode == "tap":
    assert "eth0" in ifaces, f"expected eth0 in tap mode, got {ifaces}"
    assert "tun0" not in ifaces, f"zero in-VM tun0 expected in tap mode, got {ifaces}"
elif mode == "vsock":
    assert ifaces == ["lo", "tun0"], f"expected zero NIC (only lo + tun0) in vsock mode, got {ifaces}"
else:
    raise SystemExit(f"unknown AGENT_MODE={mode}")

# 2. Start in-guest HTTP server for IP-less inbound verification.
shutdown_event = threading.Event()
bind_addr = "0.0.0.0" if mode == "tap" else "127.0.0.1"


class InboundHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/shutdown":
            body = b"bye"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            shutdown_event.set()
            return
        body = f"microvm-{mode}-inbound-ok:{self.path}".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


srv = http.server.ThreadingHTTPServer((bind_addr, 8080), InboundHandler)
threading.Thread(target=srv.serve_forever, daemon=True).start()
print("GUEST_READY", flush=True)

# 3. Outbound RFC 8484 DoH: allowed host -> synthetic 198.18.0.0/15, unknown -> real NXDOMAIN.
resolved_ip = None
last_err = None
for _ in range(25):
    try:
        resolved_ip = socket.gethostbyname("echo.microvm.local")
        break
    except Exception as e:
        last_err = e
        time.sleep(0.2)
if resolved_ip is None:
    raise SystemExit(f"FAIL[{mode}]: DoH resolve echo.microvm.local failed: {last_err}")
assert ipaddress.ip_address(resolved_ip) in ipaddress.ip_network("198.18.0.0/15"), (
    f"non-synthetic IP returned: {resolved_ip}"
)
print(f"PASS[{mode}]: DoH echo.microvm.local -> {resolved_ip} (198.18.0.0/15)", flush=True)

try:
    bad_ip = socket.gethostbyname("doesnotexist.example")
    raise SystemExit(f"FAIL[{mode}]: doesnotexist.example unexpectedly resolved to {bad_ip}")
except socket.gaierror as e:
    print(f"PASS[{mode}]: DoH returned real NXDOMAIN for doesnotexist.example: {e}", flush=True)

# 4. Outbound transparent TCP CONNECT to allowed host:port.
url = f"http://echo.microvm.local:{tcp_port}/from-microvm-{mode}"
with urllib.request.urlopen(url, timeout=10) as resp:
    body = resp.read().decode()
    want = f"microvm-tcp-ok:/from-microvm-{mode}"
    assert resp.status == 200 and body == want, (resp.status, body, want)
    print(f"PASS[{mode}]: outbound TCP CONNECT -> {body}", flush=True)

# 5. Outbound TCP CONNECT to disallowed port on allowed host must fail closed at kube-pep.
denied = False
try:
    s = socket.create_connection(("echo.microvm.local", 9999), timeout=5)
    s.settimeout(3)
    s.sendall(b"GET / HTTP/1.1\r\nHost: echo.microvm.local\r\n\r\n")
    data = s.recv(64)
    s.close()
    denied = len(data) == 0
except OSError:
    denied = True
assert denied, f"FAIL[{mode}]: disallowed port echo.microvm.local:9999 unexpectedly succeeded"
print(f"PASS[{mode}]: disallowed port echo.microvm.local:9999 failed closed", flush=True)

# 6. Outbound transparent UDP over RFC 9298 connect-udp.
payload = f"microvm-{mode}-udp-ok".encode()
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
u.settimeout(10)
u.sendto(payload, ("echo.microvm.local", udp_port))
echoed, _ = u.recvfrom(4096)
u.close()
assert echoed == payload, f"UDP echo mismatch: got={echoed!r} want={payload!r}"
print(f"PASS[{mode}]: outbound UDP connect-udp echoed {echoed.decode()}", flush=True)

print("GUEST_OUTBOUND_PASS", flush=True)

# Wait for host inbound test to send /shutdown over the inbound tunnel.
if not shutdown_event.wait(timeout=30):
    raise SystemExit(f"FAIL[{mode}]: timed out waiting for host inbound /shutdown")
print("GUEST_SHUTDOWN_OK", flush=True)
sys.exit(0)
