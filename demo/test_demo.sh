#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

echo "=== 1. Running Unit Tests ==="
python3 -m unittest discover -s demo

echo "=== 2. Generating Demo CA Certificates ==="
./demo/gen_certs.sh

echo "=== 3. Building Sandbox Container Image ==="
docker build -t agentsnet-demo demo/

echo "=== 4. Verifying Agent Harness inside Zero-Network Container ==="
docker run --rm --network none agentsnet-demo python3 /demo/agent.py

echo "=== 5. Starting Host Proxy ==="
rm -rf /tmp/agent-sockets /tmp/agent-proxy-audit.log
mkdir -p /tmp/agent-sockets
python3 demo/host_proxy.py &
PROXY_PID=$!

cleanup() {
    echo "=== Cleaning up ==="
    kill "${PROXY_PID}" 2>/dev/null || true
    rm -rf /tmp/agent-sockets /tmp/agent-proxy-audit.log
}
trap cleanup EXIT

# Wait for proxy socket
for i in {1..30}; do
    if [ -S /tmp/agent-sockets/egress-proxy.sock ]; then
        break
    fi
    sleep 0.2
done

if [ ! -S /tmp/agent-sockets/egress-proxy.sock ]; then
    echo "ERROR: Host proxy socket was not created"
    exit 1
fi

echo "=== 6. Testing Proxy and Trust Contracts (Fake Response) ==="
OUTPUT=$(docker run --rm \
  --network none \
  -v /tmp/agent-sockets:/var/run/agents.net \
  -v "${REPO_ROOT}/demo/certs/agent-ca.pem:/var/run/agent-ca.pem:ro" \
  -e AGENT_NET_LEGACY_COMPAT=1 \
  agentsnet-demo curl -s https://example.com)

echo "${OUTPUT}"
if ! echo "${OUTPUT}" | grep -q "escaped the zero-network sandbox"; then
    echo "ERROR: Expected success message from fake response tier not found!"
    exit 1
fi

echo "=== 7. Testing ACL Blocking (Blocked Host) ==="
BLOCKED_OUTPUT=$(docker run --rm \
  --network none \
  -v /tmp/agent-sockets:/var/run/agents.net \
  -v "${REPO_ROOT}/demo/certs/agent-ca.pem:/var/run/agent-ca.pem:ro" \
  -e AGENT_NET_LEGACY_COMPAT=1 \
  agentsnet-demo curl -s -i https://blocked-host.example || true)

echo "${BLOCKED_OUTPUT}"
if ! echo "${BLOCKED_OUTPUT}" | grep -q "403 Forbidden"; then
    echo "ERROR: Expected 403 Forbidden response for blocked host not found!"
    exit 1
fi

echo "=== 8. Testing Bidirectional Ingress & Egress ==="
AGENT_CONTAINER_ID=$(docker run -d --rm \
  --network none \
  -v /tmp/agent-sockets:/var/run/agents.net \
  -v "${REPO_ROOT}/demo/certs/agent-ca.pem:/var/run/agent-ca.pem:ro" \
  -e AGENT_NET_LEGACY_COMPAT=1 \
  agentsnet-demo python3 -c "import os, urllib.request, threading, time; from http.server import BaseHTTPRequestHandler, HTTPServer; p = int(os.environ.get('AGENT_INGRESS_PORT', 8081)); (lambda s: threading.Thread(target=s.serve_forever, daemon=True).start())(HTTPServer(('127.0.0.1', p), type('H', (BaseHTTPRequestHandler,), {'do_POST': lambda self: (self.send_response(200), self.end_headers(), self.wfile.write(b'Webhook processed securely\n'))}))); urllib.request.urlopen('http://example.com'); time.sleep(10)")

sleep 2

WEBHOOK_RESP=$(curl -s -X POST -d "hello from the outside world!" http://localhost:9000/webhook || true)
echo "Webhook Response: ${WEBHOOK_RESP}"

docker stop "${AGENT_CONTAINER_ID}" >/dev/null 2>&1 || true

if ! echo "${WEBHOOK_RESP}" | grep -q "Webhook processed securely"; then
    echo "ERROR: Webhook response did not match expected output!"
    exit 1
fi

echo "=== 9. Verifying Audit Log ==="
if [ ! -f /tmp/agent-proxy-audit.log ]; then
    echo "ERROR: Audit log file was not created!"
    exit 1
fi

cat /tmp/agent-proxy-audit.log
grep -q "ALLOW-FAKE" /tmp/agent-proxy-audit.log || (echo "ERROR: ALLOW-FAKE missing in audit log" && exit 1)
grep -q "BLOCK" /tmp/agent-proxy-audit.log || (echo "ERROR: BLOCK missing in audit log" && exit 1)
grep -q "INGRESS" /tmp/agent-proxy-audit.log || (echo "ERROR: INGRESS missing in audit log" && exit 1)

echo "=== ALL DEMO TESTS PASSED SUCCESSFULLY ==="
