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

echo "=== 4. Verifying Unmodified CLI inside Zero-Network Container ==="
docker run --rm --network none agentsnet-demo opencode --version

echo "=== 5. Starting Host Proxy ==="
rm -f /tmp/agent-proxy.sock /tmp/agent-proxy-audit.log
python3 demo/host_proxy.py &
PROXY_PID=$!

cleanup() {
    echo "=== Cleaning up ==="
    kill "${PROXY_PID}" 2>/dev/null || true
    rm -f /tmp/agent-proxy.sock /tmp/agent-proxy-audit.log
}
trap cleanup EXIT

# Wait for proxy socket
for i in {1..30}; do
    if [ -S /tmp/agent-proxy.sock ]; then
        break
    fi
    sleep 0.2
done

if [ ! -S /tmp/agent-proxy.sock ]; then
    echo "ERROR: Host proxy socket was not created"
    exit 1
fi

echo "=== 6. Testing Proxy and Trust Contracts (Fake Response) ==="
OUTPUT=$(docker run --rm \
  --network none \
  -v /tmp/agent-proxy.sock:/var/run/agent-proxy.sock \
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
  -v /tmp/agent-proxy.sock:/var/run/agent-proxy.sock \
  -v "${REPO_ROOT}/demo/certs/agent-ca.pem:/var/run/agent-ca.pem:ro" \
  -e AGENT_NET_LEGACY_COMPAT=1 \
  agentsnet-demo curl -s -i https://blocked-host.example || true)

echo "${BLOCKED_OUTPUT}"
if ! echo "${BLOCKED_OUTPUT}" | grep -q "403 Forbidden"; then
    echo "ERROR: Expected 403 Forbidden response for blocked host not found!"
    exit 1
fi

echo "=== 8. Verifying Audit Log ==="
if [ ! -f /tmp/agent-proxy-audit.log ]; then
    echo "ERROR: Audit log file was not created!"
    exit 1
fi

cat /tmp/agent-proxy-audit.log
grep -q "ALLOW-FAKE" /tmp/agent-proxy-audit.log || (echo "ERROR: ALLOW-FAKE missing in audit log" && exit 1)
grep -q "BLOCK" /tmp/agent-proxy-audit.log || (echo "ERROR: BLOCK missing in audit log" && exit 1)

echo "=== ALL DEMO TESTS PASSED SUCCESSFULLY ==="
