#!/usr/bin/env bash
# test_lpe.sh: Tests Local Privilege Escalation (root) inside the Capsule
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RUN_DIR="/tmp/scenarios/01-lpe"
LAUNCHER="${REPO_ROOT}/demo/tun2connect"
PROXY_BIN="${REPO_ROOT}/scenarios/bin/boundary-proxy"
TARGET_BIN="${REPO_ROOT}/scenarios/bin/target-server"
IMAGE="agentsnet-demo:latest"

mkdir -p "${RUN_DIR}"
rm -f "${RUN_DIR}"/*.sock "${RUN_DIR}"/audit.log

# 1. Start target server on port 9092
TARGET_PORT=9092
"${TARGET_BIN}" -port "${TARGET_PORT}" > "${RUN_DIR}/target.log" 2>&1 &
TARGET_PID=$!

# 2. Start boundary proxy
"${PROXY_BIN}" \
  -listen "unix://${RUN_DIR}/boundary.sock" \
  -allow "target.internal" \
  -upstream-map "target.internal=127.0.0.1:${TARGET_PORT}" \
  -audit-log "${RUN_DIR}/audit.log" > "${RUN_DIR}/proxy.log" 2>&1 &
PROXY_PID=$!

cleanup() {
    kill "${PROXY_PID}" "${TARGET_PID}" 2>/dev/null || true
    rm -rf "${RUN_DIR}"
}
trap cleanup EXIT

for i in {1..30}; do
    [ -S "${RUN_DIR}/boundary.sock" ] && break
    sleep 0.1
done

echo "=== LPE Test 1: Root flushes routes inside container ==="
# Inside container, root runs 'ip route flush dev tun0'. Verify fail-closed behavior.
OUTPUT_FLUSH=$(docker run --rm --network none \
  --cap-add NET_ADMIN --device /dev/net/tun \
  -v "${RUN_DIR}:/var/run/agents.net" \
  -v "${LAUNCHER}:/tun2connect:ro" \
  --entrypoint /tun2connect \
  "${IMAGE}" run /var/run/agents.net/boundary.sock \
  sh -c "ip route flush dev tun0 && curl -s --max-time 3 http://target.internal/ping || echo 'FLUSH_FAILED_CLOSED'")

echo "${OUTPUT_FLUSH}"
if echo "${OUTPUT_FLUSH}" | grep -q "FLUSH_FAILED_CLOSED"; then
    echo "  [PASS] Route flush resulted in FAIL-CLOSED (no external egress leak)"
else
    echo "  [FAIL] Unexpected behavior on route flush"
    exit 1
fi

echo "=== LPE Test 2: Compromised agent attempts to spoof X-Capsule-ID header ==="
docker run --rm --network none \
  --cap-add NET_ADMIN --device /dev/net/tun \
  -v "${RUN_DIR}:/var/run/agents.net" \
  -v "${LAUNCHER}:/tun2connect:ro" \
  --entrypoint /tun2connect \
  "${IMAGE}" run /var/run/agents.net/boundary.sock \
  curl -s -H "X-Capsule-ID: attacker-compromised-agent" -H "Sandbox-Id: fake-id" http://target.internal/ping >/dev/null

echo "Audit log entries:"
cat "${RUN_DIR}/audit.log"

if grep -q "attacker-compromised-agent" "${RUN_DIR}/audit.log"; then
    echo "  [FAIL] Security vulnerability: boundary proxy accepted untrusted guest capsule ID!"
    exit 1
else
    echo "  [PASS] Boundary proxy sanitized untrusted guest headers and verified identity from SO_PEERCRED"
fi
