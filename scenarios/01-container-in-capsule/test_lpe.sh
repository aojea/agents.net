#!/usr/bin/env bash
# test_lpe.sh: Route-tampering and CONNECT identity smoke tests, not an LPE test.
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

echo "=== Route-tampering smoke test: root flushes routes inside container ==="
# Inside container, root runs 'ip route flush dev tun0'. Verify fail-closed behavior.
OUTPUT_FLUSH=$(docker run --rm --network none \
  --cap-add NET_ADMIN --device /dev/net/tun \
  -v "${RUN_DIR}:/var/run/agents.net" \
  -v "${LAUNCHER}:/tun2connect:ro" \
  --entrypoint /tun2connect \
  "${IMAGE}" run /var/run/agents.net/boundary.sock \
  sh -c "curl -fsS --max-time 3 http://target.internal/ping >/dev/null || exit 2; ip route flush dev tun0 || exit 2; if curl -fsS --max-time 3 http://target.internal/ping; then exit 1; fi; echo 'FLUSH_FAILED_CLOSED'")

echo "${OUTPUT_FLUSH}"
if echo "${OUTPUT_FLUSH}" | grep -q "FLUSH_FAILED_CLOSED"; then
    echo "  [PASS] Route flush resulted in FAIL-CLOSED (no external egress leak)"
else
    echo "  [FAIL] Unexpected behavior on route flush"
    exit 1
fi

echo "=== CONNECT identity smoke test: direct forged boundary request ==="
docker run --rm --network none \
  -v "${RUN_DIR}/boundary.sock:/boundary.sock" \
  --entrypoint python3 "${IMAGE}" -c '
import socket

for target, status in [("target.internal:80", b"200"), ("denied.internal:80", b"403")]:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(5)
        client.connect("/boundary.sock")
        request = f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nX-Capsule-ID: attacker-compromised-agent\r\nSandbox-Id: fake-id\r\nX-Dome-Tenant: fake-id\r\n\r\n"
        client.sendall(request.encode())
        with client.makefile("rb") as response:
            assert response.readline().split()[1] == status
'

echo "Audit log entries:"
cat "${RUN_DIR}/audit.log"

if grep -q "attacker-compromised-agent" "${RUN_DIR}/audit.log"; then
    echo "  [FAIL] Security vulnerability: boundary proxy accepted untrusted guest capsule ID!"
    exit 1
elif grep -Eq "BLOCK not-on-allowlist target=denied.internal:80 capsule=capsule-pid-[0-9]+-uid-[0-9]+" "${RUN_DIR}/audit.log"; then
  echo "  [PASS] Forged CONNECT headers did not grant access; denial has kernel-derived identity"
else
  echo "  [FAIL] Missing kernel-attributed denial"
  exit 1
fi
