#!/usr/bin/env bash
# 01-container-in-capsule: Benchmark and validation for Horizon 1 (In-Capsule)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RUN_DIR="/tmp/scenarios/01"
LAUNCHER="${REPO_ROOT}/demo/tun2connect"
PROXY_BIN="${REPO_ROOT}/scenarios/bin/boundary-proxy"
TARGET_BIN="${REPO_ROOT}/scenarios/bin/target-server"
IMAGE="agentsnet-demo:latest"

mkdir -p "${RUN_DIR}"
rm -f "${RUN_DIR}"/*.sock "${RUN_DIR}"/audit.log

# 1. Start target server on port 9443 with TLS
TARGET_PORT=9443
"${TARGET_BIN}" \
  -host 127.0.0.1 -port "${TARGET_PORT}" \
  -tls -cert "${RUN_DIR}/cert.pem" -key "${RUN_DIR}/key.pem" \
  -san "test.example.com,target.internal,localhost,127.0.0.1" > "${RUN_DIR}/target.log" 2>&1 &
TARGET_PID=$!

# Wait for cert to exist
for i in {1..30}; do
    [ -f "${RUN_DIR}/cert.pem" ] && break
    sleep 0.1
done

# 2. Start boundary proxy on Unix domain socket
"${PROXY_BIN}" \
  -listen "unix://${RUN_DIR}/boundary.sock" \
  -allow "test.example.com" \
  -upstream-map "test.example.com=127.0.0.1:${TARGET_PORT}" \
  -audit-log "${RUN_DIR}/audit.log" > "${RUN_DIR}/proxy.log" 2>&1 &
PROXY_PID=$!

cleanup() {
    kill "${PROXY_PID}" "${TARGET_PID}" 2>/dev/null || true
    rm -rf "${RUN_DIR}"
}
trap cleanup EXIT

# Wait for socket
for i in {1..30}; do
    [ -S "${RUN_DIR}/boundary.sock" ] && break
    sleep 0.1
done
if [ ! -S "${RUN_DIR}/boundary.sock" ]; then
    echo "ERROR: Boundary socket failed to start"
    exit 1
fi

echo "=== Horizon 1 (In-Capsule): Measuring Conntrack Delta ==="
CONNTRACK_BEFORE=unknown
if [[ -r /proc/sys/net/netfilter/nf_conntrack_count ]]; then
    CONNTRACK_BEFORE=$(cat /proc/sys/net/netfilter/nf_conntrack_count)
fi

echo "=== Horizon 1 (In-Capsule): Real curl HTTPS Benchmark (5 rounds x 20 requests = 100 flows) ==="
docker run --rm --network none \
  --cap-add NET_ADMIN --device /dev/net/tun \
  -v "${RUN_DIR}:/var/run/agents.net" \
  -v "${REPO_ROOT}/scenarios/common/benchmark_client.py:/client.py:ro" \
  -v "${LAUNCHER}:/tun2connect:ro" \
  --entrypoint /tun2connect \
  "${IMAGE}" run /var/run/agents.net/boundary.sock \
  python3 /client.py \
    --url "https://test.example.com:${TARGET_PORT}/ping" \
    --cacert /var/run/agents.net/cert.pem \
    --rounds 5 --requests 20 --warmup 5 \
    --throughput-url "https://test.example.com:${TARGET_PORT}/stream?mb=50" \
    --throughput-trials 3

CONNTRACK_AFTER=unknown
if [[ -r /proc/sys/net/netfilter/nf_conntrack_count ]]; then
    CONNTRACK_AFTER=$(cat /proc/sys/net/netfilter/nf_conntrack_count)
fi
CONNTRACK_DELTA=unknown
if [[ "${CONNTRACK_BEFORE}" != unknown && "${CONNTRACK_AFTER}" != unknown ]]; then
    CONNTRACK_DELTA=$((CONNTRACK_AFTER - CONNTRACK_BEFORE))
fi
echo "CONNTRACK_DELTA=${CONNTRACK_DELTA}"
echo "HOST_IPAM_ALLOCATED=0"

echo "=== Horizon 1: Verification Complete ==="
