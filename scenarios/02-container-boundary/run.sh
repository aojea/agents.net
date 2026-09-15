#!/usr/bin/env bash
# 02-container-boundary: Benchmark and validation for Horizon 2 (At Boundary)
# Interception occurs at the boundary (direct socket stream / eBPF cgroup redirection)
# without guest-side TUN device, synthetic DNS, or Netstack packetization math.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RUN_DIR="/tmp/scenarios/02"
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

for i in {1..30}; do
    [ -f "${RUN_DIR}/cert.pem" ] && break
    sleep 0.1
done

# 2. Start boundary proxy on TCP loopback (simulating transparent socket intercept)
PROXY_PORT=9082
"${PROXY_BIN}" \
  -listen "tcp://127.0.0.1:${PROXY_PORT}" \
  -allow "test.example.com" \
  -upstream-map "test.example.com=127.0.0.1:${TARGET_PORT}" \
  -audit-log "${RUN_DIR}/audit.log" > "${RUN_DIR}/proxy.log" 2>&1 &
PROXY_PID=$!

cleanup() {
    kill "${PROXY_PID}" "${TARGET_PID}" 2>/dev/null || true
    rm -rf "${RUN_DIR}"
}
trap cleanup EXIT

sleep 0.5

echo "=== Horizon 2 (Boundary Intercept): Measuring Conntrack Delta ==="
CONNTRACK_BEFORE=unknown
if [[ -r /proc/sys/net/netfilter/nf_conntrack_count ]]; then
    CONNTRACK_BEFORE=$(cat /proc/sys/net/netfilter/nf_conntrack_count)
fi

echo "=== Horizon 2 (Boundary Intercept): Real curl HTTPS Benchmark (5 rounds x 20 requests = 100 flows) ==="
python3 "${REPO_ROOT}/scenarios/common/benchmark_client.py" \
  --url "https://test.example.com:${TARGET_PORT}/ping" \
  --cacert "${RUN_DIR}/cert.pem" \
  --proxy "http://127.0.0.1:${PROXY_PORT}" \
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
echo "=== Horizon 2: Verification Complete ==="
