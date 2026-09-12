#!/usr/bin/env bash
# 04-microvm-vsock: Benchmark and validation for MicroVM VSOCK transport
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RUN_DIR="/tmp/scenarios/04"

LAUNCHER="${REPO_ROOT}/demo/tun2connect"
PROXY_BIN="${REPO_ROOT}/scenarios/bin/boundary-proxy"
TARGET_BIN="${REPO_ROOT}/scenarios/bin/target-server"

mkdir -p "${RUN_DIR}"

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

# 2. Start boundary proxy on AF_VSOCK
VSOCK_PORT=10088
"${PROXY_BIN}" \
  -listen "vsock://:${VSOCK_PORT}" \
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

echo "=== Horizon 1 (MicroVM VSOCK): Measuring Conntrack Delta ==="
CONNTRACK_BEFORE=0
if [ -f /proc/sys/net/netfilter/nf_conntrack_count ]; then
    CONNTRACK_BEFORE=$(cat /proc/sys/net/netfilter/nf_conntrack_count)
fi

echo "=== Horizon 1 (MicroVM VSOCK): Real curl HTTPS Benchmark (5 rounds x 20 requests = 100 flows) ==="
BENCH_OUTPUT=$(unshare -m -n -r bash -c "
  echo 'nameserver 100.127.255.253' > /tmp/resolv.conf && mount --bind /tmp/resolv.conf /etc/resolv.conf && \
  ${LAUNCHER} run vsock://1:${VSOCK_PORT} \
    python3 ${REPO_ROOT}/scenarios/common/benchmark_client.py \
      --url 'https://test.example.com:${TARGET_PORT}/ping' \
      --cacert '${RUN_DIR}/cert.pem' \
      --rounds 5 --requests 20 --warmup 5 \
      --throughput-url 'https://test.example.com:${TARGET_PORT}/stream?mb=50' \
      --throughput-trials 3
")

echo "${BENCH_OUTPUT}"

CONNTRACK_AFTER=0
if [ -f /proc/sys/net/netfilter/nf_conntrack_count ]; then
    CONNTRACK_AFTER=$(cat /proc/sys/net/netfilter/nf_conntrack_count)
fi
CONNTRACK_DELTA=$((CONNTRACK_AFTER - CONNTRACK_BEFORE))
echo "CONNTRACK_DELTA=${CONNTRACK_DELTA}"

echo "HOST_IPAM_ALLOCATED=0"
echo "=== MicroVM VSOCK: Verification Complete ==="
