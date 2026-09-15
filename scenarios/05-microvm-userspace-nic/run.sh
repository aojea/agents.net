#!/usr/bin/env bash
# 05-microvm-userspace-nic: Benchmark for MicroVM Userspace NIC (slirp4netns / gVisor netstack)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RUN_DIR="/tmp/scenarios/05"

TARGET_BIN="${REPO_ROOT}/scenarios/bin/target-server"

mkdir -p "${RUN_DIR}"
rm -f "${RUN_DIR}"/*.pem "${RUN_DIR}"/*.log

# 1. Start target server on port 9443 with TLS
TARGET_PORT=9443
"${TARGET_BIN}" \
  -host 127.0.0.1 -port "${TARGET_PORT}" \
  -tls -cert "${RUN_DIR}/cert.pem" -key "${RUN_DIR}/key.pem" \
  -san "test.example.com,target.internal,localhost,127.0.0.1,10.0.2.2" > "${RUN_DIR}/target.log" 2>&1 &
TARGET_PID=$!

for i in {1..30}; do
    [ -f "${RUN_DIR}/cert.pem" ] && break
    sleep 0.1
done

cleanup() {
    kill "${TARGET_PID}" "${SLIRP_PID:-}" 2>/dev/null || true
    rm -rf "${RUN_DIR}"
}
trap cleanup EXIT

echo "=== Horizon 1 (MicroVM Userspace NIC): Measuring Conntrack Delta ==="
CONNTRACK_BEFORE=unknown
if [[ -r /proc/sys/net/netfilter/nf_conntrack_count ]]; then
    CONNTRACK_BEFORE=$(cat /proc/sys/net/netfilter/nf_conntrack_count)
fi

echo "=== Horizon 1 (MicroVM Userspace NIC): Real curl HTTPS Benchmark (5 rounds x 20 requests = 100 flows) ==="
# Launch isolated netns with slirp4netns userspace NIC
unshare -m -n -r bash -c '
    echo $$ > '"${RUN_DIR}"'/netns.pid
    for i in {1..50}; do
        ip link show tap0 2>/dev/null | grep -q "UP" && break
        sleep 0.1
    done
    sleep 0.5
    echo "10.0.2.2 test.example.com" >> '"${RUN_DIR}"'/hosts
    mount --bind '"${RUN_DIR}"'/hosts /etc/hosts 2>/dev/null || true
    python3 '"${REPO_ROOT}"'/scenarios/common/benchmark_client.py \
      --url "https://test.example.com:'"${TARGET_PORT}"'/ping" \
      --cacert "'"${RUN_DIR}"'/cert.pem" \
      --rounds 5 --requests 20 --warmup 5 \
      --throughput-url "https://test.example.com:'"${TARGET_PORT}"'/stream?mb=50" \
      --throughput-trials 3
' &
UNSHARE_PID=$!

for i in {1..30}; do
    [ -f "${RUN_DIR}/netns.pid" ] && break
    sleep 0.1
done
NETNS_PID=$(cat "${RUN_DIR}/netns.pid")

slirp4netns -c "${NETNS_PID}" tap0 > "${RUN_DIR}/slirp.log" 2>&1 &
SLIRP_PID=$!

wait "${UNSHARE_PID}"

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
echo "=== MicroVM Userspace NIC: Verification Complete ==="
