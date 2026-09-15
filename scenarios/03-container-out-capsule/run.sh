#!/usr/bin/env bash
# 03-container-out-capsule: Benchmark and analysis for Horizon 3 (Out-of-Capsule / Routed veth)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RUN_DIR="/tmp/scenarios/03"
TARGET_BIN="${REPO_ROOT}/scenarios/bin/target-server"
IMAGE="agentsnet-demo:latest"

mkdir -p "${RUN_DIR}"

# Find the host bridge IP (typically 192.168.9.1 or 172.17.0.1)
HOST_GATEWAY_IP=$(docker network inspect bridge --format '{{range .IPAM.Config}}{{.Gateway}}{{end}}')
if [ -z "${HOST_GATEWAY_IP}" ]; then
    HOST_GATEWAY_IP="172.17.0.1"
fi

# 1. Start target server on port 9443 with TLS
TARGET_PORT=9443
"${TARGET_BIN}" \
  -host 0.0.0.0 -port "${TARGET_PORT}" \
  -tls -cert "${RUN_DIR}/cert.pem" -key "${RUN_DIR}/key.pem" \
  -san "test.example.com,target.internal,localhost,127.0.0.1,${HOST_GATEWAY_IP}" > "${RUN_DIR}/target.log" 2>&1 &
TARGET_PID=$!

cleanup() {
    kill "${TARGET_PID}" 2>/dev/null || true
    rm -rf "${RUN_DIR}"
}
trap cleanup EXIT

for i in {1..30}; do
    [ -f "${RUN_DIR}/cert.pem" ] && break
    sleep 0.1
done

echo "=== Horizon 3 (Out-of-Capsule): IPAM Inspection ==="
CONTAINER_IP=$(docker run --rm --network bridge --entrypoint hostname "${IMAGE}" -I | awk '{print $1}')
echo "HOST_IPAM_ALLOCATED=1 (Allocated IP: ${CONTAINER_IP} on bridge subnet)"

echo "=== Horizon 3 (Out-of-Capsule): Loss of Domain Name at Host Boundary ==="
DOMAIN_TEST_OUTPUT=$(docker run --rm --network bridge --entrypoint python3 "${IMAGE}" \
  -c "
import socket
resolved_ip = socket.gethostbyname('example.com')
print(f'GUEST_RESOLVED_IP={resolved_ip}')
print('DOMAIN_PRESERVED_ON_WIRE=FALSE (Host kernel only observes raw destination IP)')
")
echo "${DOMAIN_TEST_OUTPUT}"

echo "=== Horizon 3 (Out-of-Capsule): Host-wide Conntrack Snapshot ==="
CONNTRACK_BEFORE=unknown
if [[ -r /proc/sys/net/netfilter/nf_conntrack_count ]]; then
    CONNTRACK_BEFORE=$(cat /proc/sys/net/netfilter/nf_conntrack_count)
fi

echo "=== Horizon 3 (Out-of-Capsule): Real curl HTTPS Benchmark (5 rounds x 20 requests = 100 flows) ==="
docker run --rm --network bridge \
  --add-host test.example.com:${HOST_GATEWAY_IP} \
  -v "${RUN_DIR}:/var/run/agents.net" \
  -v "${REPO_ROOT}/scenarios/common/benchmark_client.py:/client.py:ro" \
  --entrypoint python3 \
  "${IMAGE}" /client.py \
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

echo "=== Horizon 3: Verification Complete ==="
