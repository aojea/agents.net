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

# 1. Start target server on port 9091
TARGET_PORT=9091
"${TARGET_BIN}" -port "${TARGET_PORT}" > "${RUN_DIR}/target.log" 2>&1 &
TARGET_PID=$!

# 2. Start boundary proxy on Unix domain socket
"${PROXY_BIN}" \
  -listen "unix://${RUN_DIR}/boundary.sock" \
  -allow "target.internal,blocked.internal" \
  -upstream-map "target.internal=127.0.0.1:${TARGET_PORT}" \
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
CONNTRACK_BEFORE=0
if [ -f /proc/sys/net/netfilter/nf_conntrack_count ]; then
    CONNTRACK_BEFORE=$(cat /proc/sys/net/netfilter/nf_conntrack_count)
fi

echo "=== Horizon 1 (In-Capsule): Latency Benchmark (5 rounds x 100 requests = 500 samples) ==="
LATENCY_OUTPUT=$(docker run --rm --network none \
  --cap-add NET_ADMIN --device /dev/net/tun \
  -v "${RUN_DIR}:/var/run/agents.net" \
  -v "${LAUNCHER}:/tun2connect:ro" \
  --entrypoint /tun2connect \
  "${IMAGE}" run /var/run/agents.net/boundary.sock \
  python3 -c "
import time, urllib.request

# Warmup (10 requests)
for _ in range(10):
    try:
        with urllib.request.urlopen('http://target.internal/ping', timeout=2) as r:
            r.read()
    except Exception:
        pass

def calc_stats(data):
    data = sorted(data)
    n = len(data)
    def get_p(p):
        idx = (n - 1) * p
        lower = int(idx)
        upper = min(lower + 1, n - 1)
        weight = idx - lower
        return data[lower] * (1.0 - weight) + data[upper] * weight
    mean = sum(data) / n
    stddev = (sum((x - mean) ** 2 for x in data) / (n - 1)) ** 0.5 if n > 1 else 0.0
    cv = (stddev / mean) * 100.0 if mean > 0 else 0.0
    return {
        'min': data[0],
        'p50': get_p(0.50),
        'p90': get_p(0.90),
        'p95': get_p(0.95),
        'p99': get_p(0.99),
        'max': data[-1],
        'mean': mean,
        'stddev': stddev,
        'cv_pct': cv,
    }

rounds_p50 = []
all_times = []

for r_idx in range(5):
    r_times = []
    for _ in range(100):
        t0 = time.perf_counter()
        with urllib.request.urlopen('http://target.internal/ping', timeout=2) as r:
            r.read()
        r_times.append((time.perf_counter() - t0) * 1000.0)
    st = calc_stats(r_times)
    rounds_p50.append(st['p50'])
    all_times.extend(r_times)
    print(f'ROUND_{r_idx+1}_P50_MS={st[\"p50\"]:.2f}')

overall = calc_stats(all_times)
# Cross-round stability of p50
mean_p50 = sum(rounds_p50) / len(rounds_p50)
var_p50 = sum((x - mean_p50) ** 2 for x in rounds_p50) / (len(rounds_p50) - 1)
stddev_p50 = var_p50 ** 0.5
stability_cv = (stddev_p50 / mean_p50) * 100.0 if mean_p50 > 0 else 0.0

print(f'SAMPLE_COUNT={len(all_times)}')
print(f'LATENCY_P50_MS={overall[\"p50\"]:.2f}')
print(f'LATENCY_P90_MS={overall[\"p90\"]:.2f}')
print(f'LATENCY_P95_MS={overall[\"p95\"]:.2f}')
print(f'LATENCY_P99_MS={overall[\"p99\"]:.2f}')
print(f'LATENCY_MIN_MS={overall[\"min\"]:.2f}')
print(f'LATENCY_MAX_MS={overall[\"max\"]:.2f}')
print(f'LATENCY_MEAN_MS={overall[\"mean\"]:.2f}')
print(f'LATENCY_STDDEV_MS={overall[\"stddev\"]:.2f}')
print(f'LATENCY_CV_PCT={overall[\"cv_pct\"]:.2f}')
print(f'P50_STABILITY_CV_PCT={stability_cv:.2f}')
")
echo "${LATENCY_OUTPUT}"

echo "=== Horizon 1 (In-Capsule): Throughput Benchmark (3 trials x 50 MB) ==="
THROUGHPUT_OUTPUT=$(docker run --rm --network none \
  --cap-add NET_ADMIN --device /dev/net/tun \
  -v "${RUN_DIR}:/var/run/agents.net" \
  -v "${LAUNCHER}:/tun2connect:ro" \
  --entrypoint /tun2connect \
  "${IMAGE}" run /var/run/agents.net/boundary.sock \
  python3 -c "
import time, urllib.request

trials = []
for i in range(3):
    t0 = time.perf_counter()
    with urllib.request.urlopen('http://target.internal/stream?mb=50', timeout=30) as r:
        total = len(r.read())
    duration = time.perf_counter() - t0
    mb_per_sec = (total / (1024 * 1024)) / duration
    trials.append(mb_per_sec)
    print(f'TRIAL_{i+1}_THROUGHPUT_MB_S={mb_per_sec:.2f}')

mean_tp = sum(trials) / len(trials)
stddev_tp = (sum((x - mean_tp) ** 2 for x in trials) / (len(trials) - 1)) ** 0.5
tp_cv = (stddev_tp / mean_tp) * 100.0 if mean_tp > 0 else 0.0

print(f'THROUGHPUT_MB_S={mean_tp:.2f}')
print(f'THROUGHPUT_STDDEV_MB_S={stddev_tp:.2f}')
print(f'THROUGHPUT_CV_PCT={tp_cv:.2f}')
")
echo "${THROUGHPUT_OUTPUT}"

CONNTRACK_AFTER=0
if [ -f /proc/sys/net/netfilter/nf_conntrack_count ]; then
    CONNTRACK_AFTER=$(cat /proc/sys/net/netfilter/nf_conntrack_count)
fi
CONNTRACK_DELTA=$((CONNTRACK_AFTER - CONNTRACK_BEFORE))
echo "CONNTRACK_DELTA=${CONNTRACK_DELTA}"
echo "HOST_IPAM_ALLOCATED=0"

echo "=== Horizon 1: Verification Complete ==="
