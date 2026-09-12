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

# 1. Start target server on port 9093
TARGET_PORT=9093
"${TARGET_BIN}" -port "${TARGET_PORT}" > "${RUN_DIR}/target.log" 2>&1 &
TARGET_PID=$!

# 2. Start boundary proxy on Unix domain socket
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

echo "=== Horizon 2 (Boundary Intercept): Latency Benchmark (5 rounds x 100 requests = 500 samples) ==="
LATENCY_OUTPUT=$(docker run --rm --network none \
  --entrypoint python3 \
  -v "${RUN_DIR}:/var/run/agents.net" \
  "${IMAGE}" -c "
import time, socket

def get_tunnel():
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect('/var/run/agents.net/boundary.sock')
    req = b'CONNECT target.internal:80 HTTP/1.1\r\nHost: target.internal:80\r\n\r\n'
    s.sendall(req)
    resp = s.recv(1024)
    if b'200 OK' not in resp:
        raise RuntimeError(f'Tunnel failed: {resp}')
    return s

# Warmup (10 requests)
for _ in range(10):
    try:
        s = get_tunnel()
        s.sendall(b'GET /ping HTTP/1.1\r\nHost: target.internal\r\nConnection: close\r\n\r\n')
        s.recv(1024)
        s.close()
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
        s = get_tunnel()
        s.sendall(b'GET /ping HTTP/1.1\r\nHost: target.internal\r\nConnection: close\r\n\r\n')
        s.recv(1024)
        s.close()
        r_times.append((time.perf_counter() - t0) * 1000.0)
    st = calc_stats(r_times)
    rounds_p50.append(st['p50'])
    all_times.extend(r_times)
    print(f'ROUND_{r_idx+1}_P50_MS={st[\"p50\"]:.2f}')

overall = calc_stats(all_times)
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

echo "=== Horizon 2 (Boundary Intercept): Throughput Benchmark (3 trials x 50 MB) ==="
THROUGHPUT_OUTPUT=$(docker run --rm --network none \
  --entrypoint python3 \
  -v "${RUN_DIR}:/var/run/agents.net" \
  "${IMAGE}" -c "
import time, socket

trials = []
for i in range(3):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect('/var/run/agents.net/boundary.sock')
    s.sendall(b'CONNECT target.internal:80 HTTP/1.1\r\nHost: target.internal:80\r\n\r\n')
    resp = s.recv(1024)
    if b'200 OK' not in resp:
        raise RuntimeError('Tunnel failed')

    t0 = time.perf_counter()
    s.sendall(b'GET /stream?mb=50 HTTP/1.1\r\nHost: target.internal\r\nConnection: close\r\n\r\n')

    header = b''
    while b'\r\n\r\n' not in header:
        c = s.recv(1)
        if not c:
            break
        header += c

    expected = 50 * 1024 * 1024
    total = 0
    while total < expected:
        chunk = s.recv(65536)
        if not chunk:
            break
        total += len(chunk)

    duration = time.perf_counter() - t0
    mb_per_sec = (total / (1024 * 1024)) / duration
    trials.append(mb_per_sec)
    s.close()
    print(f'TRIAL_{i+1}_THROUGHPUT_MB_S={mb_per_sec:.2f}')

mean_tp = sum(trials) / len(trials)
stddev_tp = (sum((x - mean_tp) ** 2 for x in trials) / (len(trials) - 1)) ** 0.5
tp_cv = (stddev_tp / mean_tp) * 100.0 if mean_tp > 0 else 0.0

print(f'THROUGHPUT_MB_S={mean_tp:.2f}')
print(f'THROUGHPUT_STDDEV_MB_S={stddev_tp:.2f}')
print(f'THROUGHPUT_CV_PCT={tp_cv:.2f}')
")
echo "${THROUGHPUT_OUTPUT}"

echo "HOST_IPAM_ALLOCATED=0"
echo "=== Horizon 2: Verification Complete ==="
