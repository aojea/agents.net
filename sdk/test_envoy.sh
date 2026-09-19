#!/usr/bin/env bash
# tun2connect presubmit: the full Go suite plus the mesh-integration
# proof -- an unmodified Envoy (examples/envoy-boundary.yaml) terminating
# the wire at both stages for the library's own dialers.
# Needs docker and real egress (example.com).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

ENVOY_IMAGE="${ENVOY_IMAGE:-envoyproxy/envoy:v1.32-latest}"
ENVOY_NAME="tun2connect-envoy-test"
ADMIN=127.0.0.1:19901

echo "=== 1. Go unit + e2e tests (race) ==="
go build ./...
go vet ./...
go test -race -count=1 ./...

echo "=== 2. Starting Envoy boundary (${ENVOY_IMAGE}) ==="
docker rm -f "${ENVOY_NAME}" >/dev/null 2>&1 || true
docker run -d --name "${ENVOY_NAME}" --network host "${ENVOY_IMAGE}" \
  --config-yaml "$(cat examples/envoy-boundary.yaml)" >/dev/null
cleanup() { docker rm -f "${ENVOY_NAME}" >/dev/null 2>&1 || true; }
trap cleanup EXIT

for i in {1..50}; do
    curl -sf "http://${ADMIN}/ready" >/dev/null 2>&1 && break
    sleep 0.2
done
curl -sf "http://${ADMIN}/ready" >/dev/null || { echo "ERROR: Envoy never became ready"; docker logs "${ENVOY_NAME}" | tail -5; exit 1; }

echo "=== 3. Envoy interop: both dialers through the mesh dataplane ==="
ENVOY_CONNECT_H1=127.0.0.1:10000 ENVOY_CONNECT_H2=127.0.0.1:10001 \
  go test -count=1 -v -run TestEnvoyInterop ./pkg/...

echo "=== 4. Envoy's own view: one CONNECT upgrade per listener ==="
STATS=$(curl -s "http://${ADMIN}/stats")
echo "${STATS}" | grep -E "connect_h[12]\.downstream_cx_upgrades_total"
for l in connect_h1 connect_h2; do
    n=$(echo "${STATS}" | sed -n "s/^http\.${l}\.downstream_cx_upgrades_total: //p")
    if [ "${n:-0}" -lt 1 ]; then
        echo "ERROR: Envoy terminated no CONNECT upgrade on ${l}"
        exit 1
    fi
done

echo "=== PASS ==="
