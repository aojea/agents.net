#!/usr/bin/env bash
# tun2connect fuzz presubmit: runs every fuzz target against the
# guest-facing parsers for a bounded time. Regression inputs found by
# earlier runs live in testdata/fuzz and are replayed by `go test` too.
#
#   FUZZTIME=2m ./test_fuzz.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"
FUZZTIME="${FUZZTIME:-20s}"

# Go runs one fuzz target per invocation.
TARGETS=(
    ./cmd/connect-proxy:FuzzReadHead
    ./cmd/connect-proxy:FuzzAuthorize
    ./cmd/connect-proxy:FuzzPolicyParsers
    ./cmd/connect-proxy:FuzzMasqueTarget
    ./pkg/tun2connect:FuzzReadDatagram
    ./pkg/tun2connect:FuzzHandleQuery
)
for spec in "${TARGETS[@]}"; do
    pkg="${spec%%:*}" target="${spec##*:}"
    echo "=== ${pkg} ${target} (${FUZZTIME}) ==="
    # Audit records go to stdout; keep only the fuzzer's own lines.
    go test -run '^$' -fuzz "^${target}\$" -fuzztime "${FUZZTIME}" "${pkg}" \
        | grep -vE '^\{"ts"' | tail -3
done
echo "=== fuzz: PASS ==="
