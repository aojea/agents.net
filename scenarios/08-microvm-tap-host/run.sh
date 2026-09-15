#!/usr/bin/env bash
# 08-microvm-tap-host: Host TAP creation permission probe; no VM is started.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RUN_DIR="/tmp/scenarios/08"

mkdir -p "${RUN_DIR}"
rm -f "${RUN_DIR}"/*.log

cleanup() {
    rm -rf "${RUN_DIR}"
}
trap cleanup EXIT

echo "=== Scenario 08: Host TAP Creation Permission Probe (No VM) ==="

# 1. Audit Root Namespace Permissions
echo "--- 1. Privilege & Capability Audit ---"
CAP_STATUS="BLOCKED_NON_ROOT"
if ip tuntap add mode tap test_tap_root0 2>"${RUN_DIR}/tap_err.log"; then
    CAP_STATUS="ALLOWED_ROOT_PRIVILEGE"
    ip link delete test_tap_root0 2>/dev/null || true
else
    ERR_MSG=$(cat "${RUN_DIR}/tap_err.log")
    echo "Privilege Check: Unprivileged user cannot create TAP in host root netns."
    echo "Kernel Response: ${ERR_MSG}"
fi
echo "CAPABILITY_REQUIREMENT=CAP_NET_ADMIN_HOST_ROOT"
echo "CAPABILITY_STATUS=${CAP_STATUS}"

# 2. Host Root Namespace Interface Pollution Analysis
echo "--- 2. Host Root Namespace Interface Pollution Analysis ---"
echo "Host TUN/TAP inventory (not a scaling measurement):"
ip tuntap show || true

# 3. Security Boundary Summary
echo "--- 3. Architectural Boundary Summary ---"
echo "TOPOLOGY=Host TAP permission probe only"
echo "SCALING_MEASURED=false"
echo "SECURITY_ISOLATION_TESTED=false"
echo "=== Host TAP Permission Probe Complete ==="
