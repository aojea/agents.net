#!/usr/bin/env bash
# 08-microvm-tap-host: Audit and analysis of Legacy MicroVM TAP in Host Root Netns
# Demonstrates host pollution, privilege requirements, and security risks.
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

echo "=== Scenario 08: MicroVM TAP in Host Root Namespace (Legacy Architecture) ==="

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
HOST_TAP_COUNT=$(ip link show type tap 2>/dev/null | wc -l || echo 0)
echo "HOST_ROOT_NETNS_CURRENT_TAPS=${HOST_TAP_COUNT}"
echo "HOST_ROOT_NETNS_POLLUTION_RISK=CRITICAL"
echo "POLLUTION_FACTOR_PER_1000_VMS=1000 TAP devices + 1000 Host Routes + Netlink Broadcast Storms"

# 3. Security Boundary Summary
echo "--- 3. Architectural Boundary Summary ---"
echo "HORIZON=Out-of-Capsule (L2/L3 Host Root)"
echo "HOST_IPAM_POLLUTION=HIGH (Allocates subnet and host routes on host root table)"
echo "HOST_CONNTRACK_POLLUTION=HIGH (Every microvm flow tracked in host conntrack table)"
echo "HOST_SECURITY_BOUNDARY=VIOLATED (Hypervisor requires full host root networking capabilities)"
echo "=== MicroVM TAP Host: Audit Complete ==="
