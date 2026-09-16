#!/usr/bin/env bash
# 09-firecracker-vsock: two Firecracker microVMs, each with its own boundary.
#
# Each guest has no network device. Its only path out is the in-guest TUN
# adapter dialing vsock CID 2, which Firecracker delivers to the host Unix
# socket "<uds_path>_<port>" -- the per-VM boundary listener. The two VMs
# get different policies; the test checks that the same request succeeds
# in one and is refused in the other, that a forged CONNECT on the raw
# channel is refused, that an unbound port is unreachable, and that the
# ingress reverse channel reaches the guest's loopback listener.
#
# Requires: firecracker on PATH, read/write access to /dev/kvm, mke2fs >= 1.47.1
# with libarchive, docker (rootfs build), python3, curl, Go.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RUN_DIR="${RUN_DIR:-/tmp/scenarios/09}"
CACHE_DIR="${AGENTS_NET_CACHE:-${HOME}/.cache/agents.net}"
BIN_DIR="${REPO_ROOT}/scenarios/bin"

KERNEL_VERSION="6.18.41"
KERNEL_URL="https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/20260819-0a745def42dd-0/x86_64/debug/vmlinux-${KERNEL_VERSION}"
KERNEL_SHA256="78bb3d647ff0ebfe223158df33501d42df28fffccd8b5ab0180a6cfb84b40aa3"
KERNEL="${CACHE_DIR}/vmlinux-${KERNEL_VERSION}"
ROOTFS="${BIN_DIR}/guest-rootfs.ext4"

TARGET_ADDR=127.0.0.2
TARGET_PORT=9443
BOUNDARY_PORT=1024   # guest vsock port on CID 2 -> host "<uds>_1024"
OTHER_PORT=1025      # never bound: must be refused
INGRESS_PORT=5000    # guest vsock listener served by the launcher
GUEST_HTTP_PORT=8081
VM_TIMEOUT="${VM_TIMEOUT:-90}"

fail() { echo "FAIL: $*" >&2; exit 1; }

echo "=== 0. Prerequisites ==="
command -v firecracker >/dev/null || fail "firecracker not on PATH"
[ -r /dev/kvm ] && [ -w /dev/kvm ] || fail "no read/write access to /dev/kvm"
command -v mke2fs >/dev/null || fail "mke2fs missing"
command -v python3 >/dev/null || fail "python3 missing"
command -v jq >/dev/null || fail "jq missing"
firecracker --version | head -1

echo "=== 1. Guest kernel ==="
mkdir -p "${CACHE_DIR}"
if [ ! -f "${KERNEL}" ]; then
    echo "downloading ${KERNEL_URL}"
    curl -fsSL --retry 3 -o "${KERNEL}.tmp" "${KERNEL_URL}"
    mv "${KERNEL}.tmp" "${KERNEL}"
fi
echo "${KERNEL_SHA256}  ${KERNEL}" | sha256sum -c - >/dev/null || fail "kernel digest mismatch"
echo "kernel ${KERNEL} verified"

echo "=== 2. Guest rootfs and host binaries ==="
if [ ! -f "${ROOTFS}" ] || [ "${REBUILD_ROOTFS:-0}" = 1 ]; then
    "${SCRIPT_DIR}/build-rootfs.sh" "${ROOTFS}"
fi
mkdir -p "${BIN_DIR}"
go -C "${REPO_ROOT}/tun2connect" build -o "${BIN_DIR}/connect-proxy" ./cmd/connect-proxy
go -C "${REPO_ROOT}/scenarios" build -o "${BIN_DIR}/target-server" ./cmd/target-server

rm -rf "${RUN_DIR}"
mkdir -p "${RUN_DIR}"
PIDS=()
cleanup() {
    for pid in "${PIDS[@]:-}"; do
        [ -n "${pid}" ] && kill "${pid}" 2>/dev/null || true
    done
    if [ "${KEEP_RUN_DIR:-0}" != 1 ]; then
        rm -rf "${RUN_DIR}"
    else
        echo "run directory kept at ${RUN_DIR}"
    fi
}
trap cleanup EXIT

echo "=== 3. Upstream target on ${TARGET_ADDR}:${TARGET_PORT} ==="
"${BIN_DIR}/target-server" -host "${TARGET_ADDR}" -port "${TARGET_PORT}" -tls \
    -cert "${RUN_DIR}/cert.pem" -key "${RUN_DIR}/key.pem" \
    -san "test.example.com,${TARGET_ADDR}" > "${RUN_DIR}/target.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 1 50); do [ -s "${RUN_DIR}/cert.pem" ] && break; sleep 0.1; done
[ -s "${RUN_DIR}/cert.pem" ] || fail "target-server did not create its certificate"

echo "=== 4. Config drive (certificate and guest test) ==="
mkdir -p "${RUN_DIR}/config"
cp "${RUN_DIR}/cert.pem" "${SCRIPT_DIR}/guest-test.sh" "${RUN_DIR}/config/"
truncate -s 4M "${RUN_DIR}/config.ext4"
mke2fs -q -t ext4 -L config -d "${RUN_DIR}/config" "${RUN_DIR}/config.ext4"

fc_put() {
    curl -sf -X PUT --unix-socket "$1" "http://localhost$2" \
        -H 'Content-Type: application/json' -d "$3" -o /dev/null \
        || fail "firecracker API PUT $2 failed"
}

# start_vm NAME CID BOUNDARY_FLAGS...
start_vm() {
    local name="$1" cid="$2"; shift 2
    local uds="${RUN_DIR}/${name}.vsock" api="${RUN_DIR}/${name}.api"
    # The boundary listens exactly where Firecracker delivers guest
    # connections to CID 2 port ${BOUNDARY_PORT}. Nothing else is bound
    # under this VM's prefix. The sandbox identity in every audit record
    # is this flag, bound to the listener by the controller (this script).
    "${BIN_DIR}/connect-proxy" -listen "unix://${uds}_${BOUNDARY_PORT}" \
        -sandbox "${name}" -policy-version "scenario-09" "$@" \
        > "${RUN_DIR}/${name}.audit" 2> "${RUN_DIR}/${name}.boundary.log" &
    PIDS+=($!)
    for _ in $(seq 1 50); do [ -S "${uds}_${BOUNDARY_PORT}" ] && break; sleep 0.1; done
    [ -S "${uds}_${BOUNDARY_PORT}" ] || fail "${name}: boundary did not listen"

    firecracker --api-sock "${api}" > "${RUN_DIR}/${name}.console" 2>&1 &
    PIDS+=($!)
    for _ in $(seq 1 100); do [ -S "${api}" ] && break; sleep 0.05; done
    [ -S "${api}" ] || fail "${name}: firecracker API socket did not appear"

    # Unknown KEY=VALUE cmdline words reach PID 1 as environment variables.
    fc_put "${api}" /boot-source "{
        \"kernel_image_path\": \"${KERNEL}\",
        \"boot_args\": \"console=ttyS0 reboot=k panic=1 pci=off ro quiet BOUNDARY_PORT=${BOUNDARY_PORT} OTHER_BOUNDARY_PORT=${OTHER_PORT} INGRESS_PORT=${INGRESS_PORT} GUEST_HTTP_PORT=${GUEST_HTTP_PORT} TARGET_PORT=${TARGET_PORT} INGRESS_WAIT=12\"
    }"
    fc_put "${api}" /machine-config '{"vcpu_count": 1, "mem_size_mib": 128}'
    fc_put "${api}" /drives/rootfs "{
        \"drive_id\": \"rootfs\", \"path_on_host\": \"${ROOTFS}\",
        \"is_root_device\": true, \"is_read_only\": true
    }"
    fc_put "${api}" /drives/config "{
        \"drive_id\": \"config\", \"path_on_host\": \"${RUN_DIR}/config.ext4\",
        \"is_root_device\": false, \"is_read_only\": true
    }"
    # No network-interfaces call: the guest has loopback only.
    fc_put "${api}" /vsock "{\"guest_cid\": ${cid}, \"uds_path\": \"${uds}\"}"
    fc_put "${api}" /actions '{"action_type": "InstanceStart"}'
    echo "${name}: started (cid ${cid}, boundary ${uds}_${BOUNDARY_PORT})"
}

wait_marker() { # NAME MARKER
    local console="${RUN_DIR}/$1.console"
    for _ in $(seq 1 $((VM_TIMEOUT * 10))); do
        grep -q "$2" "${console}" 2>/dev/null && return 0
        sleep 0.1
    done
    echo "--- ${1} console ---"; cat "${console}"
    fail "$1: timed out waiting for ${2}"
}

result() { # NAME KEY -> value
    grep -o "RESULT $2 .*" "${RUN_DIR}/$1.console" | head -1 | cut -d' ' -f3- | tr -d '\r'
}

echo "=== 5. Boot two sandboxes with different policies ==="
# vm-a may reach test.example.com on the target port only; the boundary
# maps the name to the target address.
start_vm vm-a 3 -allow "test.example.com:${TARGET_PORT}" \
    -resolve "test.example.com=${TARGET_ADDR}" -allow-ip "${TARGET_ADDR}:${TARGET_PORT}"
# vm-b has an empty policy: every destination is refused.
start_vm vm-b 4

echo "=== 6. Ingress through Firecracker's socket into each guest ==="
FAILED=0
for vm in vm-a vm-b; do
    wait_marker "${vm}" "RESULT ingress-ready"
    if python3 "${SCRIPT_DIR}/ingress_probe.py" "${RUN_DIR}/${vm}.vsock" "${INGRESS_PORT}" "${GUEST_HTTP_PORT}" \
        > "${RUN_DIR}/${vm}.ingress" 2>&1; then
        echo "${vm}: $(cat "${RUN_DIR}/${vm}.ingress")"
    else
        echo "${vm}: ingress FAILED: $(cat "${RUN_DIR}/${vm}.ingress")"; FAILED=1
    fi
    # The launcher pins the loopback port; naming another is refused even
    # though nothing else listens there anyway.
    if python3 "${SCRIPT_DIR}/ingress_probe.py" "${RUN_DIR}/${vm}.vsock" "${INGRESS_PORT}" 22 \
        > "${RUN_DIR}/${vm}.ingress-other" 2>&1; then
        echo "${vm}: ingress to an unpinned port SUCCEEDED"; FAILED=1
    elif grep -q 'port not permitted' "${RUN_DIR}/${vm}.ingress-other"; then
        echo "${vm}: ingress to an unpinned port refused by the launcher"
    else
        echo "${vm}: unexpected unpinned-port result: $(cat "${RUN_DIR}/${vm}.ingress-other")"; FAILED=1
    fi
done

echo "=== 7. Guest results ==="
for vm in vm-a vm-b; do
    wait_marker "${vm}" "RESULT done"
done
# Both guests power off after the test; Firecracker exits on reboot.
sleep 1

check() { # NAME KEY EXPECTED-SUBSTRING
    local got; got="$(result "$1" "$2")"
    if [[ "${got}" == *"$3"* ]]; then
        echo "  ok   $1 $2: ${got}"
    else
        echo "  FAIL $1 $2: got '${got}', want '*$3*'"; FAILED=1
    fi
}
echo "vm-a (test.example.com:${TARGET_PORT} permitted):"
check vm-a allow-name "http=200"
check vm-a deny-name "curl-exit=7"
check vm-a deny-port "curl-exit=7"
check vm-a deny-ip "curl-exit=7"
check vm-a forged-connect "403"
echo "vm-b (nothing permitted):"
check vm-b allow-name "curl-exit=7"
check vm-b deny-name "curl-exit=7"
check vm-b deny-port "curl-exit=7"
check vm-b deny-ip "curl-exit=7"
check vm-b forged-connect "403"
for vm in vm-a vm-b; do
    if [[ "$(result "${vm}" other-sandbox-port)" == *"200"* ]]; then
        echo "  FAIL ${vm}: unbound boundary port answered"; FAILED=1
    fi
done

echo "=== 8. Boundary audit records ==="
# audit_count NAME JQ-FILTER -> number of records matching the filter
audit_count() {
    jq -c "select($2)" "${RUN_DIR}/$1.audit" 2>/dev/null | wc -l
}
for vm in vm-a vm-b; do
    echo "--- ${vm} ---"
    jq -c '{sandbox,decision,reason,destination,address}' "${RUN_DIR}/${vm}.audit" || true
    if ! jq -e . "${RUN_DIR}/${vm}.audit" >/dev/null 2>&1; then
        echo "  FAIL ${vm}: audit is not one JSON object per line"; FAILED=1
    fi
    if [ "$(audit_count "${vm}" ".sandbox != \"${vm}\" or .policy != \"scenario-09\"")" -ne 0 ]; then
        echo "  FAIL ${vm}: a record lacks the listener-bound sandbox identity"; FAILED=1
    fi
done
[ "$(audit_count vm-a ".decision == \"allow\" and .destination == \"test.example.com:${TARGET_PORT}\" and .address == \"${TARGET_ADDR}:${TARGET_PORT}\"")" -ge 1 ] \
    || { echo "  FAIL vm-a audit lacks the allowed dial to the checked address"; FAILED=1; }
[ "$(audit_count vm-a '.decision == "block" and .reason == "port-not-allowed" and .destination == "test.example.com:80"')" -ge 1 ] \
    || { echo "  FAIL vm-a audit lacks the refused port"; FAILED=1; }
[ "$(audit_count vm-a ".decision == \"block\" and .reason == \"ip-not-on-allowlist\" and .destination == \"192.0.2.10:${TARGET_PORT}\"")" -ge 1 ] \
    || { echo "  FAIL vm-a audit lacks the refused literal"; FAILED=1; }
[ "$(audit_count vm-b '.decision == "allow"')" -eq 0 ] \
    || { echo "  FAIL vm-b boundary allowed something"; FAILED=1; }
[ "$(audit_count vm-b '.decision == "block" and .reason == "not-on-allowlist" and (.destination | startswith("test.example.com:"))')" -ge 1 ] \
    || { echo "  FAIL vm-b audit lacks the refused name"; FAILED=1; }

if [ "${FAILED}" -ne 0 ]; then
    KEEP_RUN_DIR=1
    for vm in vm-a vm-b; do echo "--- ${vm} console ---"; cat "${RUN_DIR}/${vm}.console"; done
    fail "scenario 09 failed"
fi
echo "=== Firecracker vsock scenario: PASS ==="
