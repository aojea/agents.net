#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

fail() { echo "FAIL: $*" >&2; exit 1; }
wait_for() {
    local file="$1" pattern="$2"
    for ((attempt=0; attempt<900; attempt++)); do
        if [[ -f "$file" ]] && grep -q "$pattern" "$file"; then return; fi
        sleep 0.1
    done
    fail "timed out waiting for $pattern in $file"
}

if [[ "${1:-}" == fixtures ]]; then
    RUN_DIR="$2"
    children=()
    trap 'kill "${children[@]}" 2>/dev/null || true; wait || true' EXIT
    trap 'exit 1' TERM INT
    ip link set lo up
    ip addr add 192.0.2.10/32 dev lo
    ip -6 addr add 2001:db8::10/128 dev lo nodad
    "${RUN_DIR}/bin/target-server" -host 192.0.2.10 -port 18080 >"${RUN_DIR}/target4.log" 2>&1 &
    children+=($!)
    "${RUN_DIR}/bin/target-server" -host '[2001:db8::10]' -port 18080 >"${RUN_DIR}/target6.log" 2>&1 &
    children+=($!)
    "${RUN_DIR}/bin/connect-proxy" -listen "unix://${RUN_DIR}/vm-a.boundary/egress.sock" \
        -sandbox vm-a -policy-version initial -allow www.example.com:18080,v6.example.com:18080 \
        -allow-ip '192.0.2.10:18080,[2001:db8::10]:18080' \
        -resolve 'www.example.com=192.0.2.10,v6.example.com=2001:db8::10' \
        >"${RUN_DIR}/vm-a.audit" 2>"${RUN_DIR}/vm-a.boundary.log" &
    boundary_pid=$!
    children+=("$boundary_pid")
    "${RUN_DIR}/bin/connect-proxy" -listen "unix://${RUN_DIR}/vm-b.boundary/egress.sock" \
        -sandbox vm-b -policy-version empty >"${RUN_DIR}/vm-b.audit" 2>"${RUN_DIR}/vm-b.boundary.log" &
    children+=($!)
    read -r command <"${RUN_DIR}/fixtures.control"
    [[ "$command" == revoke ]] || exit 1
    kill "$boundary_pid"
    wait "$boundary_pid" || true
    "${RUN_DIR}/bin/connect-proxy" -listen "unix://${RUN_DIR}/vm-a.boundary/egress.sock" \
        -sandbox vm-a -policy-version revoked >"${RUN_DIR}/vm-a.revoked.audit" 2>"${RUN_DIR}/vm-a.revoked.log" &
    children+=($!)
    wait
    exit
fi

for tool in go qemu-system-x86_64 busybox cpio file bwrap unshare ip jq curl; do
    command -v "$tool" >/dev/null || fail "$tool is required"
done
[[ "$(uname -m)" == x86_64 ]] || fail 'this scenario requires x86_64'
[[ -r /dev/kvm && -w /dev/kvm ]] || fail 'read/write access to /dev/kvm is required'
BUSYBOX="${BUSYBOX:-$(command -v busybox)}"
file "$BUSYBOX" | grep -q 'statically linked' || fail 'BUSYBOX must point to a static binary (busybox-static)'
CACHE_DIR="${AGENTS_NET_CACHE:-${HOME}/.cache/agents.net}"
KERNEL="${CACHE_DIR}/vmlinux-6.18.41"
mkdir -p "$CACHE_DIR"
if [[ ! -f "$KERNEL" ]]; then
    curl -fsSL --retry 3 -o "${KERNEL}.tmp" \
        https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/20260819-0a745def42dd-0/x86_64/debug/vmlinux-6.18.41
    mv "${KERNEL}.tmp" "$KERNEL"
fi
echo "78bb3d647ff0ebfe223158df33501d42df28fffccd8b5ab0180a6cfb84b40aa3  ${KERNEL}" | sha256sum -c -
RUN_DIR="$(mktemp -d /tmp/agents-qemu.XXXXXX)"
echo "Run directory: ${RUN_DIR}"
PIDS=()
cleanup() {
    local status=$?
    for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
    wait || true
    if [[ -n "${input_a:-}" ]]; then exec {input_a}>&-; fi
    if [[ -n "${input_b:-}" ]]; then exec {input_b}>&-; fi
    if [[ "$status" == 0 && "${KEEP_RUN_DIR:-0}" != 1 ]]; then
        rm -rf "$RUN_DIR"
    else
        echo "Artifacts kept at ${RUN_DIR}"
    fi
}
trap cleanup EXIT
trap 'exit 1' INT TERM
mkdir -p "${RUN_DIR}/bin" "${RUN_DIR}/root"/{bin,dev,proc,sys,etc,tmp}
cp "$BUSYBOX" "${RUN_DIR}/root/bin/busybox"
ln -s busybox "${RUN_DIR}/root/bin/sh"
cp "${SCRIPT_DIR}/init.sh" "${RUN_DIR}/root/init"
chmod +x "${RUN_DIR}/root/init"
pushd "${RUN_DIR}/root" >/dev/null
find . -print0 | cpio --null -o --format=newc --owner=0:0 >"${RUN_DIR}/initramfs" 2>"${RUN_DIR}/cpio.log"
popd >/dev/null
CGO_ENABLED=0 go -C "${REPO_ROOT}/tun2connect" build -o "${RUN_DIR}/bin/qemuproxy" ./cmd/qemuproxy
CGO_ENABLED=0 go -C "${REPO_ROOT}/tun2connect" build -o "${RUN_DIR}/bin/connect-proxy" ./cmd/connect-proxy
go -C "${REPO_ROOT}/scenarios" build -o "${RUN_DIR}/bin/target-server" ./cmd/target-server
for vm in vm-a vm-b; do
    mkdir -m 700 "${RUN_DIR}/${vm}.packets" "${RUN_DIR}/${vm}.boundary"
    mkfifo "${RUN_DIR}/${vm}.input"
done
mkfifo "${RUN_DIR}/fixtures.control"
unshare -Urn bash "${SCRIPT_DIR}/run.sh" fixtures "$RUN_DIR" >"${RUN_DIR}/fixtures.log" 2>&1 &
PIDS+=($!)
for vm in vm-a vm-b; do
    for ((attempt=0; attempt<100; attempt++)); do
        [[ -S "${RUN_DIR}/${vm}.boundary/egress.sock" ]] && break
        sleep 0.1
    done
    [[ -S "${RUN_DIR}/${vm}.boundary/egress.sock" ]] || fail "${vm}: boundary did not start"
done
exec {input_a}<>"${RUN_DIR}/vm-a.input"
exec {input_b}<>"${RUN_DIR}/vm-b.input"

supervise_vm() {
    vm="$1"
    children=()
    trap 'kill "${children[@]}" 2>/dev/null || true; wait || true; echo "RESULT supervisor-stopped" >"${RUN_DIR}/${vm}.supervisor"' EXIT
    trap 'exit 1' TERM INT
    bwrap --unshare-all --die-with-parent --new-session --cap-drop ALL \
        --ro-bind "${RUN_DIR}/bin/qemuproxy" /qemuproxy --proc /proc --dev /dev \
        --tmpfs /tmp --dir /run --bind "${RUN_DIR}/${vm}.packets" /run/packets \
        --ro-bind "${RUN_DIR}/${vm}.boundary" /run/boundary \
        /qemuproxy -listen /run/packets/nic.sock -proxy unix:///run/boundary/egress.sock \
        >"${RUN_DIR}/${vm}.adapter.log" 2>&1 &
    adapter_pid=$!
    children+=("$adapter_pid")
    echo "$adapter_pid" >"${RUN_DIR}/${vm}.adapter.pid"
    wait_for "${RUN_DIR}/${vm}.adapter.log" 'qemuproxy ready'
    unshare -Urn qemu-system-x86_64 -machine microvm -enable-kvm -cpu host -m 128 -smp 1 \
        -nodefaults -no-user-config -display none -monitor none -serial stdio -no-reboot \
        -kernel "$KERNEL" -initrd "${RUN_DIR}/initramfs" \
        -append 'console=ttyS0 reboot=t panic=1 quiet rdinit=/init' \
        -netdev "stream,id=net0,server=off,addr.type=unix,addr.path=${RUN_DIR}/${vm}.packets/nic.sock" \
        -device 'virtio-net-device,netdev=net0,mac=02:00:00:00:00:02,host_mtu=1500,mq=off,csum=off,gso=off,guest_csum=off,guest_tso4=off,guest_tso6=off,guest_ecn=off,guest_ufo=off,host_tso4=off,host_tso6=off,host_ecn=off,host_ufo=off' \
        <"${RUN_DIR}/${vm}.input" >"${RUN_DIR}/${vm}.console" 2>&1 &
    children+=($!)
    echo "$!" >"${RUN_DIR}/${vm}.qemu.pid"
    status=0
    wait -n -p exited_pid "${children[@]}" || status=$?
    echo "child exit: pid=${exited_pid:-unknown} status=$status" >"${RUN_DIR}/${vm}.exit"
}

qemu-system-x86_64 --version | head -1
supervise_vm vm-a &
PIDS+=($!)
supervise_vm vm-b &
PIDS+=($!)
for vm in vm-a vm-b; do wait_for "${RUN_DIR}/${vm}.console" 'RESULT tests-done'; done
for label in name ipv4 ipv6 ipv6-name ipv6-dns; do
    grep -q "RESULT ${label} exit=0 body=pong" "${RUN_DIR}/vm-a.console" || fail "vm-a: ${label} did not succeed"
done
for label in denied-name denied-port denied-ip; do
    grep -Eq "RESULT ${label} exit=[1-9]" "${RUN_DIR}/vm-a.console" || fail "vm-a: ${label} was not denied"
done
for label in name denied-name denied-port ipv4 ipv6 denied-ip ipv6-name ipv6-dns; do
    grep -Eq "RESULT ${label} exit=[1-9]" "${RUN_DIR}/vm-b.console" || fail "vm-b: ${label} was not denied"
done
[[ "$(jq -s '[.[] | select(.decision == "allow")] | length' "${RUN_DIR}/vm-b.audit")" == 0 ]] || fail 'vm-b allowed a tunnel'
jq -e 'select(.decision == "allow" and .destination == "www.example.com:18080" and .address == "192.0.2.10:18080")' "${RUN_DIR}/vm-a.audit" >/dev/null \
    || fail 'boundary did not receive the hostname and dial its checked address'
echo 'PASS: dual-stack ordinary sockets, synthetic DNS, names, literals and disjoint policies'

printf 'stream\n' >&"$input_a"
wait_for "${RUN_DIR}/vm-a.console" 'RESULT stream-active'
printf 'revoke\n' >"${RUN_DIR}/fixtures.control"
wait_for "${RUN_DIR}/vm-a.console" 'RESULT stream-stopped'
grep -Eq 'RESULT stream-stopped exit=[1-9] bytes=[1-9]' "${RUN_DIR}/vm-a.console" || fail 'revocation did not interrupt an active transfer'
for ((attempt=0; attempt<100; attempt++)); do
    [[ -s "${RUN_DIR}/vm-a.revoked.log" ]] && break
    sleep 0.1
done
printf 'check\n' >&"$input_a"
wait_for "${RUN_DIR}/vm-a.console" 'RESULT revoked-done'
grep -Eq 'RESULT revoked exit=[1-9]' "${RUN_DIR}/vm-a.console" || fail 'revoked destination succeeded'
jq -e 'select(.policy == "revoked" and .decision == "block")' "${RUN_DIR}/vm-a.revoked.audit" >/dev/null || fail 'replacement policy was not used'
echo 'PASS: boundary loss stops active traffic; replacement policy governs new flows'

kill "$(cat "${RUN_DIR}/vm-b.adapter.pid")"
wait_for "${RUN_DIR}/vm-b.supervisor" 'RESULT supervisor-stopped'
if kill -0 "$(cat "${RUN_DIR}/vm-b.qemu.pid")" 2>/dev/null; then fail 'vm-b QEMU survived adapter loss'; fi
echo 'PASS: packet-backend loss terminates its VM generation'
echo 'QEMU integration passed'