#!/usr/bin/env bash
# Copyright 2026 The Kubernetes Authors.
# Licensed under the Apache License, Version 2.0.
#
# End-to-end KVM microVM test runner validating BOTH microVM networking models:
#   1. Zero-agent KVM microVM (QEMU microvm + L2 virtio-net dgram) -> unprivileged
#      kube-netstack -> pkg/tunnel -> mandatory mTLS HTTP/2 -> kube-pep +
#      pkg/ingress.Server (DoH NOERROR/NXDOMAIN, TCP CONNECT, UDP connect-udp, inbound)
#   2. Zero-NIC Firecracker v1.16.1 KVM microVM (AF_VSOCK only) -> kube-tun2connect
#      (-h2 -udp -doh) -> kube-pep + vsock inbound.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
CACHE_DIR="${AGENTS_NET_CACHE:-${HOME}/.cache/agents.net}"

KERNEL_VERSION="6.18.41"
KERNEL_URL="https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/20260819-0a745def42dd-0/x86_64/debug/vmlinux-${KERNEL_VERSION}"
KERNEL_SHA256="78bb3d647ff0ebfe223158df33501d42df28fffccd8b5ab0180a6cfb84b40aa3"
KERNEL="${CACHE_DIR}/vmlinux-${KERNEL_VERSION}"

FIRECRACKER_VERSION="v1.16.1"
FIRECRACKER_SHA256="382a02a869e4d6d5cb14c40577f9545e8458021ea8b0b2d3fc10ec14d9c242e6"
FIRECRACKER_BIN="${CACHE_DIR}/firecracker-${FIRECRACKER_VERSION}"

ROOTFS="${CACHE_DIR}/microvm-rootfs.ext4"

fail() { echo "FAIL: $*" >&2; exit 1; }

[ -r /dev/kvm ] && [ -w /dev/kvm ] || fail "no read/write access to /dev/kvm"
command -v qemu-system-x86_64 >/dev/null || fail "qemu-system-x86_64 not found on PATH"
command -v mke2fs >/dev/null || fail "mke2fs not found on PATH"
command -v docker >/dev/null || fail "docker not found on PATH"

mkdir -p "${CACHE_DIR}"

echo "=== 1. Ensure pinned guest kernel (${KERNEL_VERSION}) ==="
if [ ! -f "${KERNEL}" ]; then
  curl -fsSL --retry 3 -o "${KERNEL}.tmp" "${KERNEL_URL}"
  mv "${KERNEL}.tmp" "${KERNEL}"
fi
echo "${KERNEL_SHA256}  ${KERNEL}" | sha256sum -c - >/dev/null || fail "kernel SHA256 mismatch"

echo "=== 2. Ensure pinned Firecracker (${FIRECRACKER_VERSION}) ==="
if [ ! -x "${FIRECRACKER_BIN}" ]; then
  TMPFC="$(mktemp -d)"
  trap 'rm -rf "${TMPFC}"' EXIT
  curl -fsSL --retry 3 -o "${TMPFC}/fc.tgz" \
    "https://github.com/firecracker-microvm/firecracker/releases/download/${FIRECRACKER_VERSION}/firecracker-${FIRECRACKER_VERSION}-x86_64.tgz"
  echo "${FIRECRACKER_SHA256}  ${TMPFC}/fc.tgz" | sha256sum -c - >/dev/null || fail "Firecracker SHA256 mismatch"
  tar xzf "${TMPFC}/fc.tgz" --wildcards "*/firecracker-${FIRECRACKER_VERSION}-x86_64" -O > "${FIRECRACKER_BIN}.tmp"
  chmod +x "${FIRECRACKER_BIN}.tmp"
  mv "${FIRECRACKER_BIN}.tmp" "${FIRECRACKER_BIN}"
  rm -rf "${TMPFC}"
  trap - EXIT
fi
"${FIRECRACKER_BIN}" --version | head -n 1

echo "=== 3. Ensure guest ext4 rootfs (${ROOTFS}) ==="
if [ ! -f "${ROOTFS}" ] || [ "${REBUILD_ROOTFS:-0}" = "1" ] || \
   [ -n "$(find "${REPO_ROOT}/cmd/kube-tun2connect" "${REPO_ROOT}/pkg/tun2connect" \
     "${SCRIPT_DIR}/init.sh" "${SCRIPT_DIR}/guest-test.py" "${SCRIPT_DIR}/build-rootfs.sh" \
     -newer "${ROOTFS}" -print -quit)" ]; then
  "${SCRIPT_DIR}/build-rootfs.sh" "${ROOTFS}"
fi

echo "=== 4. Run KVM microVM E2E tests (QEMU L2 tapFD + Firecracker AF_VSOCK) ==="
cd "${REPO_ROOT}"
MICROVM_KERNEL="${KERNEL}" \
MICROVM_ROOTFS="${ROOTFS}" \
FIRECRACKER_BIN="${FIRECRACKER_BIN}" \
  go test -tags=microvm_e2e -v -count=1 -timeout=180s ./test/microvm
