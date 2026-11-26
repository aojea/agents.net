#!/usr/bin/env bash
# Copyright 2026 The Kubernetes Authors.
# Licensed under the Apache License, Version 2.0.
#
# Builds the shared Alpine ext4 guest rootfs for test/microvm (both QEMU L2
# virtio-net and Firecracker AF_VSOCK models) without root on e2fsprogs >= 1.47.1.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
OUT="${1:?usage: build-rootfs.sh <output-ext4-path>}"
ROOTFS_MB="${ROOTFS_MB:-128}"
IMAGE="agentsnet-microvm-rootfs:e2e"

mkdir -p "$(dirname "${OUT}")"
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

cat > "${WORK}/Dockerfile" <<'EOF'
FROM golang:1.26.5 AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ ./cmd/
COPY pkg/ ./pkg/
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-s -w" \
    -o /kube-tun2connect ./cmd/kube-tun2connect

FROM alpine:3.20
RUN apk add --no-cache python3 iproute2 ca-certificates && mkdir -p /run /tmp /mnt/config
COPY --from=builder /kube-tun2connect /usr/local/bin/kube-tun2connect
RUN rm -f /sbin/init
COPY --chmod=755 test/microvm/init.sh /sbin/init
COPY --chmod=755 test/microvm/guest-test.py /usr/local/bin/guest-test.py
EOF

echo "=== Building microVM guest rootfs image (Go 1.26.5 + Alpine 3.20) ==="
docker build --load -q -t "${IMAGE}" -f "${WORK}/Dockerfile" "${REPO_ROOT}" >/dev/null
CONTAINER="$(docker create "${IMAGE}")"
docker export "${CONTAINER}" > "${WORK}/rootfs.tar"
docker rm "${CONTAINER}" >/dev/null

echo "=== Creating ext4 image ${OUT} (${ROOTFS_MB} MiB) ==="
rm -f "${OUT}"
truncate -s "${ROOTFS_MB}M" "${OUT}"
if ! mke2fs -q -t ext4 -L agentsnet-vm -d "${WORK}/rootfs.tar" "${OUT}" 2>"${WORK}/mke2fs.err"; then
  if ! sudo -n true 2>/dev/null; then
    cat "${WORK}/mke2fs.err" >&2
    echo "mke2fs could not populate from tarball and sudo is unavailable" >&2
    exit 1
  fi
  echo "mke2fs lacks tarball support; extracting rootfs with sudo"
  mkdir "${WORK}/root"
  sudo tar -C "${WORK}/root" -xf "${WORK}/rootfs.tar"
  rm -f "${OUT}"
  truncate -s "${ROOTFS_MB}M" "${OUT}"
  sudo mke2fs -q -t ext4 -L agentsnet-vm -d "${WORK}/root" "${OUT}"
  sudo chown "$(id -u):$(id -g)" "${OUT}"
  sudo rm -rf "${WORK}/root"
fi
ls -lh "${OUT}"
