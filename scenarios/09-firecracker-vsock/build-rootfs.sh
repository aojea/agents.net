#!/usr/bin/env bash
# Build the guest root filesystem for scenarios/09-firecracker-vsock.
#
# The image is Alpine plus curl, socat (for a raw AF_VSOCK CONNECT), the
# tun2connect launcher, and init.sh as /sbin/init. It is populated with
# `mke2fs -d` from the exported container tar, so no root, loop device, or
# privileged container is needed on the host.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
OUT="${1:-${REPO_ROOT}/scenarios/bin/guest-rootfs.ext4}"
ROOTFS_MB="${ROOTFS_MB:-96}"
IMAGE="agentsnet-guest-rootfs"

mkdir -p "$(dirname "${OUT}")"
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

echo "=== Building launcher (CGO_ENABLED=0) ==="
CGO_ENABLED=0 go -C "${REPO_ROOT}/tun2connect" build -ldflags='-s -w' \
    -o "${WORK}/tun2connect" ./cmd/tun2connect
cp "${SCRIPT_DIR}/init.sh" "${WORK}/init.sh"

cat > "${WORK}/Dockerfile" <<'EOF'
FROM alpine:3.20
RUN apk add --no-cache curl socat ca-certificates busybox-extras && mkdir -p /mnt/config /run
COPY tun2connect /usr/local/bin/tun2connect
# Alpine's /sbin/init is a symlink to busybox; COPY would follow it.
RUN rm -f /sbin/init
COPY --chmod=755 init.sh /sbin/init
EOF

echo "=== Building guest image ==="
docker build -q -t "${IMAGE}" "${WORK}" > /dev/null
CONTAINER="$(docker create "${IMAGE}")"
docker export "${CONTAINER}" > "${WORK}/rootfs.tar"
docker rm "${CONTAINER}" > /dev/null

echo "=== Creating ${OUT} (${ROOTFS_MB} MiB) ==="
rm -f "${OUT}"
truncate -s "${ROOTFS_MB}M" "${OUT}"
# -d accepts a tarball with e2fsprogs >= 1.47.1 built with libarchive; it
# preserves the ownership and modes recorded by docker export.
mke2fs -q -t ext4 -L guest-rootfs -d "${WORK}/rootfs.tar" "${OUT}"
ls -l "${OUT}"
