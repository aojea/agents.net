#!/bin/sh
# Guest /sbin/init for the agents.net Firecracker scenario.
#
# The kernel starts PID 1 with an empty environment. Everything the guest
# needs to know arrives on the kernel command line as KEY=VALUE pairs, which
# the kernel passes to init as environment variables:
#   BOUNDARY_PORT  vsock port on CID 2 (the host) where the boundary listens
#   INGRESS_PORT   guest vsock port the launcher serves the ingress handshake on
# The workload itself is /mnt/config/guest-test.sh from the second drive.
set -u
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# devtmpfs is mounted by the kernel (CONFIG_DEVTMPFS_MOUNT); the rest is ours.
mount -t proc proc /proc 2>/dev/null
mount -t sysfs sysfs /sys 2>/dev/null
mount -t tmpfs tmpfs /tmp
mount -t tmpfs tmpfs /run
mkdir -p /mnt/config
mount -o ro /dev/vdb /mnt/config || echo "init: config drive missing" > /dev/console

# The root filesystem is read-only and shared; the launcher writes
# /etc/resolv.conf, so give it a writable copy of /etc on tmpfs.
mkdir -p /tmp/etc && cp -a /etc/. /tmp/etc/ && mount --bind /tmp/etc /etc

echo "init: starting launcher (boundary vsock://2:${BOUNDARY_PORT:-1024})" > /dev/console
tun2connect run \
    -ingress-socket "vsock://${INGRESS_PORT:-5000}" \
    "vsock://2:${BOUNDARY_PORT:-1024}" \
    /bin/sh /mnt/config/guest-test.sh > /dev/console 2>&1
echo "init: launcher exited with status $?" > /dev/console

# PID 1 exiting panics the kernel before the console drains; power off instead.
sync
sleep 1
reboot -f
