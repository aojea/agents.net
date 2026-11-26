#!/bin/sh
# Guest /sbin/init for agents.net KVM microVM E2E tests.
# Supports two isolation models selected by kernel cmdline AGENT_MODE=...:
#   - AGENT_MODE=tap   : Zero in-VM agent; configures plain eth0 (198.19.255.254/15)
#                        pointing to host unprivileged kube-netstack (198.19.255.253).
#   - AGENT_MODE=vsock : Zero NIC in VM; runs kube-tun2connect (-h2 -udp -doh)
#                        over AF_VSOCK CID 2 to host kube-pep plus vsock ingress.
set -u
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

mount -t proc proc /proc 2>/dev/null
mount -t sysfs sysfs /sys 2>/dev/null
mount -t tmpfs tmpfs /tmp
mount -t tmpfs tmpfs /run

# Rootfs is mounted read-only; overlay /etc on tmpfs so /etc/resolv.conf is writable.
mkdir -p /tmp/etc && cp -a /etc/. /tmp/etc/ && mount --bind /tmp/etc /etc

MODE="${AGENT_MODE:-tap}"
echo "init: starting microVM guest (AGENT_MODE=${MODE})" > /dev/console

case "${MODE}" in
  tap)
    ip link set lo up
    ip link set eth0 up
    ip addr add 198.19.255.254/15 dev eth0
    ip route add default via 198.19.255.253
    echo "nameserver 198.19.255.253" > /etc/resolv.conf
    python3 -u /usr/local/bin/guest-test.py > /dev/console 2>&1
    RC=$?
    ;;
  vsock)
    ip link set lo up
    kube-tun2connect run \
      -udp -h2 -doh \
      -ingress-socket "vsock://${INGRESS_PORT:-5000}" \
      -ingress-port "8080" \
      "vsock://2:${BOUNDARY_PORT:-1024}" \
      python3 -u /usr/local/bin/guest-test.py > /dev/console 2>&1
    RC=$?
    ;;
  *)
    echo "init: unknown AGENT_MODE=${MODE}" > /dev/console
    RC=2
    ;;
esac

echo "init: guest workload exited rc=${RC}" > /dev/console
sync
reboot -f
