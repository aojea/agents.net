#!/bin/busybox sh
export PATH=/bin
/bin/busybox --install -s /bin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
exec </dev/console >/dev/console 2>&1
set -o pipefail
ip link set lo up
ip link set eth0 up
ip addr add 10.0.2.2/24 dev eth0
sysctl -w net.ipv6.conf.eth0.accept_dad=0
ip -6 addr add fd00::2/64 dev eth0
ip route add default via 10.0.2.1
ip -6 route add default via fd00::1
echo 'nameserver 10.0.2.1' > /etc/resolv.conf
unset HTTP_PROXY HTTPS_PROXY ALL_PROXY http_proxy https_proxy all_proxy

probe() {
    label="$1"
    url="$2"
    : > /tmp/body
    wget -q -T 5 -O /tmp/body "$url" 2>/tmp/error
    status=$?
    echo "RESULT $label exit=$status body=$(cat /tmp/body)"
}

probe name http://www.example.com:18080/ping
probe denied-name http://denied.example:18080/ping
probe denied-port http://www.example.com:18081/ping
probe ipv4 http://192.0.2.10:18080/ping
probe ipv6 'http://[2001:db8::10]:18080/ping'
probe denied-ip http://192.0.2.11:18080/ping
probe ipv6-name 'http://v6.example.com:18080/ping'
echo 'nameserver fd00::1' > /etc/resolv.conf
probe ipv6-dns http://www.example.com:18080/ping
echo 'nameserver 10.0.2.1' > /etc/resolv.conf
echo 'RESULT tests-done'

read -r command
if [ "$command" = stream ]; then
    wget -q -T 10 -O - 'http://www.example.com:18080/stream?mb=4096' 2>/tmp/error | {
        dd bs=1 count=1 of=/dev/null 2>/dev/null
        echo 'RESULT stream-active' > /dev/console
        wc -c > /tmp/bytes
    }
    status=$?
    echo "RESULT stream-stopped exit=$status bytes=$(cat /tmp/bytes)"
    read -r command
    probe revoked http://www.example.com:18080/ping
    echo 'RESULT revoked-done'
fi
read -r command
reboot -f