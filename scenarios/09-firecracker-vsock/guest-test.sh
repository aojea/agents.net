#!/bin/sh
# Runs inside the guest as the launcher's child. Results are printed as
# RESULT lines that the host driver parses from the serial console.
#
# Config drive contents (from run.sh): cert.pem, and this script.
set -u
CERT=/mnt/config/cert.pem
PORT="${TARGET_PORT:-9443}"

probe() {
    # $1 label, $2 url. Prints the HTTP status or the curl failure class.
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 --cacert "$CERT" "$2")"
    rc=$?
    if [ "$rc" -ne 0 ]; then
        echo "RESULT $1 curl-exit=$rc"
    else
        echo "RESULT $1 http=$code"
    fi
}

echo "--- guest: interfaces ---"
ip -o link 2>/dev/null || cat /proc/net/dev
echo "--- guest: resolv.conf ---"
cat /etc/resolv.conf

probe allow-name  "https://test.example.com:${PORT}/ping"
probe deny-name   "https://denied.example:${PORT}/ping"
# A literal address never named by DNS reaches the boundary as an IP
# CONNECT and needs -allow-ip; 192.0.2.10 is not listed.
probe deny-ip     "https://192.0.2.10:${PORT}/ping"

# Forge a CONNECT directly on the boundary channel, bypassing the adapter
# and carrying an identity header. Policy must not change.
forged="$(printf 'CONNECT denied.example:443 HTTP/1.1\r\nHost: denied.example:443\r\nSandbox-Id: forged-admin\r\n\r\n' \
    | socat -T 5 - "VSOCK-CONNECT:2:${BOUNDARY_PORT:-1024}" 2>/dev/null | head -1 | tr -d '\r')"
echo "RESULT forged-connect status=${forged:-no-response}"

# Another VM's boundary port must not be reachable through this channel.
other="$(printf 'CONNECT test.example.com:443 HTTP/1.1\r\nHost: test.example.com:443\r\n\r\n' \
    | socat -T 5 - "VSOCK-CONNECT:2:${OTHER_BOUNDARY_PORT:-1025}" 2>&1 | head -1 | tr -d '\r')"
echo "RESULT other-sandbox-port reply=${other:-no-response}"

# Ingress: serve a fixed body on loopback and wait for the host to fetch it.
mkdir -p /tmp/www && echo "hello-from-guest" > /tmp/www/index.html
httpd -p 127.0.0.1:8081 -h /tmp/www || echo "RESULT httpd failed"
echo "RESULT ingress-ready port=8081"
sleep "${INGRESS_WAIT:-8}"
echo "RESULT done"
