#!/usr/bin/env bash
# End-to-end presubmit for the agents.net reference demo: the SOCKS5
# boundary (host_proxy.py) judging an unmodified image confined by the
# injected nano-init launcher.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

SAM_REPO="${SAM_REPO:-https://github.com/google/sam}"
SAM_CHECKOUT="${SAM_CHECKOUT:-}"   # set to a local sam checkout to skip cloning
NANO_INIT="${SCRIPT_DIR}/nano-init"

echo "=== 1. Running Unit Tests ==="
python3 -m unittest discover -s demo

echo "=== 2. Generating Demo CA Certificates ==="
./demo/gen_certs.sh

echo "=== 3. Acquiring the Launcher (nano-init) ==="
if [ ! -x "${NANO_INIT}" ]; then
    if [ -z "${SAM_CHECKOUT}" ]; then
        SAM_CHECKOUT="$(mktemp -d)/sam"
        git clone --depth 1 "${SAM_REPO}" "${SAM_CHECKOUT}"
    fi
    docker build -t sam-nano-init:local -f "${SAM_CHECKOUT}/Dockerfile.nano-init" "${SAM_CHECKOUT}"
    cid=$(docker create sam-nano-init:local)
    docker cp "${cid}:/nano-init" "${NANO_INIT}"
    docker rm "${cid}" >/dev/null
fi
file "${NANO_INIT}" | grep -q "statically linked" || { echo "ERROR: nano-init is not a static binary"; exit 1; }

echo "=== 4. Building Sandbox Container Image ==="
docker build -t agentsnet-demo demo/

echo "=== 5. Fail-Closed Check: no launcher, no network, no connections ==="
# The image knows nothing about agents.net; with --network none and no
# launcher, every connect() must fail. The image's entrypoint is the agent,
# so override it to run curl directly. Exit code 7 (couldn't connect) or
# 6 (couldn't resolve) both prove there is no way out.
set +e
docker run --rm --network none --entrypoint curl agentsnet-demo -s --max-time 5 https://example.com
NO_NET_RC=$?
set -e
if [ "${NO_NET_RC}" -eq 0 ]; then
    echo "ERROR: zero-network container reached the internet without the launcher!"
    exit 1
fi
echo "OK: connection failed as expected (rc=${NO_NET_RC})"

echo "=== 6. Starting Host Boundary ==="
rm -rf /tmp/agent-sockets /tmp/agent-proxy-audit.log
mkdir -p /tmp/agent-sockets
python3 demo/host_proxy.py &
PROXY_PID=$!

cleanup() {
    echo "=== Cleaning up ==="
    kill "${PROXY_PID}" 2>/dev/null || true
    rm -rf /tmp/agent-sockets /tmp/agent-proxy-audit.log
}
trap cleanup EXIT

for i in {1..30}; do
    [ -S /tmp/agent-sockets/egress-proxy.sock ] && break
    sleep 0.2
done
if [ ! -S /tmp/agent-sockets/egress-proxy.sock ]; then
    echo "ERROR: Host boundary socket was not created"
    exit 1
fi

# Every sandbox run below is the spec's recommended entrypoint injection:
# unmodified image, launcher bind-mounted read-only, three runtime flags.
run_sandboxed() {
    docker run --rm \
      --network none \
      --cap-add NET_ADMIN --device /dev/net/tun \
      -v /tmp/agent-sockets:/var/run/agents.net \
      -v "${NANO_INIT}:/nano-init:ro" \
      --entrypoint /nano-init \
      "$@"
}

echo "=== 7. Boundary + Trust: fake-response tier over real TLS ==="
OUTPUT=$(run_sandboxed agentsnet-demo \
  run /var/run/agents.net/egress-proxy.sock \
  curl -s https://example.com)
echo "${OUTPUT}"
if ! echo "${OUTPUT}" | grep -q "escaped the zero-network sandbox"; then
    echo "ERROR: Expected success message from fake response tier not found!"
    exit 1
fi

echo "=== 8. Deny-by-default: refused host observed as connection failure ==="
set +e
BLOCKED_OUTPUT=$(run_sandboxed agentsnet-demo \
  run /var/run/agents.net/egress-proxy.sock \
  curl -sv --max-time 10 https://blocked-host.example 2>&1)
BLOCKED_RC=$?
set -e
echo "${BLOCKED_OUTPUT}" | tail -3
if [ "${BLOCKED_RC}" -eq 0 ]; then
    echo "ERROR: curl to a non-allow-listed host succeeded!"
    exit 1
fi
# The SOCKS5 0x02 refusal surfaces in the guest as an immediate connection
# failure; the exact shape (refused at connect, or reset just after) is a
# guest-stack detail. Step 10 pins that the refusal came from policy.
if ! echo "${BLOCKED_OUTPUT}" | grep -qiE "connection refused|couldn't connect|reset by peer|SSL_ERROR_SYSCALL"; then
    echo "ERROR: Expected an immediate connection failure for the refused host!"
    exit 1
fi

echo "=== 9. Bidirectional: egress + ingress over the reverse channel ==="
AGENT_CONTAINER_ID=$(run_sandboxed -d agentsnet-demo \
  run --ingress-socket /var/run/agents.net/ingress-proxy.sock \
  /var/run/agents.net/egress-proxy.sock \
  python3 -c "import os, urllib.request, threading, time; from http.server import BaseHTTPRequestHandler, HTTPServer; p = int(os.environ.get('AGENT_INGRESS_PORT', 8081)); (lambda s: threading.Thread(target=s.serve_forever, daemon=True).start())(HTTPServer(('127.0.0.1', p), type('H', (BaseHTTPRequestHandler,), {'do_POST': lambda self: (self.send_response(200), self.end_headers(), self.wfile.write(b'Webhook processed securely\n'))}))); urllib.request.urlopen('http://example.com'); time.sleep(15)")

# Wait for the launcher to bring up tun0 and bind the ingress socket.
for i in {1..30}; do
    [ -S /tmp/agent-sockets/ingress-proxy.sock ] && break
    sleep 0.2
done

# The socket is created by container-root; open it to the unprivileged
# boundary from inside the container, where root owns the file.
docker exec "${AGENT_CONTAINER_ID}" chmod 666 /var/run/agents.net/ingress-proxy.sock

# The agent's loopback listener races container startup; retry briefly
# instead of failing on the first in-flight dial.
WEBHOOK_RESP=""
for i in {1..10}; do
    WEBHOOK_RESP=$(curl -s -X POST -d "hello from the outside world!" http://localhost:9000/webhook || true)
    echo "${WEBHOOK_RESP}" | grep -q "Webhook processed securely" && break
    sleep 1
done
echo "Webhook Response: ${WEBHOOK_RESP}"

docker stop "${AGENT_CONTAINER_ID}" >/dev/null 2>&1 || true

if ! echo "${WEBHOOK_RESP}" | grep -q "Webhook processed securely"; then
    echo "ERROR: Webhook response did not match expected output!"
    exit 1
fi

echo "=== 10. Verifying Audit Log ==="
if [ ! -f /tmp/agent-proxy-audit.log ]; then
    echo "ERROR: Audit log file was not created!"
    exit 1
fi

cat /tmp/agent-proxy-audit.log
grep -q "ALLOW-FAKE" /tmp/agent-proxy-audit.log || { echo "ERROR: ALLOW-FAKE missing in audit log"; exit 1; }
grep -q "BLOCK" /tmp/agent-proxy-audit.log || { echo "ERROR: BLOCK missing in audit log"; exit 1; }
grep -q "INGRESS" /tmp/agent-proxy-audit.log || { echo "ERROR: INGRESS missing in audit log"; exit 1; }

echo "=== ALL DEMO TESTS PASSED SUCCESSFULLY ==="
