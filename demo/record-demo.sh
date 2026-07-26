#!/bin/bash
# Regenerates the terminal recording embedded in README.md /
# demo/README.md. Not part of the sandbox itself.
set -e
cd "$(dirname "$0")/.."

rm -rf /tmp/agent-sockets /tmp/agent-proxy-audit.log
mkdir -p /tmp/agent-sockets
touch /tmp/agent-proxy-audit.log

type_out() {
  printf '$ %s\n' "$1"
  sleep 0.3
}

comment() {
  printf '\n# %s\n' "$1"
  sleep 0.3
}

comment "1. Start host-side agents.net proxy & ingress gateway"
type_out "python3 demo/host_proxy.py &"
python3 -u demo/host_proxy.py >/dev/null 2>&1 &
PROXY_PID=$!
sleep 1.0

comment "2. Verify Egress & Trust Contract inside container with --network none"
type_out "docker run --rm --network none \\"
echo '    -v /tmp/agent-sockets:/var/run/agents.net \'
echo '    -v "$(pwd)/demo/certs/agent-ca.pem:/var/run/agent-ca.pem:ro" \'
echo '    -e AGENT_NET_LEGACY_COMPAT=1 \'
echo '    agentsnet-demo curl -s https://example.com'

docker run --rm \
  --network none \
  -v /tmp/agent-sockets:/var/run/agents.net \
  -v "$(pwd)/demo/certs/agent-ca.pem:/var/run/agent-ca.pem:ro" \
  -e AGENT_NET_LEGACY_COMPAT=1 \
  agentsnet-demo curl -s https://example.com

sleep 1.0

comment "3. Verify Ingress Gateway Contract (Send webhook from host to zero-network agent)"
type_out "curl -X POST -d \"hello from outside world!\" http://localhost:9000/webhook"

AGENT_ID=$(docker run -d --rm \
  --network none \
  -v /tmp/agent-sockets:/var/run/agents.net \
  -v "${PWD}/demo/certs/agent-ca.pem:/var/run/agent-ca.pem:ro" \
  -e AGENT_NET_LEGACY_COMPAT=1 \
  agentsnet-demo python3 -c "import os, urllib.request, threading, time; from http.server import BaseHTTPRequestHandler, HTTPServer; p = int(os.environ.get('AGENT_INGRESS_PORT', 8081)); (lambda s: threading.Thread(target=s.serve_forever, daemon=True).start())(HTTPServer(('127.0.0.1', p), type('H', (BaseHTTPRequestHandler,), {'do_POST': lambda self: (self.send_response(200), self.end_headers(), self.wfile.write(b'Webhook processed securely\n'))}))); urllib.request.urlopen('http://example.com'); time.sleep(5)")

sleep 1.2
curl -X POST -d "hello from outside world!" http://localhost:9000/webhook
docker stop "${AGENT_ID}" >/dev/null 2>&1 || true

sleep 1.0

comment "4. Verify host-side proxy audit log (Egress + Ingress events)"
type_out "cat /tmp/agent-proxy-audit.log"
cat /tmp/agent-proxy-audit.log

sleep 2.0

kill "$PROXY_PID" 2>/dev/null || true
wait "$PROXY_PID" 2>/dev/null || true
