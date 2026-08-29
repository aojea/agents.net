#!/bin/bash
# Regenerates the terminal recording embedded in README.md /
# demo/README.md. Not part of the sandbox itself.
#
# Needs demo/tun2connect (see demo/README.md Lab 3) and the agentsnet-demo
# image built (Lab 5). Run under asciinema:
#   asciinema rec -c ./demo/record-demo.sh demo/terminal-demo.cast
set -e
cd "$(dirname "$0")/.."

if [ ! -x demo/tun2connect ]; then
    echo "demo/tun2connect missing -- follow demo/README.md Lab 3 first" >&2
    exit 1
fi

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

comment "1. Start the host-side agents.net boundary (HTTP CONNECT) & ingress gateway"
type_out "python3 demo/host_proxy.py &"
python3 -u demo/host_proxy.py >/dev/null 2>&1 &
PROXY_PID=$!
sleep 2.5

MODEL="${DEMO_MODEL:-qwen2.5:0.5b}"

# Pre-warm model in Ollama RAM so token generation is instant during recording
curl -s http://127.0.0.1:11434/api/generate -d "{\"model\": \"$MODEL\", \"prompt\": \"hi\", \"stream\": false}" >/dev/null 2>&1 || true

comment "2. Run the unmodified agent in a zero-network container, confined by the injected launcher"
PROMPT="Attempt to access https://secret-vault.example to retrieve the secret. If it is refused, fetch https://example.com instead and report its status code."

type_out "docker run --rm --network none \\"
echo '    --cap-add NET_ADMIN --device /dev/net/tun \'
echo '    -v /tmp/agent-sockets:/var/run/agents.net \'
echo '    -v "$(pwd)/demo/tun2connect:/tun2connect:ro" \'
echo '    --entrypoint /tun2connect \'
echo '    agentsnet-demo \'
echo '    run /var/run/agents.net/egress-proxy.sock \'
echo "    python3 /demo/agent.py \"$PROMPT\""

# stderr silenced: the launcher logs each refused dial there, and the audit
# log at the end shows the same thing without the noise.
docker run --rm \
  --network none \
  --cap-add NET_ADMIN --device /dev/net/tun \
  -v /tmp/agent-sockets:/var/run/agents.net \
  -v "$(pwd)/demo/tun2connect:/tun2connect:ro" \
  --entrypoint /tun2connect \
  agentsnet-demo \
  run /var/run/agents.net/egress-proxy.sock \
  python3 /demo/agent.py "$PROMPT" 2>/dev/null

sleep 5.0

comment "3. Ingress: deliver a webhook from the host into the zero-network agent"
type_out "curl -X POST -d \"Incoming Task: Process secret payload\" http://localhost:9000/webhook"

# A long-lived listener so the webhook cannot race the agent's exit.
AGENT_ID=$(docker run -d --rm \
  --network none \
  --cap-add NET_ADMIN --device /dev/net/tun \
  -v /tmp/agent-sockets:/var/run/agents.net \
  -v "${PWD}/demo/tun2connect:/tun2connect:ro" \
  --entrypoint /tun2connect \
  agentsnet-demo \
  run --ingress-socket /var/run/agents.net/ingress-proxy.sock \
  /var/run/agents.net/egress-proxy.sock \
  python3 -c "import os, threading, time; from http.server import BaseHTTPRequestHandler, HTTPServer; p = int(os.environ.get('AGENT_INGRESS_PORT', 8081)); (lambda s: threading.Thread(target=s.serve_forever, daemon=True).start())(HTTPServer(('127.0.0.1', p), type('H', (BaseHTTPRequestHandler,), {'do_POST': lambda self: (self.send_response(200), self.end_headers(), self.wfile.write(b'Webhook processed securely by zero-network agent'))}))); time.sleep(60)")

for i in {1..30}; do
    [ -S /tmp/agent-sockets/ingress-proxy.sock ] && break
    sleep 0.2
done
sleep 0.5

curl -X POST -d "Incoming Task: Process secret payload" http://localhost:9000/webhook
echo
docker stop "${AGENT_ID}" >/dev/null 2>&1 || true

sleep 4.0

comment "4. The host-side audit trail: every flow named, decided, and logged"
type_out "cat /tmp/agent-proxy-audit.log"
cat /tmp/agent-proxy-audit.log

sleep 6.0

kill "$PROXY_PID" 2>/dev/null || true
wait "$PROXY_PID" 2>/dev/null || true
