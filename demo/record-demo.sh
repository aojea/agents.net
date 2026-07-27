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
sleep 2.5

MODEL="${DEMO_MODEL:-qwen2.5:0.5b}"

# Pre-warm model in Ollama RAM so token generation is instant during recording
curl -s http://127.0.0.1:11434/api/generate -d "{\"model\": \"$MODEL\", \"prompt\": \"hi\", \"stream\": false}" >/dev/null 2>&1 || true

comment "2. Run ReAct agent in zero-network container (--network none) with Gamified In-Band Guidance"
PROMPT="Attempt to access https://secret-vault.example to retrieve the secret."

type_out "docker run --rm --network none \\"
echo '    -v /tmp/agent-sockets:/var/run/agents.net \'
echo '    -v "$(pwd)/demo/certs/agent-ca.pem:/var/run/agent-ca.pem:ro" \'
echo '    -e AGENT_NET_LEGACY_COMPAT=1 \'
echo "    agentsnet-demo python3 /demo/agent.py \"$PROMPT\""

docker run --rm \
  --network none \
  -v /tmp/agent-sockets:/var/run/agents.net \
  -v "$(pwd)/demo/certs/agent-ca.pem:/var/run/agent-ca.pem:ro" \
  -e AGENT_NET_LEGACY_COMPAT=1 \
  agentsnet-demo \
  python3 /demo/agent.py "$PROMPT"

sleep 5.0

comment "3. Verify Ingress Gateway Contract (Send webhook from host to zero-network agent listener)"
type_out "curl -X POST -d \"Incoming Task: Process secret payload\" http://localhost:9000/webhook"

AGENT_ID=$(docker run -d --rm \
  --network none \
  -v /tmp/agent-sockets:/var/run/agents.net \
  -v "${PWD}/demo/certs/agent-ca.pem:/var/run/agent-ca.pem:ro" \
  -e AGENT_NET_LEGACY_COMPAT=1 \
  agentsnet-demo python3 /demo/agent.py "$PROMPT" --listen)

sleep 2.0
curl -X POST -d "Incoming Task: Process secret payload" http://localhost:9000/webhook
docker stop "${AGENT_ID}" >/dev/null 2>&1 || true

sleep 4.0

comment "4. Verify host-side proxy audit log (Egress + Ingress events)"
type_out "cat /tmp/agent-proxy-audit.log"
cat /tmp/agent-proxy-audit.log

sleep 6.0

kill "$PROXY_PID" 2>/dev/null || true
wait "$PROXY_PID" 2>/dev/null || true
