#!/bin/bash
# Regenerates the terminal recording embedded in AGENTS_NET.md /
# AGENTS_NET_THE_HARD_WAY.md. Not part of the sandbox itself.
#
# Prerequisites:
#   docker build -t agentsnet-demo demo/
#   ./demo/gen_certs.sh
#   Ollama running with qwen3-coder:latest
#
# Usage:
#   asciinema rec -c "demo/record-demo.sh" --idle-time-limit 2 demo/terminal-demo.cast
#   agg --rows 35 demo/terminal-demo.cast demo/terminal-demo.gif --theme monokai --speed 2
set -e
cd "$(dirname "$0")/.."

MODEL="${DEMO_MODEL:-qwen3-coder:latest}"

rm -f /tmp/agent-proxy.sock /tmp/agent-proxy-audit.log
touch /tmp/agent-proxy-audit.log

type_out() {
  printf '$ %s\n' "$1"
  sleep 0.5
}

comment() {
  printf '\n# %s\n' "$1"
  sleep 0.5
}

comment "1. Start the host-side agents.net enforcement proxy"
type_out "python3 demo/host_proxy.py &"
python3 -u demo/host_proxy.py >/dev/null 2>&1 &
PROXY_PID=$!
sleep 1.5

comment "2. Run unmodified agent harness inside container with --network none"
PROMPT="Fetch https://example.com and https://google.com and report the status code for each. Nobody has told you how networking is configured in this sandbox -- inspect your environment and figure it out."

type_out "docker run --rm --network none \\"
echo '    -v /tmp/agent-proxy.sock:/var/run/agent-proxy.sock \'
echo '    -v "$(pwd)/demo/certs/agent-ca.pem:/var/run/agent-ca.pem:ro" \'
echo '    -e AGENT_NET_LEGACY_COMPAT=1 \'
echo "    agentsnet-demo opencode run --model ollama/$MODEL --auto \"$PROMPT\""

docker run --rm \
  --network none \
  -v /tmp/agent-proxy.sock:/var/run/agent-proxy.sock \
  -v "$(pwd)/demo/certs/agent-ca.pem:/var/run/agent-ca.pem:ro" \
  -e AGENT_NET_LEGACY_COMPAT=1 \
  agentsnet-demo \
  opencode run --model "ollama/$MODEL" --auto "$PROMPT"

sleep 2

comment "3. Verify host-side proxy audit log"
type_out "tail -n 8 /tmp/agent-proxy-audit.log"
tail -n 8 /tmp/agent-proxy-audit.log

sleep 5

kill "$PROXY_PID" 2>/dev/null || true
wait "$PROXY_PID" 2>/dev/null || true
