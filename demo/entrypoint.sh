#!/bin/sh
set -e

# Provide a directory for the sockets
SOCKET_DIR="/var/run/agents.net"
mkdir -p "$SOCKET_DIR"

# 1. Egress Bridge: Local TCP -> Host-mounted Unix Socket
# (Agent dialing out)
socat TCP-LISTEN:8080,fork,reuseaddr UNIX-CONNECT:$SOCKET_DIR/egress-proxy.sock &

# 2. Ingress Bridge: Host-mounted Unix Socket -> Local TCP
# (Host sending webhooks in. Container creates the socket file and listens)
rm -f "$SOCKET_DIR/ingress-proxy.sock"
socat UNIX-LISTEN:"$SOCKET_DIR/ingress-proxy.sock",fork,reuseaddr,unlink-early,mode=777 TCP:127.0.0.1:8081 &

sleep 0.2

# 3. Fulfill the Egress Contract
export AGENT_HTTP_PROXY="http://127.0.0.1:8080"
export AGENT_HTTPS_PROXY="http://127.0.0.1:8080"
export AGENT_NO_PROXY="localhost,127.0.0.1"

if [ "${AGENT_NET_LEGACY_COMPAT:-0}" = "1" ]; then
    export HTTP_PROXY="$AGENT_HTTP_PROXY"
    export HTTPS_PROXY="$AGENT_HTTPS_PROXY"
    export http_proxy="$AGENT_HTTP_PROXY"
    export https_proxy="$AGENT_HTTPS_PROXY"
    export NO_PROXY="$AGENT_NO_PROXY"
    export no_proxy="$AGENT_NO_PROXY"
fi

# 4. Fulfill the Trust Contract (if a CA is mounted)
if [ -f "/var/run/agent-ca.pem" ]; then
    export AGENT_CA_CERT="/var/run/agent-ca.pem"
    export REQUESTS_CA_BUNDLE="$AGENT_CA_CERT"
    export NODE_EXTRA_CA_CERTS="$AGENT_CA_CERT"
    export SSL_CERT_FILE="$AGENT_CA_CERT"
fi

# 5. Fulfill the Ingress Contract
export AGENT_INGRESS_PORT="${AGENT_INGRESS_PORT:-8081}"
export AGENT_PUBLIC_URL="${AGENT_PUBLIC_URL:-http://localhost:9000/webhook}"

# 6. Launch the Agent
exec "$@"
