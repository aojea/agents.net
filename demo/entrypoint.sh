#!/bin/sh
set -e

# 1. Bridge local TCP to the host-mounted Unix Socket
socat TCP-LISTEN:8080,fork,reuseaddr UNIX-CONNECT:/var/run/agent-proxy.sock &
sleep 0.2

# 2. Fulfill the Proxy Contract. This is the ONLY thing the sandbox
#    guarantees. On purpose we do NOT export the conventional HTTP_PROXY /
#    http_proxy variables by default: the agent under test isn't told how
#    networking is wired up, so it has to discover AGENT_HTTP_PROXY /
#    AGENT_HTTPS_PROXY itself (e.g. by running `env`) and decide how to use
#    it (curl -x, requests `proxies=`, etc.).
#
#    Set AGENT_NET_LEGACY_COMPAT=1 to additionally export the conventional
#    variables, demonstrating the "zero code changes" compatibility mode
#    instead of the discovery challenge -- required for this demo, since
#    OpenCode (like the vast majority of existing tools) honors the
#    conventional HTTPS_PROXY/HTTP_PROXY names, not the AGENT_* ones.
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

# 3. Fulfill the Trust Contract (if a CA is mounted)
if [ -f "/var/run/agent-ca.pem" ]; then
    export AGENT_CA_CERT="/var/run/agent-ca.pem"
    export REQUESTS_CA_BUNDLE="$AGENT_CA_CERT"
    export NODE_EXTRA_CA_CERTS="$AGENT_CA_CERT"
    export SSL_CERT_FILE="$AGENT_CA_CERT"
fi

# 4. Launch the Agent
exec "$@"
