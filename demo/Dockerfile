# The sandbox image for the agents.net reference demo.
#
# Deliberately, this image knows NOTHING about agents.net: no launcher, no
# proxy variables, no bridge scripts, no socket paths. It is just a harness
# and its dependencies. The Boundary Contract is applied entirely from the
# outside, at `docker run` time, by entrypoint injection (see the README's
# "Injecting the launcher" section):
#
#   docker run --rm --network none \
#     --cap-add NET_ADMIN --device /dev/net/tun \
#     -v "$SOCKET_DIR":/var/run/agents.net \
#     -v "$NANO_INIT":/nano-init:ro \
#     --entrypoint /nano-init \
#     agents-net-demo \
#     run /var/run/agents.net/egress-proxy.sock \
#     python3 /demo/agent.py "Fetch https://example.com and report its status code."
#
# (For inbound traffic add `--ingress-socket <path>` BEFORE the boundary
# socket -- the launcher stops parsing flags at the first positional
# argument; everything after it belongs to the agent. See the demo README's
# ingress lab.)
#
# The launcher (nano-init, a dependency-free static binary consumed from the
# SAM project) becomes PID 1, builds the tun that is the sandbox's only route,
# and delivers every flow to the host boundary as SOCKS5 naming its
# destination. The harness below runs unmodified behind it.
#
# Swap in any other harness by editing this one file: the only requirement is
# that it runs non-interactively and reads its credentials from its own
# environment (an interactive OAuth/browser flow can't complete in a
# disposable --network none container).
FROM debian:bookworm-slim
# curl/dig/nc give a normal recon toolkit for poking at the boundary from
# inside; ca-certificates is required for TLS the boundary relays untouched.
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl ca-certificates iproute2 dnsutils netcat-openbsd python3 python3-pip python3-venv \
    && rm -rf /var/lib/apt/lists/*

# Install production LangChain ReAct Agent framework dependencies
RUN pip install --no-cache-dir --break-system-packages \
        requests \
        langchain \
        langchain-core \
        langchain-community \
        langchain-ollama

# Trust Convention (opt-in): bake the demo CA into the system trust store so
# TLS-inspected tiers (fake-response, credential-inject) validate. This is
# coordination, not enforcement -- an image built without it still cannot
# reach anything the boundary denies; its own requests to inspected domains
# simply fail TLS. Runtimes with private trust stores get the env vars.
COPY certs/agent-ca.pem /usr/local/share/ca-certificates/agents-net-demo-ca.crt
RUN update-ca-certificates
ENV AGENT_CA_CERT=/etc/ssl/certs/ca-certificates.crt \
    REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt \
    SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
    NODE_EXTRA_CA_CERTS=/etc/ssl/certs/ca-certificates.crt

COPY agent.py /demo/agent.py
RUN chmod +x /demo/agent.py

# The image's own entrypoint runs the agent DIRECTLY -- no proxy env, no
# bridges. Run it this way (with --network none and no launcher) to watch the
# zero-network sandbox fail closed: every connect() is unreachable.
ENTRYPOINT ["python3", "/demo/agent.py"]
CMD ["Fetch https://example.com and report its status code."]
