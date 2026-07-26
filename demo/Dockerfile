FROM debian:bookworm-slim
# curl/dig/nc give a normal recon toolkit; ca-certificates is required for
# TLS verification of anything the proxy forwards.
RUN apt-get update && apt-get install -y --no-install-recommends \
        socat curl ca-certificates iproute2 dnsutils netcat-openbsd python3 \
    && rm -rf /var/lib/apt/lists/*

# Install the real, unmodified OpenCode CLI as the agent harness -- no
# agents.net-aware patches, no custom transport code.
# https://github.com/anomalyco/opencode
#
# Chosen specifically because it supports a one-shot, non-interactive
# `opencode run --auto` subcommand, and it natively honors the standard
# HTTP(S)_PROXY / NO_PROXY / NODE_EXTRA_CA_CERTS environment variables (see
# https://opencode.ai/docs/network) -- no code changes needed for it to
# respect this sandbox's egress contract. Its provider system also treats
# ANY OpenAI-compatible backend the same way, whether that's a free local
# model server (Ollama, see opencode.json) or a real paid cloud API -- so
# swapping between them is a config change only, never a rebuild.
RUN curl -fsSL https://opencode.ai/install | bash
ENV PATH="/root/.opencode/bin:${PATH}"

COPY opencode.json /root/.config/opencode/opencode.json
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
# --auto: Docker's own --network none + this proxy's ACL IS the sandbox
#   boundary here, so OpenCode's own interactive permission prompts (which
#   have nothing to attach to in a headless container anyway) are turned off
#   rather than double-sandboxed.
CMD ["opencode", "run", \
     "--model", "ollama/qwen3-coder:latest", \
     "--auto", \
     "Fetch https://example.com and report its HTTP status code and the first 200 characters of the response body. Nobody has told you how networking is configured in this sandbox -- inspect your environment and figure it out."]

