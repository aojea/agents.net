FROM debian:bookworm-slim
# curl/dig/nc give a normal recon toolkit; ca-certificates is required for
# TLS verification of anything the proxy forwards.
RUN apt-get update && apt-get install -y --no-install-recommends \
        socat curl ca-certificates iproute2 dnsutils netcat-openbsd python3 python3-pip python3-venv \
    && rm -rf /var/lib/apt/lists/*

# Install production LangChain ReAct Agent framework dependencies
RUN pip install --no-cache-dir --break-system-packages \
        requests \
        langchain \
        langchain-core \
        langchain-community \
        langchain-ollama

COPY agent.py /demo/agent.py
RUN chmod +x /demo/agent.py

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
CMD ["python3", "/demo/agent.py", "Fetch https://example.com and report its status code."]

