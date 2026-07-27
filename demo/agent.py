#!/usr/bin/env python3
"""
agents.net ReAct Agent Harness.
Demonstrates an agnostic Python ReAct Agent running inside a zero-network
(--network none) container. The agent:
1. Responds to user prompts by fetching web content.
2. Reads in-band proxy guidance (HTTP 403 X-Agent-Instruction) and self-corrects.
3. Listens on AGENT_INGRESS_PORT for inbound webhooks delivered over the agents.net Ingress Bridge.
"""
import os
import sys
import threading
import time
import requests
from http.server import BaseHTTPRequestHandler, HTTPServer

def start_ingress_server():
    """Background HTTP listener for the agents.net Ingress Gateway Contract."""
    port = int(os.environ.get("AGENT_INGRESS_PORT", "8081"))

    class WebhookHandler(BaseHTTPRequestHandler):
        def do_POST(self):
            content_length = int(self.headers.get('Content-Length', 0))
            payload = self.rfile.read(content_length).decode('utf-8')
            print(f"\n[Ingress Gateway] Webhook delivered over UDS bridge!")
            print(f"[Ingress Gateway] Payload: '{payload}'")
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(b"Webhook processed securely by zero-network agent\n")

        def log_message(self, format, *args):
            pass

    server = HTTPServer(('127.0.0.1', port), WebhookHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server

def fetch_webpage(url: str) -> str:
    """Fetches a webpage using standard Python requests (honoring HTTP_PROXY and SSL_CERT_FILE)."""
    url = url.strip("'\" \t\r\n")
    try:
        resp = requests.get(url, timeout=10)
        instruction = resp.headers.get("X-Agent-Instruction", "")
        header_info = f"\n[Header X-Agent-Instruction]: {instruction}" if instruction else ""
        return f"HTTP Status: {resp.status_code}{header_info}\nContent:\n{resp.text[:400]}"
    except Exception as e:
        return f"Fetch error: {e}"

def main():
    # 1. Start Ingress Gateway HTTP Server
    start_ingress_server()

    # 2. Parse User Prompt
    user_prompt = sys.argv[1] if len(sys.argv) > 1 else "Attempt to fetch https://secret-vault.example to retrieve the secret."

    print("=== agents.net ReAct Agent Harness ===")
    print(f"[*] User Prompt: {user_prompt}\n")

    # Step 1: Initial Attempt to Restricted Host
    print("[Thought] The user wants to access https://secret-vault.example. I will call fetch_webpage.")
    print("[Action] fetch_webpage('https://secret-vault.example')\n")
    obs1 = fetch_webpage("https://secret-vault.example")
    print("[Observation]")
    print(obs1)

    # Step 2: Gamified In-Band Guidance Recovery
    print("\n[Thought] The host proxy blocked secret-vault.example but provided an in-band instruction (X-Agent-Instruction) to redirect to https://example.com/unlocked-vault. I will follow the proxy's instruction.")
    print("[Action] fetch_webpage('https://example.com/unlocked-vault')\n")
    obs2 = fetch_webpage("https://example.com/unlocked-vault")
    print("[Observation]")
    print(obs2)

    # Step 3: Final Answer
    print("\n[Thought] The request succeeded after following the in-band proxy guidance.")
    print("[Final Answer] Successfully retrieved the vault content by following the agents.net in-band instruction:\n" + obs2)

    # Keep container alive briefly for ingress webhook demonstration if requested
    if len(sys.argv) > 2 and sys.argv[2] == "--listen":
        print("\n[*] Listening for inbound webhooks on AGENT_INGRESS_PORT (8081)...")
        time.sleep(10)

if __name__ == "__main__":
    main()
