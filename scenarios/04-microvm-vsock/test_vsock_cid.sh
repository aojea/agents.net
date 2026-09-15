#!/usr/bin/env bash
# test_vsock_cid.sh: Local VSOCK peer-address smoke test, not VM attestation.
set -euo pipefail

python3 -c "
import socket, threading, time

TEST_PORT = 10051

server = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
server.bind((socket.VMADDR_CID_ANY, TEST_PORT))
server.listen(1)

resolved_identity = None

def server_loop():
    global resolved_identity
    conn, addr = server.accept()
    peer_cid, peer_port = addr
    
    # Read incoming request
    buf = conn.recv(4096).decode('utf-8', errors='ignore')
    
    # Emulate Host Boundary Proxy Header Sanitization:
    # 1. Ignore any guest-supplied X-Capsule-ID
    # 2. Derive trusted identity from the kernel peer_cid
    trusted_capsule_id = f'capsule-microvm-cid-{peer_cid}'
    
    resolved_identity = {
        'guest_claimed_header': 'forged-guest-id' in buf,
        'kernel_peer_cid': peer_cid,
        'trusted_capsule_id': trusted_capsule_id
    }
    
    conn.sendall(b'HTTP/1.1 200 OK\r\nX-Capsule-ID: ' + trusted_capsule_id.encode() + b'\r\n\r\n')
    conn.close()

th = threading.Thread(target=server_loop, daemon=True)
th.start()
time.sleep(0.1)

# Guest client attempts to forge identity headers
client = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
client.connect((1, TEST_PORT))
payload = (
    'CONNECT api.example.com:443 HTTP/1.1\r\n'
    'Host: api.example.com:443\r\n'
    'X-Capsule-ID: forged-guest-id\r\n'
    'Sandbox-Id: malicious-sandbox\r\n\r\n'
)
client.sendall(payload.encode())
resp = client.recv(4096).decode()
client.close()
server.close()

print(f'Kernel Peer CID: {resolved_identity[\"kernel_peer_cid\"]}')
print(f'Trusted Host Capsule ID: {resolved_identity[\"trusted_capsule_id\"]}')
assert resolved_identity['trusted_capsule_id'] == 'capsule-microvm-cid-1'
assert 'forged-guest-id' not in resp
print('  [PASS] Local VSOCK peer CID is independent of request headers; no VM or attestation tested')
"
