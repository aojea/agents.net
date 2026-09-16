#!/usr/bin/env python3
"""Deliver one HTTP request into a Firecracker guest over hybrid vsock.

Host side of the ingress channel: connect to Firecracker's vsock Unix socket,
ask it for the guest's ingress port ("CONNECT <port>" -> "OK <hostport>"),
then perform the launcher's own handshake ("CONNECT <loopback port>" ->
"OK") and send the request. Prints the response body.
"""
import socket
import sys


def read_line(sock: socket.socket) -> str:
    buf = b""
    while not buf.endswith(b"\n"):
        chunk = sock.recv(1)
        if not chunk:
            raise ConnectionError(f"peer closed during handshake after {buf!r}")
        buf += chunk
        if len(buf) > 128:
            raise ConnectionError("oversized handshake reply")
    return buf.decode(errors="replace").strip()


def main() -> int:
    if len(sys.argv) != 4:
        print(f"usage: {sys.argv[0]} <firecracker-vsock-uds> <guest-vsock-port> <loopback-port>", file=sys.stderr)
        return 2
    uds, guest_port, loopback_port = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(10)
        sock.connect(uds)
        sock.sendall(f"CONNECT {guest_port}\n".encode())
        reply = read_line(sock)
        if not reply.startswith("OK"):
            print(f"firecracker refused: {reply}", file=sys.stderr)
            return 1
        sock.sendall(f"CONNECT {loopback_port}\n".encode())
        reply = read_line(sock)
        if reply != "OK":
            print(f"launcher refused: {reply}", file=sys.stderr)
            return 1
        sock.sendall(b"GET /index.html HTTP/1.0\r\nHost: guest\r\n\r\n")
        response = b""
        while True:
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            response += chunk
        head, _, body = response.partition(b"\r\n\r\n")
        status = head.split(b"\r\n", 1)[0].decode(errors="replace")
        print(f"INGRESS status={status!r} body={body.strip().decode(errors='replace')!r}")
        return 0 if status.startswith("HTTP/1.") and " 200 " in status else 1


if __name__ == "__main__":
    sys.exit(main())
