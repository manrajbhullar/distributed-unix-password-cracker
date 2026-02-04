import socket
import json
import struct
from typing import Any


def send_msg(sock: socket.socket, obj: Any) -> None:
    payload = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    header = struct.pack("!I", len(payload))
    sock.sendall(header + payload)


def recv_msg(sock: socket.socket) -> Any:
    header = _recv_exact(sock, 4)
    (n,) = struct.unpack("!I", header)
    payload = _recv_exact(sock, n)
    return json.loads(payload.decode("utf-8"))


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise OSError("ERROR: Connection closed while reading data")
        data += chunk
    return data


def recv_with_timeout(sock: socket.socket, seconds: float=5.0):
    old = sock.gettimeout()
    sock.settimeout(seconds)
    try:
        return recv_msg(sock)
    finally:
        sock.settimeout(old)