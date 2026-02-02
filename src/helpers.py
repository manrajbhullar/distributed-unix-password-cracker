import json, struct

def send_msg(sock, obj: dict) -> None:
    payload = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    sock.sendall(struct.pack("!I", len(payload)))
    sock.sendall(payload)

def recv_msg(sock) -> dict:
    header = sock.recv(4)
    if len(header) < 4:
        raise OSError("connection closed while reading header")

    (n,) = struct.unpack("!I", header)
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise OSError("connection closed while reading payload")
        data += chunk

    return json.loads(data.decode("utf-8"))
