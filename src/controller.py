import argparse
from dataclasses import dataclass, field
from enum import Enum, auto
import sys
import socket


class State(Enum):
    PARSE_ARGS = auto()
    HANDLE_ARGS = auto()
    PARSE_SHADOW = auto()
    LISTEN = auto()
    WAIT_REGISTER = auto()
    RECEIVE_REGISTRATION = auto()
    DISPATCH_JOB = auto()
    CLEANUP = auto()
    ERROR = auto()


@dataclass
class Settings:
    filename: str | None = None
    username: str | None = None
    port: int | None = None


@dataclass
class ShadowInfo:
    alg_id: str | None = None
    salt: str | None = None
    hash: str | None = None
    full: str | None = None   


@dataclass
class Context:
    args: argparse.Namespace | None = None      
    settings: Settings = field(default_factory=Settings)
    exit_message: str | None = None
    shadow: ShadowInfo = field(default_factory=ShadowInfo)
    server_sock: socket.socket | None = None   # listening socket
    worker_sock: socket.socket | None = None   # accepted connection
    worker_addr: tuple[str, int] | None = None
    

def parse_arguments(ctx: Context) -> State:
    parser = argparse.ArgumentParser(
        prog="UNIX Password Cracker Controller",
        description="This is a control server that manages distributed password cracking.",
        epilog=""
    )
    

    parser.add_argument(
        "-f", "--filename",
        type=str, 
        help="Name of shadow file", 
        required=True
    )

    parser.add_argument(
        "-u", "--username",
        type=str, 
        help="Username whose password being cracked", 
        required=True
    )

    parser.add_argument(
        "-p", "--port",
        type=int, 
        help="Port number control server runs on", 
        required=True
    )

    ctx.args = parser.parse_args()
    
    return State.HANDLE_ARGS
    

def handle_arguments(ctx: Context) -> State:
    args = ctx.args
    if not (1024 <= args.port <= 65535):
        ctx.exit_message = "Port must be between 1024 and 65535"
        return State.ERROR

    try:
        with open(args.filename, "r"):
            pass
    except FileNotFoundError:
        ctx.exit_message = "Shadow file not found"
        return State.ERROR
    except PermissionError:
        ctx.exit_message = "Shadow file not readable"
        return State.ERROR

    ctx.settings.filename = args.filename
    ctx.settings.username = args.username
    ctx.settings.port = args.port

    return State.PARSE_SHADOW

def cleanup(ctx: Context) -> State:
    if ctx.worker_sock:
        ctx.worker_sock.close()
    if ctx.server_sock:
        ctx.server_sock.close()

    print("Exiting program")
    sys.exit(0)


def error(ctx: Context) -> State:
    print(ctx.exit_message)
    return State.CLEANUP


def parse_shadow(ctx: Context) -> State:
    username = ctx.settings.username
    filename = ctx.settings.filename

    try:
        with open(filename, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                fields = line.split(":")
                if len(fields) < 2:
                    continue  # malformed line

                user = fields[0]
                pw_field = fields[1]

                if user != username:
                    continue

                # Found the user
                if pw_field in ("", "!", "*", "!!"):
                    ctx.exit_message = f"User '{username}' has no usable hash (locked/empty)."
                    return State.ERROR

                # Store raw hash field
                ctx.shadow.full = pw_field

                # Hash formats: $id$salt$hash  (per your class pdf) :contentReference[oaicite:2]{index=2}
                if pw_field.startswith("$"):
                    toks = pw_field.split("$")
                    # Example: ["", "6", "randomsalt", "hashedpassword"]
                    if len(toks) >= 2:
                        ctx.shadow.alg_id = toks[1]
                    if len(toks) >= 3:
                        ctx.shadow.salt = toks[2]
                    if len(toks) >= 4:
                        ctx.shadow.hash = toks[3]
                else:
                    # Some systems may store non-$ formats; keep full and fail later if needed
                    ctx.shadow.alg_id = None

                return State.LISTEN 
    except:
        ctx.exit_message = f"Username '{username}' not found in shadow file"
        return State.ERROR



def listen(ctx: Context) -> State:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", ctx.settings.port))
        s.listen(1)

        ctx.server_sock = s
        print(f"Listening on port {ctx.settings.port}")

        return State.WAIT_REGISTER

    except OSError as e:
        ctx.exit_message = f"Listen failed: {e}"
        return State.ERROR
    

def accept_worker(ctx: Context) -> State:
    try:
        conn, addr = ctx.server_sock.accept()
        ctx.worker_sock = conn
        ctx.worker_addr = addr
        print(f"Worker connected from {addr[0]}:{addr[1]}")
        return State.RECEIVE_REGISTRATION
    except OSError as e:
        ctx.exit_message = f"Accept failed: {e}"
        return State.ERROR


def receive_registration(ctx: Context) -> State:
    if ctx.worker_sock is None:
        ctx.exit_message = "No worker socket to register"
        return State.ERROR

    try:
        data = ctx.worker_sock.recv(64)
        if not data:
            ctx.exit_message = "Worker disconnected before registering"
            return State.ERROR

        msg = data.decode("utf-8", errors="replace").strip()
        if msg != "REGISTER":
            ctx.worker_sock.sendall(b"ERR expected REGISTER\n")
            ctx.exit_message = f"Bad registration message: {msg}"
            return State.ERROR

        ctx.worker_sock.sendall(b"OK\n")
        print("Worker registered")
        return State.DISPATCH_JOB

    except OSError as e:
        ctx.exit_message = f"Registration recv failed: {e}"
        return State.ERROR


def dispatch_job(ctx: Context) -> State:
    print("DISPATCH_JOB reached (stub)")
    return State.CLEANUP


def main():
    ctx = Context()
    state = State.PARSE_ARGS

    handlers = {
        State.PARSE_ARGS: parse_arguments,
        State.HANDLE_ARGS: handle_arguments,
        State.PARSE_SHADOW: parse_shadow,
        State.LISTEN: listen,
        State.WAIT_REGISTER: accept_worker,
        State.RECEIVE_REGISTRATION: receive_registration,
        State.DISPATCH_JOB: dispatch_job,
        State.CLEANUP: cleanup
    }

    while True:
        state = handlers[state](ctx)
    

if __name__ == "__main__":
    main()