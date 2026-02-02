import argparse
from dataclasses import dataclass, field
from enum import Enum, auto
import socket
import sys


class State(Enum):
    PARSE_ARGS = auto()
    HANDLE_ARGS = auto()
    CONNECT = auto()
    CLEANUP = auto()
    ERROR = auto()


@dataclass
class Settings:
    controller_host: str | None = None
    controller_port: int | None = None


@dataclass
class Context:
    args: argparse.Namespace | None = None
    settings: Settings = field(default_factory=Settings)
    exit_message: str | None = None
    sock: socket.socket | None = None  # connection to controller


def parse_arguments(ctx: Context) -> State:
    parser = argparse.ArgumentParser(
        prog="UNIX Password Cracker Worker",
        description="Worker node that connects to controller and executes cracking jobs."
    )
    
    parser.add_argument("-c", "--controller",
        required=True,
        help="Controller host or IP"
    )
    
    parser.add_argument("-p", "--port",
        required=True,
        type=int,
        help="Controller port"
    )
    
    ctx.args = parser.parse_args()
    return State.HANDLE_ARGS


def handle_arguments(ctx: Context) -> State:
    args = ctx.args

    if not (1024 <= args.port <= 65535):
        ctx.exit_message = "Port must be between 1024 and 65535"
        return State.ERROR

    ctx.settings.controller_host = args.controller
    ctx.settings.controller_port = args.port
    return State.CONNECT


def connect(ctx: Context) -> State:
    host = ctx.settings.controller_host
    port = ctx.settings.controller_port

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host, port))
        ctx.sock = s

        print(f"Connected to controller at {host}:{port}")
        return State.CLEANUP  # TEMP for now (later -> REGISTER)

    except OSError as e:
        ctx.exit_message = f"Connect failed: {e}"
        return State.ERROR


def error(ctx: Context) -> State:
    print(ctx.exit_message or "Unknown error")
    return State.CLEANUP


def cleanup(ctx: Context) -> State:
    if ctx.sock:
        ctx.sock.close()
    sys.exit(0)


def main():
    ctx = Context()
    state = State.PARSE_ARGS

    handlers = {
        State.PARSE_ARGS: parse_arguments,
        State.HANDLE_ARGS: handle_arguments,
        State.CONNECT: connect,
        State.CLEANUP: cleanup,
    }

    while True:
        state = handlers[state](ctx)


if __name__ == "__main__":
    main()

