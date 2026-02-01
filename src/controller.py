import argparse
from dataclasses import dataclass, field
from enum import Enum, auto
import sys


class State(Enum):
    PARSE_ARGS = auto()
    HANDLE_ARGS = auto()
    PARSE_SHADOW = auto()
    EXIT = auto()
    ERROR = auto()


@dataclass
class Settings:
    filename: str | None = None
    username: str | None = None
    port: int | None = None


@dataclass
class Context:
    args: argparse.Namespace | None = None      
    settings: Settings = field(default_factory=Settings)
    exit_message: str | None = None
    

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

def exit_program(ctx: Context) -> State:
    print("Exiting program")
    sys.exit(0)


def error(ctx: Context) -> State:
    pass


def parse_shadow(ctx: Context) -> State:
    print(ctx.settings)
    
    return State.EXIT


def listen(ctx: Context) -> State:
    pass


def main():
    ctx = Context()
    state = State.PARSE_ARGS

    handlers = {
        State.PARSE_ARGS: parse_arguments,
        State.HANDLE_ARGS: handle_arguments,
        State.PARSE_SHADOW: parse_shadow,
        State.EXIT: exit_program
    }

    while True:
        state = handlers[state](ctx)
    

if __name__ == "__main__":
    main()