import argparse
from dataclasses import dataclass
from enum import Enum, auto
import sys


class State(Enum):
    PARSE_ARGS = auto()
    HANDLE_ARGS = auto()
    EXIT = auto()
    ERROR = auto()


@dataclass
class Context:
    filename: str | None = None
    username: str | None = None
    port: int | None = None


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

    args = parser.parse_args()

    ctx.filename = args.filename
    ctx.username = args.username
    ctx.port = args.port
    
    print(type(args))
    return State.HANDLE_ARGS
    

def handle_arguments(ctx: Context) -> State:
    print(ctx.filename)
    print(ctx.username)
    print(ctx.port)

    return State.EXIT


def exit_program(ctx: Context) -> State:
    print("Exiting program")
    sys.exit(0)


def error(ctx: Context) -> State:
    pass


def parse_shadow(ctx: Context) -> State:
    pass


def listen(ctx: Context) -> State:
    pass


def main():
    ctx = Context()
    state = State.PARSE_ARGS

    handlers = {
        State.PARSE_ARGS: parse_arguments,
        State.HANDLE_ARGS: handle_arguments,
        State.EXIT: exit_program
    }

    while True:
        state = handlers[state](ctx)
    

if __name__ == "__main__":
    main()