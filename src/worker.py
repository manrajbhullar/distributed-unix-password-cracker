import argparse
from dataclasses import dataclass, field
from enum import Enum, auto
import socket
import sys
import itertools
import time
import crypt

from helpers import send_msg, recv_msg


class State(Enum):
    PARSE_ARGS = auto()
    HANDLE_ARGS = auto()
    CONNECT = auto()
    REGISTER = auto()
    WAIT_JOB = auto()
    CRACK = auto()
    SEND_RESULT = auto()
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
    job_data: dict | None = None


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
        return State.REGISTER

    except OSError as e:
        ctx.exit_message = f"Connect failed: {e}"
        return State.ERROR


def register(ctx: Context) -> State:
    try:
        ctx.sock.sendall(b"REGISTER\n")

        data = ctx.sock.recv(64)
        if not data:
            ctx.exit_message = "Controller closed connection during registration"
            return State.ERROR

        msg = data.decode("utf-8", errors="replace").strip()
        if msg != "OK":
            ctx.exit_message = f"Registration rejected: {msg}"
            return State.ERROR

        print("Registered with controller")
        return State.WAIT_JOB

    except OSError as e:
        ctx.exit_message = f"Register failed: {e}"
        return State.ERROR


def receive_job(ctx: Context) -> State:
    try:
        job = recv_msg(ctx.sock)

        if job.get("type") != "job":
            ctx.exit_message = f"Unexpected message type: {job.get('type')}"
            return State.ERROR

        ctx.job_data = job # Save the job for the CRACK state
        print(f"Job {job['job_id']} received. Starting to crack...")
        return State.CRACK

    except OSError as e:
        ctx.exit_message = f"Receive job failed: {e}"
        return State.ERROR


def crack(ctx: Context) -> State:
    job = ctx.job_data
    target_hash = job["hash_full"]
    charset = job["charset"]
    
    # Pre-cache function lookups to avoid global lookups in the loop
    do_crypt = crypt.crypt
    do_join = "".join
    
    start_time = time.time()
    found_password = None
    attempts = 0
    status_message = "Search Exhausted"

    print(f"Cracking {job['username']}...")
    
    try:
        for length in itertools.count(1): 
            # product() is a generator; it's fast. 
            # But the 'for' loop around it is the Python bottleneck.
            for combo in itertools.product(charset, repeat=length):
                attempts += 1
                
                # OPTIMIZATION: Call join directly inside the crypt call.
                # This avoids creating a named variable 'candidate' in the local scope.
                if do_crypt(do_join(combo), target_hash) == target_hash:
                    found_password = do_join(combo)
                    break
            
            if found_password:
                break
                
    except KeyboardInterrupt:
        status_message = "Manually Interrupted"
    except Exception as e:
        status_message = f"Runtime Error: {str(e)}"

    end_time = time.time()
    ctx.job_data["result"] = {
        "found": found_password is not None,
        "password": found_password or "N/A",
        "compute_time": end_time - start_time,
        "attempts": attempts,
        "status": status_message if not found_password else "Success"
    }
    
    return State.SEND_RESULT


def send_result(ctx: Context) -> State:
    if not ctx.job_data or "result" not in ctx.job_data:
        ctx.exit_message = "No result data to send"
        return State.ERROR

    res = ctx.job_data["result"]
    
    # Construct the message to send back
    result_msg = {
        "type": "result",
        "job_id": ctx.job_data["job_id"],
        "found": res["found"],
        "password": res["password"],
        "attempts": res["attempts"],
        "compute_time": res["compute_time"],
        "status": res.get("status", "Completed")
    }

    try:
        send_msg(ctx.sock, result_msg)
        print("Result sent to controller successfully.")
        return State.CLEANUP
    except OSError as e:
        ctx.exit_message = f"Socket error while sending result: {e}"
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
        State.REGISTER: register,
        State.WAIT_JOB: receive_job,
        State.CRACK: crack,
        State.SEND_RESULT: send_result,
        State.ERROR: error,
        State.CLEANUP: cleanup
    }

    while True:
        state = handlers[state](ctx)


if __name__ == "__main__":
    main()

