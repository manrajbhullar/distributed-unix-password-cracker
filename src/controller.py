import argparse
from dataclasses import dataclass, field
from enum import Enum, auto
import sys
import socket
import json
import time

from messaging import send_msg, recv_msg, recv_with_timeout


# FSM states
class State(Enum):
    PARSE_ARGS = auto()
    HANDLE_ARGS = auto()
    PARSE_SHADOW = auto()
    LISTEN = auto()
    WAIT_REGISTER = auto()
    RECEIVE_REGISTRATION = auto()
    DISPATCH_JOB = auto()
    WAIT_RESULT = auto()
    CLEANUP = auto()
    ERROR = auto()


# Stores settings from command line
@dataclass
class Settings:
    filename: str | None = None
    username: str | None = None
    port: int | None = None


# Stores extracted password info from shadow file
@dataclass
class PasswordInfo:
    alg_id: str | None = None
    salt: str | None = None
    hash: str | None = None
    full: str | None = None   

# Stores program context needed within states
@dataclass
class Context:
    args: argparse.Namespace | None = None      
    settings: Settings = field(default_factory=Settings)
    exit_message: str | None = None
    
    pw_info: PasswordInfo = field(default_factory=PasswordInfo)
    
    server_sock: socket.socket | None = None  
    worker_sock: socket.socket | None = None  
    worker_addr: tuple[str, int] | None = None
    
    worker_id: str | None = None    # Single worker registration id
    job_id: int = 1     # Single job needed right now

    parse_start: float | None = None
    parse_end: float | None = None
    parse_time: float | None = None
    dispatch_latency: float | None = None
    result_return_latency: float | None = None



def parse_arguments(ctx: Context) -> State:
    parser = argparse.ArgumentParser(
        prog="Distributed UNIX Password Cracker Controller",
        description="This is a control server that manages distributed password cracking on UNIX.",
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
        ctx.exit_message = "ERROR: Port must be between 1024 and 65535"
        return State.ERROR

    try:
        with open(args.filename, "r"):
            pass
    except FileNotFoundError:
        ctx.exit_message = "ERROR: Shadow file not found"
        return State.ERROR
    except PermissionError:
        ctx.exit_message = "ERROR: Shadow file not readable"
        return State.ERROR

    ctx.settings.filename = args.filename
    ctx.settings.username = args.username
    ctx.settings.port = args.port
    return State.PARSE_SHADOW


def parse_shadow(ctx: Context) -> State:
    username = ctx.settings.username
    filename = ctx.settings.filename
   
    try:
        ctx.parse_start = time.time() 
        with open(filename, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                fields = line.split(":")
                if len(fields) < 2:
                    continue

                user = fields[0]
                password = fields[1]

                # If not target user, then skip line
                if user != username:
                    continue

                # If found target user, check if there is a usable hash
                if password in ("", "!", "*", "!!"):
                    ctx.exit_message = f"ERROR: User '{username}' has no usable hash"
                    return State.ERROR

                # Store raw hash field
                ctx.pw_info.full = password

                # Store individual parts of hash
                if password.startswith("$"):
                    tokens = password.split("$")
                    if len(tokens) >= 2:
                        ctx.pw_info.alg_id = tokens[1]
                    if len(tokens) >= 3:
                        ctx.pw_info.salt = tokens[2]
                    if len(tokens) >= 4:
                        ctx.pw_info.hash = tokens[3]
                else:
                    ctx.exit_message = f"ERROR: User hash failed to tokenize"
                    return State.ERROR
                
                ctx.parse_end = time.time()
                ctx.parse_time = ctx.parse_end - ctx.parse_start
                
                return State.LISTEN
        ctx.exit_message = f"ERROR: Username '{username}' not found in shadow file"
        return State.ERROR
    except:
        ctx.exit_message = f"ERROR: Failed to parse shadow file. {e}"
        return State.ERROR



def listen(ctx: Context) -> State:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", ctx.settings.port))
        s.listen(1)

        ctx.server_sock = s
        print(f"LISTENING ON PORT: {ctx.settings.port}")
        return State.WAIT_REGISTER

    except OSError as e:
        ctx.exit_message = f"ERROR: Control server failed to start. {e}"
        return State.ERROR
    

def accept_worker(ctx: Context) -> State:
    try:
        conn, addr = ctx.server_sock.accept()
        ctx.worker_sock = conn
        ctx.worker_addr = addr
        print(f"\nWORKER CONNECTED FROM: {addr[0]}:{addr[1]}")
        return State.RECEIVE_REGISTRATION
    except OSError as e:
        ctx.exit_message = f"ERROR: Worker connection attempt failed. {e}"
        return State.ERROR


def receive_registration(ctx: Context) -> State:
    if ctx.worker_sock is None:
        ctx.exit_message = "ERROR: No worker socket"
        return State.ERROR

    try:
        print("  Waiting for worker to send registration request...")

        registration_req = recv_with_timeout(ctx.worker_sock, 5.0)

        print("  Worker registration request received")

        if registration_req.get("type") != "register":
            send_msg(ctx.worker_sock, {
                "type": "registration_err",
                "reason": "bad register"
            })
            return State.ERROR

        ctx.worker_id = registration_req["worker_id"]
        
        send_msg(ctx.worker_sock, {
            "type": "registration_ok"
        })

        print(f"  Worker registered successfully ({ctx.worker_id})")
        return State.DISPATCH_JOB

    except Exception as e:
        ctx.exit_message = f"ERROR: Worker failed to register. {e}"
        return State.WAIT_REGISTER



def dispatch_job(ctx: Context) -> State:
    charset = (
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789"
        "@#%^&*()_+-=.,:;?"
    )

    if ctx.worker_sock is None:
        ctx.exit_message = "No connected worker"
        return State.ERROR

    job = {
        "type": "job",
        "job_id": ctx.job_id,
        "username": ctx.settings.username,
        "alg_id": ctx.pw_info.alg_id,
        "salt": ctx.pw_info.salt,
        "hash": ctx.pw_info.hash,
        "hash_full": ctx.pw_info.full,
        "charset": charset,
    }

    try:
        dispatch_start_time = time.time()
        send_msg(ctx.worker_sock, job)
        ack = recv_msg(ctx.worker_sock)
        if ack.get("type") != "job_ack" or ack.get("job_id") != ctx.job_id:
            ctx.exit_message = f"ERROR: Expected job_ack, got: {ack}"
            return State.ERROR
        dispatch_end_time = time.time()
        ctx.dispatch_latency = dispatch_end_time - dispatch_start_time
        
        print(f"\nDISPATCHED JOB #{job['job_id']} (Worker: {ctx.worker_id})")
        return State.WAIT_RESULT

    except OSError as e:
        ctx.exit_message = f"ERROR: Dispatch of job to worker failed. {e}"
        return State.ERROR


def wait_result(ctx: Context) -> State:
    print("  Waiting for worker to finish cracking...")
    try:
        result = recv_msg(ctx.worker_sock)
        ack = {"type": "result_ack"}
        send_msg(ctx.worker_sock, ack)
        print("  Worker has finished")

        result_latency = recv_msg(ctx.worker_sock)
        ctx.result_return_latency = result_latency["result_return_latency"]
        
        print("\n" + "="*40)
        print("            CRACKING RESULTS")
        print("="*40)

        if result.get("found"):
            status_value = "SUCCESS"
            password_value = result.get("password")
        else:
            status_value = "FAILED"
            password_value = "N/A"

        attempts_value = result.get("attempts")
        crack_time_value = result.get("compute_time")

        if crack_time_value and crack_time_value > 0:
            hps = attempts_value / crack_time_value
        else:
            hps = 0

        label_width = 20 

        print(f"{'STATUS:':<{label_width}} {status_value}")
        print(f"{'PASSWORD:':<{label_width}} {password_value}")
        print(f"{'ATTEMPTS:':<{label_width}} {attempts_value}")
        print(f"{'TIME:':<{label_width}} {crack_time_value:.2f} seconds")
        print(f"{'SPEED:':<{label_width}} {hps:.2f} hashes/sec")

        print(f"{'PARSING TIME:':<{label_width}} {(ctx.parse_time * 1000):.2f} milliseconds")
        print(f"{'DISPATCH LATENCY:':<{label_width}} {(ctx.dispatch_latency * 1000):.2f} milliseconds")
        print(f"{'RESULT LATENCY:':<{label_width}} {(ctx.result_return_latency * 1000):.2f} milliseconds")

        print("="*40)

        return State.CLEANUP

    except OSError as e:
        ctx.exit_message = f"ERROR: Failed to receive result. {e}"
        return State.ERROR


def error(ctx: Context) -> State:
    print(f"\n{ctx.exit_message}")
    return State.CLEANUP


def cleanup(ctx: Context) -> State:
    if ctx.worker_sock:
        ctx.worker_sock.close()
    if ctx.server_sock:
        ctx.server_sock.close()

    print("\nEXITING PROGRAM")
    sys.exit(0)


def main():
    print("--- CONTROLLER ---")
    
    # Program context
    ctx = Context()
    
    # Initialize first state
    state = State.PARSE_ARGS

    # Handlers for each state
    handlers = {
        State.PARSE_ARGS: parse_arguments,
        State.HANDLE_ARGS: handle_arguments,
        State.PARSE_SHADOW: parse_shadow,
        State.LISTEN: listen,
        State.WAIT_REGISTER: accept_worker,
        State.RECEIVE_REGISTRATION: receive_registration,
        State.DISPATCH_JOB: dispatch_job,
        State.WAIT_RESULT: wait_result,
        State.ERROR: error,
        State.CLEANUP: cleanup
    }

    # FSM loop
    while True:
        state = handlers[state](ctx)
    

if __name__ == "__main__":
    main()