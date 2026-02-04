import argparse
from dataclasses import dataclass, field
from enum import Enum, auto
import socket
import sys
import itertools
import time
import crypt
import uuid
import json
from messaging import send_msg, recv_msg


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
    controller_sock: socket.socket | None = None
    worker_id: str | None = None
    job_data: dict | None = None
    send_result_latency: float | None = None


def parse_arguments(ctx: Context) -> State:
    parser = argparse.ArgumentParser(
        prog="Distributed UNIX Password Cracker Worker",
        description="Worker node for distributed UNIX password cracker that receives jobs from the control server."
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
        ctx.exit_message = "ERROR: Port must be between 1024 and 65535"
        return State.ERROR

    ctx.settings.controller_host = args.controller
    ctx.settings.controller_port = args.port
    ctx.worker_id = uuid.uuid4().hex
    print(f"WORKER ID: {ctx.worker_id}")

    return State.CONNECT


def connect(ctx: Context) -> State:
    host = ctx.settings.controller_host
    port = ctx.settings.controller_port

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host, port))
        ctx.controller_sock = s

        print(f"\nCONNECTED TO CONTROLLER: {host}:{port}")
        return State.REGISTER

    except OSError as e:
        ctx.exit_message = f"ERROR: Connection attempt failed. {e}"
        return State.ERROR


def register(ctx: Context) -> State:
    if ctx.controller_sock is None:
        ctx.exit_message = "ERROR: No controller socket to send registration request"
        return State.ERROR

    try:
        print("  Sending registration request...")
        
        ctx.controller_sock.settimeout(5.0)

        register_msg = {
            "type": "register",
            "worker_id": ctx.worker_id
        }

        send_msg(ctx.controller_sock, register_msg)

        print("  Waiting for approval from controller...")
        register_resp = recv_msg(ctx.controller_sock)

        if register_resp.get("type") != "registration_ok":
            ctx.exit_message = f"ERROR: Registration rejected. Reason: {register_resp.get('reason', register_resp)}"
            return State.ERROR

        print("  Worker registered successfully")
        return State.WAIT_JOB

    except (socket.timeout, OSError, ValueError, json.JSONDecodeError) as e:
        ctx.exit_message = f"ERROR: Registration with controller failed. {e}"
        return State.ERROR
    finally:
        ctx.controller_sock.settimeout(None)


def receive_job(ctx: Context) -> State:
    try:
        print("\nWORKER READY")
        print("  Waiting for job from controller...")

        job = recv_msg(ctx.controller_sock)
        ack = {"type": "job_ack", "job_id": job.get("job_id")}
        send_msg(ctx.controller_sock, ack)

        if job.get("type") != "job":
            ctx.exit_message = f"ERROR: Unexpected message type: {job.get('type')}"
            return State.ERROR

        ctx.job_data = job
        print(f"  Job #{job['job_id']} received from controller")
        return State.CRACK

    except OSError as e:
        ctx.exit_message = f"ERROR: Receiving job failed. {e}"
        return State.ERROR


def crack(ctx: Context) -> State:
    job = ctx.job_data
    target_hash = job["hash_full"]
    charset = job["charset"]
    
    do_crypt = crypt.crypt
    do_join = "".join
    
    start_time = time.time()
    found_password = None
    attempts = 0
    status_message = "Search Exhausted"

    print(f"\nJOB #{job['job_id']} STARTED")
    print(f"  Cracking password (Username: {job['username']})")
    
    try:
        for length in itertools.count(1): 
            for combo in itertools.product(charset, repeat=length):
                attempts += 1
                if do_crypt(do_join(combo), target_hash) == target_hash:
                    found_password = do_join(combo)
                    break           
            if found_password:
                break
                
    except KeyboardInterrupt:
        status_message = "Manually Interrupted"
    except Exception as e:
        status_message = f"Runtime Error: {e}"

    end_time = time.time()
    print(f"  Cracking process has completed")
    
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
        ctx.exit_message = "ERROR: No result data to send"
        return State.ERROR

    result = ctx.job_data["result"]
    
    result_msg = {
        "type": "result",
        "job_id": ctx.job_data["job_id"],
        "found": result["found"],
        "password": result["password"],
        "attempts": result["attempts"],
        "compute_time": result["compute_time"],
        "status": result.get("status", "Completed"),
    }

    try:
        send_result_start = time.time()
        send_msg(ctx.controller_sock, result_msg)
        ack = recv_msg(ctx.controller_sock)
        if ack.get("type") != "result_ack":
            ctx.exit_message = f"ERROR: Expected result_ack, got: {ack}"
            return State.ERROR
        send_result_end = time.time()
        
        ctx.send_result_latency = send_result_end - send_result_start
        send_msg(ctx.controller_sock, {"result_return_latency": ctx.send_result_latency})
        
        print("  Result sent to controller")
        print(f"\nJOB #1 COMPLETE")
        return State.CLEANUP
    
    except OSError as e:
        ctx.exit_message = f"ERROR: Failed sending result. {e}"
        return State.ERROR


def error(ctx: Context) -> State:
    print(f"\n{ctx.exit_message}")
    return State.CLEANUP


def cleanup(ctx: Context) -> State:
    if ctx.controller_sock:
        ctx.controller_sock.close()
    print("\nEXITING PROGRAM")
    sys.exit(0)


def main():
    print("--- WORKER ---")

    # Program context
    ctx = Context()
    
    # Initialize first state
    state = State.PARSE_ARGS

    # Handlers for each state
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

    # FSM loop
    while True:
        state = handlers[state](ctx)


if __name__ == "__main__":
    main()

