#!/usr/bin/env python3

import argparse
import errno
import json
import os
import platform
import pty
import re
import select
import shlex
import subprocess
import sys
import textwrap
import time
import urllib.parse
from pathlib import Path

BEGIN_MARKER = "__FV_REMOTE_TASK_BEGIN__"
END_MARKER = "__FV_REMOTE_TASK_END__"
DEFAULT_TASK_ROOT = "/var/lib/fly-vault/remote-task"
SERVICE_SESSION = "fv-remote-task-service"
SERVICE_DIR_NAME = ".service"
HEALTH_TIMEOUT_SECONDS = 1.5
DEFAULT_EXEC_TIMEOUT_SECONDS = 45.0
DEFAULT_BOOTSTRAP_TIMEOUT_SECONDS = 90.0
DEFAULT_SERVICE_READY_TIMEOUT_SECONDS = 8.0
DEFAULT_PROGRESS_INTERVAL_SECONDS = 10.0
HEALTH_POLL_INTERVAL_SECONDS = 0.25
LIST_COLUMNS = [
    "task_id",
    "status",
    "attachable",
    "created_at",
    "session_name",
    "cwd",
    "summary",
    "why",
    "startup_error",
]


def packaged_fly_vault_bin():
    if not sys.platform.startswith("linux"):
        return None

    machine = platform.machine().lower()
    arch_dir = None
    if machine in ("x86_64", "amd64"):
        arch_dir = "linux-amd64"
    elif machine in ("aarch64", "arm64"):
        arch_dir = "linux-arm64"

    if arch_dir is None:
        return None

    candidate = (
        Path(__file__).resolve().parent.parent / "assets" / "bin" / arch_dir / "fly-vault"
    )
    if candidate.exists():
        return str(candidate)
    return None


def default_fly_vault_bin():
    return packaged_fly_vault_bin() or os.environ.get("FLY_VAULT_BIN") or "fly-vault"


def parse_args():
    parser = argparse.ArgumentParser(
        description="Manage remote tasks over fly-vault through a VM-side control service."
    )
    parser.add_argument(
        "--fly-vault-bin",
        default=default_fly_vault_bin(),
        help="Command used to invoke fly-vault. Default: %(default)s",
    )
    parser.add_argument(
        "--task-root",
        default=DEFAULT_TASK_ROOT,
        help="Remote task registry root inside the provisioned rootfs.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print structured JSON instead of human-oriented text.",
    )
    parser.add_argument(
        "--exec-timeout",
        type=float,
        default=DEFAULT_EXEC_TIMEOUT_SECONDS,
        help="Seconds to wait for a normal fly-vault exec round-trip before aborting.",
    )
    parser.add_argument(
        "--bootstrap-timeout",
        type=float,
        default=DEFAULT_BOOTSTRAP_TIMEOUT_SECONDS,
        help="Seconds to wait for service bootstrap fly-vault exec before aborting.",
    )
    parser.add_argument(
        "--service-ready-timeout",
        type=float,
        default=DEFAULT_SERVICE_READY_TIMEOUT_SECONDS,
        help="Seconds to poll for service health before giving up.",
    )
    parser.add_argument(
        "--progress-interval",
        type=float,
        default=DEFAULT_PROGRESS_INTERVAL_SECONDS,
        help="Seconds between progress updates on stderr. Set to 0 to disable.",
    )

    subparsers = parser.add_subparsers(dest="action", required=True)

    spawn = subparsers.add_parser("spawn", help="Create a new tmux-backed remote task.")
    add_vault(spawn)
    spawn.add_argument("--summary", required=True, help="Short description of the task.")
    spawn.add_argument("--why", required=True, help="Reason this task was started.")
    spawn.add_argument("--cwd", default=".", help="Remote working directory.")
    spawn.add_argument(
        "--slug",
        help="Optional human-readable prefix for the task id. Defaults to the summary.",
    )
    spawn.add_argument("--command", required=True, help="Shell command to run remotely.")

    list_cmd = subparsers.add_parser("list", help="List known remote tasks.")
    add_vault(list_cmd)

    show = subparsers.add_parser("show", help="Show task metadata and command.")
    add_vault(show)
    show.add_argument("--task", required=True, help="Task id.")

    logs = subparsers.add_parser("logs", help="Read or follow task logs.")
    add_vault(logs)
    logs.add_argument("--task", required=True, help="Task id.")
    logs.add_argument("--lines", type=int, default=200, help="Tail line count.")
    logs.add_argument("--follow", action="store_true", help="Follow the log stream.")
    logs.add_argument(
        "--poll-interval",
        type=float,
        default=1.0,
        help="Seconds between log follow polls.",
    )

    attach = subparsers.add_parser(
        "attach-snippet",
        help="Print the tmux snippet to run through fly-vault exec.",
    )
    add_vault(attach)
    attach.add_argument("--task", required=True, help="Task id.")

    doctor = subparsers.add_parser("doctor", help="Check service and task prerequisites.")
    add_vault(doctor)
    doctor.add_argument("--cwd", default=".", help="Remote working directory to validate.")

    repair = subparsers.add_parser("repair", help="Retry session creation for an existing task.")
    add_vault(repair)
    repair.add_argument("--task", required=True, help="Task id.")

    send_keys = subparsers.add_parser(
        "send-keys",
        help="Send literal keys into a running tmux-backed task session.",
    )
    add_vault(send_keys)
    send_keys.add_argument("--task", required=True, help="Task id.")
    send_keys.add_argument("--keys", required=True, help="Literal text to send.")
    send_keys.add_argument("--enter", action="store_true", help="Send Enter after the text.")

    capture = subparsers.add_parser(
        "capture-pane",
        help="Capture recent pane output from a running tmux-backed task session.",
    )
    add_vault(capture)
    capture.add_argument("--task", required=True, help="Task id.")
    capture.add_argument("--lines", type=int, default=200, help="Captured line count.")

    return parser.parse_args()


def add_vault(parser):
    parser.add_argument("--vault", required=True, help="fly-vault config entry name.")


def shell_quote(value):
    return shlex.quote(value)


def shell_heredoc(target_expr, body, label):
    marker = f"__FV_{label}_{abs(hash((target_expr, body))) & 0xFFFFFFFF:08x}__"
    while marker in body:
        marker += "_X"
    if body and not body.endswith("\n"):
        body += "\n"
    return f"cat <<'{marker}' > {target_expr}\n{body}{marker}\n"


def service_script_path():
    return Path(__file__).resolve().with_name("remote_task_service.py")


def fly_vault_command(raw):
    cmd = shlex.split(raw)
    if not cmd:
        raise SystemExit("fly-vault command is empty")
    return cmd


def snippet(text, limit=40):
    lines = text.splitlines()
    if len(lines) > limit:
        lines = lines[:limit] + ["..."]
    return "\n".join(lines)


def extract_marked_output(raw_output):
    start = raw_output.find(BEGIN_MARKER)
    if start == -1:
        return None
    start += len(BEGIN_MARKER)
    if raw_output.startswith("\n", start):
        start += 1
    end = raw_output.find(END_MARKER, start)
    if end == -1:
        return None
    return raw_output[start:end]


def print_progress(message):
    print(message, file=sys.stderr, flush=True)


def format_elapsed(seconds):
    return f"{seconds:.1f}s" if seconds < 10 else f"{seconds:.0f}s"


def communicate_with_pty(cmd, purpose, timeout_seconds, progress_interval):
    master_fd, slave_fd = pty.openpty()
    start = time.monotonic()
    next_progress_at = (
        start + progress_interval if progress_interval and progress_interval > 0 else None
    )
    chunks = []
    process = None

    try:
        process = subprocess.Popen(
            cmd,
            stdin=slave_fd,
            stdout=slave_fd,
            stderr=slave_fd,
            close_fds=True,
        )
    finally:
        os.close(slave_fd)

    timed_out = False
    try:
        while True:
            now = time.monotonic()
            if timeout_seconds and timeout_seconds > 0 and now - start > timeout_seconds:
                timed_out = True
                process.terminate()
                break

            if next_progress_at is not None and now >= next_progress_at:
                print_progress(
                    f"remote-task: waiting for {purpose} via fly-vault exec "
                    f"({format_elapsed(now - start)} elapsed)"
                )
                next_progress_at = now + progress_interval

            if process.poll() is not None:
                ready, _, _ = select.select([master_fd], [], [], 0)
                if not ready:
                    break
                timeout = 0
            else:
                if timeout_seconds and timeout_seconds > 0:
                    timeout = min(0.2, max(0.0, timeout_seconds - (now - start)))
                else:
                    timeout = 0.2
            ready, _, _ = select.select([master_fd], [], [], timeout)
            if not ready:
                continue
            try:
                chunk = os.read(master_fd, 4096)
            except OSError as exc:
                if exc.errno == errno.EIO:
                    break
                raise
            if not chunk:
                break
            chunks.append(chunk)
    finally:
        os.close(master_fd)

    if timed_out:
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        output = b"".join(chunks).decode(errors="replace")
        raise SystemExit(
            f"remote-task {purpose} timed out after {format_elapsed(timeout_seconds)}.\n"
            "transport: fly-vault exec (pty)\n"
            f"output snippet:\n{snippet(output)}\n"
            "Hint: retry the command or inspect the remote service state with `doctor`."
        )

    returncode = process.wait()
    output = b"".join(chunks).decode(errors="replace")
    return {
        "returncode": returncode,
        "output": output,
        "stdout": output,
        "stderr": "",
        "transport": "fly-vault exec (pty)",
    }


def run_remote_exec_capture(
    fly_vault_bin,
    vault,
    remote_script,
    purpose,
    timeout_seconds=DEFAULT_EXEC_TIMEOUT_SECONDS,
    progress_interval=DEFAULT_PROGRESS_INTERVAL_SECONDS,
):
    cmd = fly_vault_command(fly_vault_bin) + [
        "exec",
        vault,
        "--",
        "/bin/sh",
        "-lc",
        remote_script,
    ]
    completed = communicate_with_pty(
        cmd,
        purpose=purpose,
        timeout_seconds=timeout_seconds,
        progress_interval=progress_interval,
    )
    payload = extract_marked_output(completed["output"])
    if payload is None:
        raise SystemExit(
            f"remote-task {purpose} did not receive the expected payload markers.\n"
            f"transport: {completed['transport']}\n"
            f"fly-vault exit code: {completed['returncode']}\n"
            f"output snippet:\n{snippet(completed['output'])}\n"
            "Hint: inspect raw fly-vault output or retry `doctor`."
        )
    return {
        "returncode": completed["returncode"],
        "payload": payload,
        "stdout": completed["stdout"],
        "stderr": completed["stderr"],
        "output": completed["output"],
        "transport": completed["transport"],
    }


def run_bootstrap_capture(
    fly_vault_bin,
    vault,
    remote_script,
    timeout_seconds=DEFAULT_BOOTSTRAP_TIMEOUT_SECONDS,
    progress_interval=DEFAULT_PROGRESS_INTERVAL_SECONDS,
):
    return run_remote_exec_capture(
        fly_vault_bin,
        vault,
        remote_script,
        "bootstrap",
        timeout_seconds=timeout_seconds,
        progress_interval=progress_interval,
    )


def parse_bootstrap_payload(payload):
    data = {}
    for line in payload.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            data[key] = value
    return data


def build_service_request_script(task_root, method, path, body=None, timeout=HEALTH_TIMEOUT_SECONDS):
    service_dir = f"{task_root.rstrip('/')}/{SERVICE_DIR_NAME}"
    meta_dir = f"{service_dir}/meta"
    service_port_file = f"{meta_dir}/service_port.txt"
    body_json = "" if body is None else json.dumps(body)

    return textwrap.dedent(
        f"""\
        set -eu
        export PS1=
        SERVICE_PORT_FILE={shell_quote(service_port_file)}
        METHOD={shell_quote(method)}
        PATH_INFO={shell_quote(path)}
        BODY_JSON={shell_quote(body_json)}
        REQUEST_TIMEOUT={shell_quote(str(timeout))}

        fv_begin() {{
          printf '%s\\n' {shell_quote(BEGIN_MARKER)}
        }}

        fv_end() {{
          printf '%s\\n' {shell_quote(END_MARKER)}
        }}

        if [ ! -f "$SERVICE_PORT_FILE" ]; then
          echo "service port file is missing: $SERVICE_PORT_FILE" >&2
          exit 1
        fi

        fv_begin
        python3 <<'PY'
import json
import os
from pathlib import Path
from urllib.request import Request, urlopen

port = Path(os.environ["SERVICE_PORT_FILE"]).read_text().strip()
url = f"http://127.0.0.1:{{port}}{{os.environ['PATH_INFO']}}"
body_json = os.environ["BODY_JSON"]
data = body_json.encode() if body_json else None
headers = {{"Content-Type": "application/json"}} if body_json else {{}}
request = Request(url, data=data, headers=headers, method=os.environ["METHOD"])
with urlopen(request, timeout=float(os.environ["REQUEST_TIMEOUT"])) as response:
    print(response.read().decode(), end="")
PY
        fv_end
        """
    )


def service_request(
    args,
    method,
    path,
    body=None,
    timeout=HEALTH_TIMEOUT_SECONDS,
    exec_timeout=None,
):
    completed = run_remote_exec_capture(
        args.fly_vault_bin,
        args.vault,
        build_service_request_script(args.task_root, method, path, body=body, timeout=timeout),
        "service request",
        timeout_seconds=args.exec_timeout if exec_timeout is None else exec_timeout,
        progress_interval=args.progress_interval,
    )
    try:
        return json.loads(completed["payload"])
    except json.JSONDecodeError as exc:
        raise SystemExit(f"remote-task service returned invalid JSON: {exc}") from exc


def service_health_ok(args, request_timeout=HEALTH_TIMEOUT_SECONDS, exec_timeout=None):
    try:
        data = service_request(
            args,
            "GET",
            "/health",
            timeout=request_timeout,
            exec_timeout=exec_timeout,
        )
    except SystemExit as exc:
        return False, str(exc)
    return bool(data.get("ok")), ""


def wait_for_service_health(args, timeout_seconds):
    deadline = time.monotonic() + timeout_seconds
    last_error = "health check did not return ok=true"
    while time.monotonic() < deadline:
        remaining = deadline - time.monotonic()
        request_timeout = min(HEALTH_TIMEOUT_SECONDS, max(0.5, remaining))
        exec_timeout = min(args.exec_timeout, request_timeout + 1.0)
        ok, error = service_health_ok(
            args,
            request_timeout=request_timeout,
            exec_timeout=exec_timeout,
        )
        if ok:
            return ""
        if error:
            last_error = error
        time.sleep(HEALTH_POLL_INTERVAL_SECONDS)
    return last_error


def build_bootstrap_script(task_root):
    service_code = service_script_path().read_text()
    service_dir = f"{task_root.rstrip('/')}/{SERVICE_DIR_NAME}"
    service_file = f"{service_dir}/remote_task_service.py"
    service_log = f"{service_dir}/service.log"
    meta_dir = f"{service_dir}/meta"

    body = textwrap.dedent(
        f"""\
        set -eu
        export PS1=
        TASK_ROOT={shell_quote(task_root)}
        SERVICE_DIR={shell_quote(service_dir)}
        SERVICE_FILE={shell_quote(service_file)}
        SERVICE_LOG={shell_quote(service_log)}
        META_DIR={shell_quote(meta_dir)}
        SERVICE_SESSION={shell_quote(SERVICE_SESSION)}

        fv_begin() {{
          printf '%s\\n' {shell_quote(BEGIN_MARKER)}
        }}

        fv_end() {{
          printf '%s\\n' {shell_quote(END_MARKER)}
        }}

        fv_fail() {{
          msg="$1"
          fv_begin
          printf 'OK=0\\n'
          printf 'ERROR=%s\\n' "$msg"
          fv_end
          exit 1
        }}

        if ! command -v python3 >/dev/null 2>&1; then
          fv_fail "python3 is required for remote-task service"
        fi
        if ! command -v tmux >/dev/null 2>&1; then
          fv_fail "tmux is required for remote-task service"
        fi

        mkdir -p "$TASK_ROOT" "$SERVICE_DIR" "$META_DIR"
        """
    )
    body += shell_heredoc('"$SERVICE_FILE"', service_code, "SERVICE")
    body += textwrap.dedent(
        """\
        chmod 700 "$SERVICE_FILE"

        if tmux has-session -t "$SERVICE_SESSION" 2>/dev/null; then
          tmux kill-session -t "$SERVICE_SESSION" || true
        fi

        rm -f "$META_DIR/service_port.txt"
        tmux new-session -d -s "$SERVICE_SESSION" -c "$SERVICE_DIR" \
          "python3 '$SERVICE_FILE' --task-root '$TASK_ROOT' --meta-dir '$META_DIR' >> '$SERVICE_LOG' 2>&1"

        i=0
        while [ $i -lt 80 ]; do
          if [ -f "$META_DIR/service_port.txt" ]; then
            port=$(cat "$META_DIR/service_port.txt")
            fv_begin
            printf 'OK=1\\n'
            printf 'REMOTE_PORT=%s\\n' "$port"
            printf 'SERVICE_SESSION=%s\\n' "$SERVICE_SESSION"
            fv_end
            exit 0
          fi
          i=$((i + 1))
          sleep 0.1
        done

        log_tail=""
        if [ -f "$SERVICE_LOG" ]; then
          log_tail=$(tail -n 20 "$SERVICE_LOG" | tr '\\n' ' ' | tr '\\t' ' ')
        fi
        fv_begin
        printf 'OK=0\\n'
        printf 'ERROR=service failed to publish a port\\n'
        printf 'LOG_TAIL=%s\\n' "$log_tail"
        fv_end
        exit 1
        """
    )
    return body + "exit\n"


def ensure_service(args):
    initial_health_error = wait_for_service_health(
        args,
        min(args.service_ready_timeout, 1.0),
    )
    if not initial_health_error:
        return

    print_progress(
        f"remote-task: bootstrapping service for vault {args.vault} "
        f"after health check failed ({initial_health_error.splitlines()[0]})"
    )
    bootstrap = run_bootstrap_capture(
        args.fly_vault_bin,
        args.vault,
        build_bootstrap_script(args.task_root),
        timeout_seconds=args.bootstrap_timeout,
        progress_interval=args.progress_interval,
    )
    data = parse_bootstrap_payload(bootstrap["payload"])
    if data.get("OK") != "1":
        raise SystemExit(
            "remote-task service bootstrap failed.\n"
            f"reason: {data.get('ERROR', 'unknown error')}\n"
            f"log tail: {data.get('LOG_TAIL', '')}"
        )
    health_error = wait_for_service_health(args, args.service_ready_timeout)
    if health_error:
        port = data.get("REMOTE_PORT", "")
        raise SystemExit(
            "remote-task service did not become healthy after bootstrap.\n"
            f"service port: {port or 'unknown'}\n"
            f"last health error: {health_error}"
        )


def emit_json(data):
    print(json.dumps(data, indent=2, sort_keys=True))


def print_task_summary(record):
    print(f"Task: {record['task_id']}")
    print(f"Status: {record.get('status', '')}")
    print(f"Attachable: {record.get('attachable', False)}")
    print(f"Session: {record.get('session_name', '')}")
    print(f"Cwd: {record.get('cwd', '')}")
    print(f"Summary: {record.get('summary', '')}")
    print(f"Why: {record.get('why', '')}")
    if record.get("startup_error"):
        print(f"Startup error: {record['startup_error']}")
    print(f"Log: {record.get('log_path', '')}")
    print(f"Attach: {record.get('attach_snippet', '')}")


def do_spawn(args):
    ensure_service(args)
    data = service_request(
        args,
        "POST",
        "/spawn",
        {
            "summary": args.summary,
            "why": args.why,
            "cwd": args.cwd,
            "slug": args.slug,
            "command": args.command,
        },
    )
    if args.json:
        emit_json(data)
    else:
        if not data.get("ok"):
            print(f"Spawn failed: {data.get('error', 'unknown error')}", file=sys.stderr)
            if data.get("task"):
                print_task_summary(data["task"])
        else:
            print_task_summary(data["task"])
    raise SystemExit(0 if data.get("ok") else 1)


def do_list(args):
    ensure_service(args)
    data = service_request(args, "GET", "/tasks")
    if args.json:
        emit_json(data)
        return
    tasks = data.get("tasks", [])
    if not tasks:
        print("No tasks found.")
        return
    print("\t".join(LIST_COLUMNS))
    for task in tasks:
        row = []
        for key in LIST_COLUMNS:
            value = task.get(key, "")
            if isinstance(value, bool):
                value = "yes" if value else "no"
            row.append(str(value).replace("\t", " ").replace("\n", " "))
        print("\t".join(row))


def do_show(args):
    ensure_service(args)
    data = service_request(
        args,
        "GET",
        "/task?" + urllib.parse.urlencode({"task": args.task}),
    )
    if args.json:
        emit_json(data)
        return
    if not data.get("ok"):
        raise SystemExit(data.get("error", "task lookup failed"))
    task = data["task"]
    print_task_summary(task)
    print("-- command --")
    print(task.get("command", ""))


def do_logs(args):
    ensure_service(args)
    if args.follow:
        offset = 0
        while True:
            data = service_request(
                args,
                "GET",
                "/log-chunk?"
                + urllib.parse.urlencode({"task": args.task, "offset": offset}),
                timeout=max(HEALTH_TIMEOUT_SECONDS, args.poll_interval + 1.0),
            )
            if not data.get("ok"):
                raise SystemExit(data.get("error", "failed to read log chunk"))
            chunk = data.get("chunk", "")
            if chunk:
                sys.stdout.write(chunk)
                sys.stdout.flush()
            offset = data.get("next_offset", offset)
            time.sleep(args.poll_interval)
    data = service_request(
        args,
        "GET",
        "/logs?" + urllib.parse.urlencode({"task": args.task, "lines": args.lines}),
    )
    if args.json:
        emit_json(data)
        return
    if not data.get("ok"):
        raise SystemExit(data.get("error", "failed to read logs"))
    sys.stdout.write(data.get("log", ""))


def do_attach_snippet(args):
    ensure_service(args)
    data = service_request(
        args,
        "GET",
        "/attach-snippet?" + urllib.parse.urlencode({"task": args.task}),
    )
    if args.json:
        emit_json(data)
        return
    if not data.get("ok"):
        raise SystemExit(data.get("error", "failed to build attach snippet"))
    print(data["attach_snippet"])


def do_doctor(args):
    ensure_service(args)
    data = service_request(
        args,
        "GET",
        "/doctor?" + urllib.parse.urlencode({"cwd": args.cwd}),
    )
    if args.json:
        emit_json(data)
    else:
        print(f"OK: {data.get('ok', False)}")
        for key, value in data.get("checks", {}).items():
            print(f"{key}: {value}")
    raise SystemExit(0 if data.get("ok") else 1)


def do_repair(args):
    ensure_service(args)
    data = service_request(
        args,
        "POST",
        "/repair",
        {"task": args.task},
    )
    if args.json:
        emit_json(data)
    else:
        if not data.get("ok"):
            print(f"Repair failed: {data.get('error', 'unknown error')}", file=sys.stderr)
        if data.get("task"):
            print_task_summary(data["task"])
    raise SystemExit(0 if data.get("ok") else 1)


def do_send_keys(args):
    ensure_service(args)
    data = service_request(
        args,
        "POST",
        "/send-keys",
        {"task": args.task, "keys": args.keys, "enter": args.enter},
    )
    if args.json:
        emit_json(data)
        return
    if not data.get("ok"):
        raise SystemExit(data.get("error", "failed to send keys"))
    print(f"Sent keys to {args.task}")


def do_capture_pane(args):
    ensure_service(args)
    data = service_request(
        args,
        "GET",
        "/capture-pane?"
        + urllib.parse.urlencode({"task": args.task, "lines": args.lines}),
    )
    if args.json:
        emit_json(data)
        return
    if not data.get("ok"):
        raise SystemExit(data.get("error", "failed to capture pane"))
    sys.stdout.write(data.get("pane", ""))


def main():
    args = parse_args()
    if args.action == "spawn":
        do_spawn(args)
    elif args.action == "list":
        do_list(args)
    elif args.action == "show":
        do_show(args)
    elif args.action == "logs":
        do_logs(args)
    elif args.action == "attach-snippet":
        do_attach_snippet(args)
    elif args.action == "doctor":
        do_doctor(args)
    elif args.action == "repair":
        do_repair(args)
    elif args.action == "send-keys":
        do_send_keys(args)
    elif args.action == "capture-pane":
        do_capture_pane(args)
    else:
        raise SystemExit(f"unsupported command: {args.action}")


if __name__ == "__main__":
    main()
