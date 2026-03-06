#!/usr/bin/env python3

import argparse
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse


def now_iso():
    return subprocess.check_output(
        ["date", "-u", "+%Y-%m-%dT%H:%M:%SZ"], text=True
    ).strip()


def now_compact():
    return subprocess.check_output(
        ["date", "-u", "+%Y%m%dT%H%M%SZ"], text=True
    ).strip()


def read_text(path):
    try:
        return Path(path).read_text().strip()
    except FileNotFoundError:
        return ""


def write_text(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value)


def slugify(value):
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    slug = re.sub(r"-{2,}", "-", slug)
    return slug or "task"


def run_tmux(args, check=False):
    return subprocess.run(
        ["tmux", *args],
        text=True,
        capture_output=True,
        check=check,
    )


def has_session(session_name):
    return run_tmux(["has-session", "-t", session_name]).returncode == 0


class RemoteTaskService:
    def __init__(self, task_root, meta_dir):
        self.task_root = Path(task_root)
        self.meta_dir = Path(meta_dir)
        self.task_root.mkdir(parents=True, exist_ok=True)
        self.meta_dir.mkdir(parents=True, exist_ok=True)

    def service_health(self):
        return {
            "ok": True,
            "task_root": str(self.task_root),
        }

    def task_dir(self, task_id):
        return self.task_root / task_id

    def task_record(self, task_id):
        task_dir = self.task_dir(task_id)
        if not task_dir.is_dir():
            return None
        session_name = read_text(task_dir / "meta" / "session_name.txt")
        attachable = bool(session_name) and has_session(session_name)
        task = {
            "task_id": task_id,
            "status": read_text(task_dir / "status.txt"),
            "created_at": read_text(task_dir / "meta" / "created_at.txt"),
            "started_at": read_text(task_dir / "started_at.txt"),
            "finished_at": read_text(task_dir / "finished_at.txt"),
            "exit_code": read_text(task_dir / "exit_code.txt"),
            "pid": read_text(task_dir / "pid.txt"),
            "pgid": read_text(task_dir / "pgid.txt"),
            "cwd": read_text(task_dir / "meta" / "cwd.txt"),
            "summary": read_text(task_dir / "meta" / "summary.txt"),
            "why": read_text(task_dir / "meta" / "why.txt"),
            "session_mode": read_text(task_dir / "meta" / "session_mode.txt"),
            "session_name": session_name,
            "attachable": attachable,
            "startup_error": read_text(task_dir / "startup_error.txt"),
            "log_path": str(task_dir / "logs" / "combined.log"),
            "command": (task_dir / "command.sh").read_text()
            if (task_dir / "command.sh").exists()
            else "",
            "attach_snippet": f"tmux attach -t {shlex.quote(session_name)}"
            if session_name
            else "",
        }
        return task

    def list_tasks(self):
        tasks = []
        if not self.task_root.exists():
            return {"ok": True, "task_root_exists": False, "tasks": []}
        for path in sorted(self.task_root.iterdir()):
            if path.name.startswith(".") or not path.is_dir():
                continue
            record = self.task_record(path.name)
            if record:
                tasks.append(record)
        return {"ok": True, "task_root_exists": self.task_root.exists(), "tasks": tasks}

    def doctor(self, cwd):
        parent = self.task_root.parent
        checks = {
            "python3": shutil.which("python3") is not None,
            "tmux": shutil.which("tmux") is not None,
            "task_root_parent_exists": parent.exists(),
            "task_root_parent_writable": os.access(parent, os.W_OK) if parent.exists() else False,
            "task_root_exists": self.task_root.exists(),
            "cwd_exists": Path(cwd).exists(),
            "cwd_accessible": Path(cwd).is_dir() and os.access(cwd, os.X_OK),
        }
        ok = all(
            [
                checks["python3"],
                checks["tmux"],
                checks["task_root_parent_exists"],
                checks["task_root_parent_writable"],
                checks["cwd_exists"],
                checks["cwd_accessible"],
            ]
        )
        return {"ok": ok, "checks": checks}

    def write_failure(self, task_dir, message):
        write_text(task_dir / "status.txt", "failed\n")
        write_text(task_dir / "finished_at.txt", now_iso() + "\n")
        write_text(task_dir / "startup_error.txt", message + "\n")

    def command_script(self, command):
        return "#!/bin/sh\n" + command.rstrip("\n") + "\n"

    def runner_script(self):
        return """#!/bin/sh
set -u
task_dir="$1"
now() {
  date -u '+%Y-%m-%dT%H:%M:%SZ'
}
finish() {
  rc=$?
  printf '%s\n' "$rc" > "$task_dir/exit_code.txt"
  printf '%s\n' "$(now)" > "$task_dir/finished_at.txt"
  if [ "$rc" -eq 0 ]; then
    printf '%s\n' "succeeded" > "$task_dir/status.txt"
  else
    printf '%s\n' "failed" > "$task_dir/status.txt"
  fi
  exit "$rc"
}
trap finish EXIT
printf '%s\n' "$(now)" > "$task_dir/started_at.txt"
printf '%s\n' "running" > "$task_dir/status.txt"
printf '%s\n' "$$" > "$task_dir/pid.txt"
if command -v ps >/dev/null 2>&1; then
  ps -o pgid= -p $$ | tr -d ' ' > "$task_dir/pgid.txt" 2>/dev/null || true
fi
IFS= read -r task_cwd < "$task_dir/meta/cwd.txt" || task_cwd=.
cd "$task_cwd"
exec "$task_dir/command.sh"
"""

    def create_tmux_session(self, task_dir, session_name, cwd):
        runner = str(task_dir / "runner.sh")
        log_path = task_dir / "logs" / "combined.log"
        result = run_tmux(
            ["new-session", "-d", "-s", session_name, "-c", cwd, f"{runner} {task_dir}"]
        )
        if result.returncode != 0:
            return False, result.stderr.strip() or result.stdout.strip() or "tmux new-session failed"
        pipe = run_tmux(
            [
                "pipe-pane",
                "-o",
                "-t",
                session_name,
                f"cat >> {shlex.quote(str(log_path))}",
            ]
        )
        if pipe.returncode != 0:
            return False, pipe.stderr.strip() or pipe.stdout.strip() or "tmux pipe-pane failed"
        return True, ""

    def spawn(self, summary, why, cwd, command, slug=None):
        if not shutil.which("tmux"):
            return {"ok": False, "error": "tmux is not installed on the VM"}
        if not Path(cwd).is_dir():
            return {"ok": False, "error": f"cwd does not exist: {cwd}"}
        if not os.access(cwd, os.X_OK):
            return {"ok": False, "error": f"cwd is not accessible: {cwd}"}

        task_id = f"{slugify(slug or summary)}-{now_compact()}"
        task_dir = self.task_dir(task_id)
        suffix = 0
        while task_dir.exists():
            suffix += 1
            task_id = f"{slugify(slug or summary)}-{now_compact()}-{suffix}"
            task_dir = self.task_dir(task_id)

        (task_dir / "meta").mkdir(parents=True)
        (task_dir / "logs").mkdir(parents=True)
        write_text(task_dir / "status.txt", "queued\n")
        write_text(task_dir / "meta" / "created_at.txt", now_iso() + "\n")
        write_text(task_dir / "meta" / "cwd.txt", cwd + "\n")
        write_text(task_dir / "meta" / "summary.txt", summary + "\n")
        write_text(task_dir / "meta" / "why.txt", why + "\n")
        write_text(task_dir / "meta" / "session_mode.txt", "tmux\n")

        session_name = f"fv-{task_id}"
        write_text(task_dir / "meta" / "session_name.txt", session_name + "\n")
        write_text(task_dir / "command.sh", self.command_script(command))
        write_text(task_dir / "runner.sh", self.runner_script())
        os.chmod(task_dir / "command.sh", 0o700)
        os.chmod(task_dir / "runner.sh", 0o700)

        ok, error = self.create_tmux_session(task_dir, session_name, cwd)
        if not ok:
            self.write_failure(task_dir, error)
            return {
                "ok": False,
                "error": error,
                "task": self.task_record(task_id),
            }

        return {"ok": True, "task": self.task_record(task_id)}

    def show(self, task):
        record = self.task_record(task)
        if not record:
            return {"ok": False, "error": f"task not found: {task}"}
        return {"ok": True, "task": record}

    def logs(self, task, lines):
        record = self.task_record(task)
        if not record:
            return {"ok": False, "error": f"task not found: {task}"}
        log_path = Path(record["log_path"])
        if not log_path.exists():
            log_path.touch()
        text = log_path.read_text(errors="replace").splitlines()
        return {"ok": True, "task": task, "log": "\n".join(text[-lines:]) + ("\n" if text else "")}

    def log_chunk(self, task, offset):
        record = self.task_record(task)
        if not record:
            return {"ok": False, "error": f"task not found: {task}"}
        log_path = Path(record["log_path"])
        if not log_path.exists():
            log_path.touch()
        with log_path.open("rb") as handle:
            handle.seek(offset)
            chunk = handle.read()
            next_offset = handle.tell()
        return {
            "ok": True,
            "task": task,
            "chunk": chunk.decode(errors="replace"),
            "next_offset": next_offset,
        }

    def attach_snippet(self, task):
        record = self.task_record(task)
        if not record:
            return {"ok": False, "error": f"task not found: {task}"}
        if not record["session_name"]:
            return {"ok": False, "error": "task is missing tmux session metadata"}
        return {"ok": True, "attach_snippet": record["attach_snippet"], "task": record}

    def repair(self, task):
        record = self.task_record(task)
        if not record:
            return {"ok": False, "error": f"task not found: {task}"}
        session_name = record["session_name"]
        if has_session(session_name):
            return {"ok": True, "task": self.task_record(task)}
        task_dir = self.task_dir(task)
        if not Path(record["cwd"]).is_dir():
            message = f"cwd does not exist: {record['cwd']}"
            self.write_failure(task_dir, message)
            return {"ok": False, "error": message, "task": self.task_record(task)}
        ok, error = self.create_tmux_session(task_dir, session_name, record["cwd"])
        if not ok:
            self.write_failure(task_dir, error)
            return {"ok": False, "error": error, "task": self.task_record(task)}
        return {"ok": True, "task": self.task_record(task)}

    def send_keys(self, task, keys, enter):
        record = self.task_record(task)
        if not record:
            return {"ok": False, "error": f"task not found: {task}"}
        if not has_session(record["session_name"]):
            return {"ok": False, "error": "task session is not currently running"}
        result = run_tmux(["send-keys", "-t", record["session_name"], "-l", keys])
        if result.returncode != 0:
            return {"ok": False, "error": result.stderr.strip() or "tmux send-keys failed"}
        if enter:
            result = run_tmux(["send-keys", "-t", record["session_name"], "C-m"])
            if result.returncode != 0:
                return {"ok": False, "error": result.stderr.strip() or "tmux send-keys enter failed"}
        return {"ok": True, "task": self.task_record(task)}

    def capture_pane(self, task, lines):
        record = self.task_record(task)
        if not record:
            return {"ok": False, "error": f"task not found: {task}"}
        if not has_session(record["session_name"]):
            return {"ok": False, "error": "task session is not currently running"}
        result = run_tmux(
            ["capture-pane", "-p", "-t", record["session_name"], "-S", f"-{lines}"]
        )
        if result.returncode != 0:
            return {"ok": False, "error": result.stderr.strip() or "tmux capture-pane failed"}
        return {"ok": True, "task": task, "pane": result.stdout}


class Handler(BaseHTTPRequestHandler):
    service = None

    def log_message(self, format, *args):
        return

    def send_json(self, status_code, payload):
        body = json.dumps(payload).encode()
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def json_body(self):
        length = int(self.headers.get("Content-Length", "0"))
        if length == 0:
            return {}
        return json.loads(self.rfile.read(length).decode())

    def query(self):
        return parse_qs(urlparse(self.path).query)

    def get_one(self, name, default=""):
        return self.query().get(name, [default])[0]

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/health":
            self.send_json(200, self.service.service_health())
        elif parsed.path == "/tasks":
            self.send_json(200, self.service.list_tasks())
        elif parsed.path == "/task":
            self.send_json(200, self.service.show(self.get_one("task")))
        elif parsed.path == "/logs":
            self.send_json(
                200,
                self.service.logs(self.get_one("task"), int(self.get_one("lines", "200"))),
            )
        elif parsed.path == "/log-chunk":
            self.send_json(
                200,
                self.service.log_chunk(
                    self.get_one("task"),
                    int(self.get_one("offset", "0")),
                ),
            )
        elif parsed.path == "/attach-snippet":
            self.send_json(200, self.service.attach_snippet(self.get_one("task")))
        elif parsed.path == "/doctor":
            self.send_json(200, self.service.doctor(self.get_one("cwd", ".")))
        elif parsed.path == "/capture-pane":
            self.send_json(
                200,
                self.service.capture_pane(
                    self.get_one("task"),
                    int(self.get_one("lines", "200")),
                ),
            )
        else:
            self.send_json(404, {"ok": False, "error": f"unknown path: {parsed.path}"})

    def do_POST(self):
        parsed = urlparse(self.path)
        body = self.json_body()
        if parsed.path == "/spawn":
            self.send_json(
                200,
                self.service.spawn(
                    body.get("summary", ""),
                    body.get("why", ""),
                    body.get("cwd", "."),
                    body.get("command", ""),
                    body.get("slug"),
                ),
            )
        elif parsed.path == "/repair":
            self.send_json(200, self.service.repair(body.get("task", "")))
        elif parsed.path == "/send-keys":
            self.send_json(
                200,
                self.service.send_keys(
                    body.get("task", ""),
                    body.get("keys", ""),
                    bool(body.get("enter", False)),
                ),
            )
        else:
            self.send_json(404, {"ok": False, "error": f"unknown path: {parsed.path}"})


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--task-root", required=True)
    parser.add_argument("--meta-dir", required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=0)
    return parser.parse_args()


def main():
    args = parse_args()
    service = RemoteTaskService(args.task_root, args.meta_dir)
    Handler.service = service
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    write_text(Path(args.meta_dir) / "service_port.txt", str(server.server_address[1]) + "\n")
    server.serve_forever()


if __name__ == "__main__":
    main()
