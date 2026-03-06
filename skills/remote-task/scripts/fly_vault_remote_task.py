#!/usr/bin/env python3

import argparse
import os
import platform
import re
import shlex
import subprocess
import sys
import textwrap
from pathlib import Path

BEGIN_MARKER = "__FV_REMOTE_TASK_BEGIN__"
END_MARKER = "__FV_REMOTE_TASK_END__"
DEFAULT_TASK_ROOT = "/var/lib/fly-vault/remote-task"


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
        description="Manage durable remote tasks over fly-vault."
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

    subparsers = parser.add_subparsers(dest="action", required=True)

    spawn = subparsers.add_parser("spawn", help="Create a new remote task.")
    add_vault(spawn)
    spawn.add_argument("--summary", required=True, help="Short description of the task.")
    spawn.add_argument("--why", required=True, help="Reason this task was started.")
    spawn.add_argument("--cwd", default=".", help="Remote working directory.")
    spawn.add_argument(
        "--slug",
        help="Optional human-readable prefix for the task id. Defaults to the summary.",
    )
    spawn.add_argument(
        "--command",
        dest="remote_command",
        required=True,
        help="Shell command to run remotely.",
    )

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

    attach = subparsers.add_parser(
        "attach-snippet",
        help="Print the snippet to paste into an interactive fly-vault shell.",
    )
    add_vault(attach)
    attach.add_argument("--task", required=True, help="Task id.")

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


def sanitize_slug(raw):
    slug = re.sub(r"[^a-z0-9]+", "-", raw.lower()).strip("-")
    slug = re.sub(r"-{2,}", "-", slug)
    return slug or "task"


def remote_prelude(task_root):
    return textwrap.dedent(
        f"""\
        set -eu
        export PS1=
        TASK_ROOT={shell_quote(task_root)}
        BEGIN_MARKER={shell_quote(BEGIN_MARKER)}
        END_MARKER={shell_quote(END_MARKER)}

        fv_begin() {{
          printf '%s\\n' "$BEGIN_MARKER"
        }}

        fv_end() {{
          printf '%s\\n' "$END_MARKER"
        }}

        fv_now_iso() {{
          date -u '+%Y-%m-%dT%H:%M:%SZ'
        }}

        fv_now_compact() {{
          date -u '+%Y%m%dT%H%M%SZ'
        }}

        fv_first_line() {{
          file="$1"
          if [ -f "$file" ]; then
            IFS= read -r line < "$file" || true
            printf '%s' "$line"
          fi
        }}

        fv_flat_file() {{
          file="$1"
          if [ -f "$file" ]; then
            tr '\\n' ' ' < "$file" | tr '\\t' ' '
          fi
        }}

        fv_require_task() {{
          task_id="$1"
          task_dir="$TASK_ROOT/$task_id"
          if [ ! -d "$task_dir" ]; then
            echo "task not found: $task_id" >&2
            exit 1
          fi
        }}
        """
    )


def build_runner_script():
    return textwrap.dedent(
        """\
        #!/bin/sh
        set -u

        task_dir="$1"

        fv_now_iso() {
          date -u '+%Y-%m-%dT%H:%M:%SZ'
        }

        finish() {
          rc=$?
          printf '%s\\n' "$rc" > "$task_dir/exit_code.txt"
          printf '%s\\n' "$(fv_now_iso)" > "$task_dir/finished_at.txt"
          if [ "$rc" -eq 0 ]; then
            printf '%s\\n' "succeeded" > "$task_dir/status.txt"
          else
            printf '%s\\n' "failed" > "$task_dir/status.txt"
          fi
          exit "$rc"
        }

        trap finish EXIT

        printf '%s\\n' "$(fv_now_iso)" > "$task_dir/started_at.txt"
        printf '%s\\n' "running" > "$task_dir/status.txt"
        printf '%s\\n' "$$" > "$task_dir/pid.txt"
        if command -v ps >/dev/null 2>&1; then
          ps -o pgid= -p $$ | tr -d ' ' > "$task_dir/pgid.txt" 2>/dev/null || true
        fi

        IFS= read -r task_cwd < "$task_dir/meta/cwd.txt" || task_cwd=.
        cd "$task_cwd"

        "$task_dir/command.sh" >> "$task_dir/logs/combined.log" 2>&1
        """
    )


def build_command_script(command_text):
    return "#!/bin/sh\n" + command_text.rstrip("\n") + "\n"


def wrap_remote_script(task_root, body, trailing_exit=True):
    script = remote_prelude(task_root) + "\n" + body.rstrip() + "\n"
    if trailing_exit:
        script += "exit\n"
    return script


def build_spawn_script(args):
    slug = sanitize_slug(args.slug or args.summary)
    command_script = build_command_script(args.remote_command)
    runner_script = build_runner_script()

    body = textwrap.dedent(
        f"""\
        mkdir -p "$TASK_ROOT"
        task_slug={shell_quote(slug)}
        task_id="${{task_slug}}-$(fv_now_compact)-$$"
        task_dir="$TASK_ROOT/$task_id"

        mkdir -p "$task_dir/meta" "$task_dir/logs"
        printf '%s\\n' "queued" > "$task_dir/status.txt"
        printf '%s\\n' "$(fv_now_iso)" > "$task_dir/meta/created_at.txt"
        printf '%s\\n' {shell_quote(args.cwd)} > "$task_dir/meta/cwd.txt"
        printf '%s\\n' "tmux" > "$task_dir/meta/session_mode.txt"
        """
    )
    body += shell_heredoc(
        '"$task_dir/meta/summary.txt"',
        args.summary,
        "SUMMARY",
    )
    body += shell_heredoc(
        '"$task_dir/meta/why.txt"',
        args.why,
        "WHY",
    )
    body += shell_heredoc(
        '"$task_dir/command.sh"',
        command_script,
        "COMMAND",
    )
    body += shell_heredoc(
        '"$task_dir/runner.sh"',
        runner_script,
        "RUNNER",
    )
    body += textwrap.dedent(
        """\
        chmod 700 "$task_dir/command.sh" "$task_dir/runner.sh"
        """
    )

    body += textwrap.dedent(
        f"""\
        if ! command -v tmux >/dev/null 2>&1; then
          echo "tmux is required for remote-task but is not installed" >&2
          exit 1
        fi
        session_name="fv-${{task_id}}"
        printf '%s\\n' "$session_name" > "$task_dir/meta/session_name.txt"
        tmux new-session -d -s "$session_name" -c {shell_quote(args.cwd)} "$task_dir/runner.sh $task_dir"
        """
    )

    body += textwrap.dedent(
        """\
        fv_begin
        printf 'TASK_ID=%s\\n' "$task_id"
        printf 'STATUS=%s\\n' "$(fv_first_line "$task_dir/status.txt")"
        printf 'SESSION_MODE=%s\\n' "$(fv_first_line "$task_dir/meta/session_mode.txt")"
        printf 'SESSION_NAME=%s\\n' "$(fv_first_line "$task_dir/meta/session_name.txt")"
        printf 'TASK_DIR=%s\\n' "$task_dir"
        printf 'CWD=%s\\n' "$(fv_first_line "$task_dir/meta/cwd.txt")"
        printf 'LOG=%s\\n' "$task_dir/logs/combined.log"
        fv_end
        """
    )
    return wrap_remote_script(args.task_root, body)


def build_list_script(args):
    body = textwrap.dedent(
        """\
        fv_begin
        printf 'TASK_ID\\tSTATUS\\tMODE\\tCREATED_AT\\tSESSION_NAME\\tCWD\\tSUMMARY\\tWHY\\n'
        if [ -d "$TASK_ROOT" ]; then
          for task_dir in "$TASK_ROOT"/*; do
            [ -d "$task_dir" ] || continue
            task_id=$(basename "$task_dir")
            printf '%s\\t%s\\t%s\\t%s\\t%s\\t%s\\t%s\\t%s\\n' \
              "$task_id" \
              "$(fv_first_line "$task_dir/status.txt")" \
              "$(fv_first_line "$task_dir/meta/session_mode.txt")" \
              "$(fv_first_line "$task_dir/meta/created_at.txt")" \
              "$(fv_first_line "$task_dir/meta/session_name.txt")" \
              "$(fv_flat_file "$task_dir/meta/cwd.txt")" \
              "$(fv_flat_file "$task_dir/meta/summary.txt")" \
              "$(fv_flat_file "$task_dir/meta/why.txt")"
          done | LC_ALL=C sort
        fi
        fv_end
        """
    )
    return wrap_remote_script(args.task_root, body)


def build_show_script(task_root, task_id):
    body = textwrap.dedent(
        f"""\
        fv_require_task {shell_quote(task_id)}
        fv_begin
        printf 'TASK_ID=%s\\n' {shell_quote(task_id)}
        printf 'STATUS=%s\\n' "$(fv_first_line "$task_dir/status.txt")"
        printf 'SESSION_MODE=%s\\n' "$(fv_first_line "$task_dir/meta/session_mode.txt")"
        printf 'SESSION_NAME=%s\\n' "$(fv_first_line "$task_dir/meta/session_name.txt")"
        printf 'TASK_DIR=%s\\n' "$task_dir"
        printf 'CWD=%s\\n' "$(fv_first_line "$task_dir/meta/cwd.txt")"
        printf 'CREATED_AT=%s\\n' "$(fv_first_line "$task_dir/meta/created_at.txt")"
        printf 'STARTED_AT=%s\\n' "$(fv_first_line "$task_dir/started_at.txt")"
        printf 'FINISHED_AT=%s\\n' "$(fv_first_line "$task_dir/finished_at.txt")"
        printf 'EXIT_CODE=%s\\n' "$(fv_first_line "$task_dir/exit_code.txt")"
        printf 'PID=%s\\n' "$(fv_first_line "$task_dir/pid.txt")"
        printf 'PGID=%s\\n' "$(fv_first_line "$task_dir/pgid.txt")"
        printf '%s\\n' '--SUMMARY--'
        cat "$task_dir/meta/summary.txt"
        printf '%s\\n' '--WHY--'
        cat "$task_dir/meta/why.txt"
        printf '%s\\n' '--COMMAND--'
        cat "$task_dir/command.sh"
        fv_end
        """
    )
    return wrap_remote_script(task_root, body)


def build_logs_script(args):
    body = textwrap.dedent(
        f"""\
        fv_require_task {shell_quote(args.task)}
        if [ ! -f "$task_dir/logs/combined.log" ]; then
          : > "$task_dir/logs/combined.log"
        fi
        """
    )
    if args.follow:
        body += textwrap.dedent(
            f"""\
            tail -n {args.lines} -f "$task_dir/logs/combined.log"
            """
        )
        return wrap_remote_script(args.task_root, body, trailing_exit=False)

    body += textwrap.dedent(
        f"""\
        fv_begin
        tail -n {args.lines} "$task_dir/logs/combined.log"
        fv_end
        """
    )
    return wrap_remote_script(args.task_root, body)


def fly_vault_command(raw):
    cmd = shlex.split(raw)
    if not cmd:
        raise ValueError("fly-vault command is empty")
    return cmd


def run_remote_capture(fly_vault_bin, vault, remote_script):
    cmd = fly_vault_command(fly_vault_bin) + ["connect", vault]
    completed = subprocess.run(
        cmd,
        input=remote_script,
        text=True,
        capture_output=True,
    )

    stdout = extract_marked_output(completed.stdout)
    stderr = completed.stderr

    if completed.returncode != 0:
        if completed.stdout:
            sys.stderr.write(completed.stdout)
        if stderr:
            sys.stderr.write(stderr)
        raise SystemExit(completed.returncode)

    return stdout


def run_remote_passthrough(fly_vault_bin, vault, remote_script):
    cmd = fly_vault_command(fly_vault_bin) + ["connect", vault]
    completed = subprocess.run(cmd, input=remote_script, text=True)
    raise SystemExit(completed.returncode)


def extract_marked_output(raw_output):
    start = raw_output.find(BEGIN_MARKER)
    if start == -1:
        return raw_output
    start += len(BEGIN_MARKER)
    if raw_output.startswith("\n", start):
        start += 1
    end = raw_output.find(END_MARKER, start)
    if end == -1:
        return raw_output[start:]
    return raw_output[start:end]


def parse_fields(show_output):
    fields = {}
    summary_lines = []
    why_lines = []
    command_lines = []
    section = "fields"

    for line in show_output.splitlines():
        if line == "--SUMMARY--":
            section = "summary"
            continue
        if line == "--WHY--":
            section = "why"
            continue
        if line == "--COMMAND--":
            section = "command"
            continue

        if section == "fields":
            if "=" in line:
                key, value = line.split("=", 1)
                fields[key] = value
        elif section == "summary":
            summary_lines.append(line)
        elif section == "why":
            why_lines.append(line)
        else:
            command_lines.append(line)

    fields["SUMMARY"] = "\n".join(summary_lines).rstrip("\n")
    fields["WHY"] = "\n".join(why_lines).rstrip("\n")
    fields["COMMAND"] = "\n".join(command_lines).rstrip("\n")
    return fields


def do_spawn(args):
    output = run_remote_capture(args.fly_vault_bin, args.vault, build_spawn_script(args))
    sys.stdout.write(output)


def do_list(args):
    output = run_remote_capture(args.fly_vault_bin, args.vault, build_list_script(args))
    sys.stdout.write(output)


def do_show(args):
    output = run_remote_capture(
        args.fly_vault_bin,
        args.vault,
        build_show_script(args.task_root, args.task),
    )
    sys.stdout.write(output)


def do_logs(args):
    remote_script = build_logs_script(args)
    if args.follow:
        run_remote_passthrough(args.fly_vault_bin, args.vault, remote_script)
    output = run_remote_capture(args.fly_vault_bin, args.vault, remote_script)
    sys.stdout.write(output)


def do_attach_snippet(args):
    show_output = run_remote_capture(
        args.fly_vault_bin,
        args.vault,
        build_show_script(args.task_root, args.task),
    )
    fields = parse_fields(show_output)
    session_name = fields.get("SESSION_NAME", "")
    if not session_name:
        raise SystemExit("task is missing tmux session metadata")

    print(f"tmux attach -t {shell_quote(session_name)}")


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
    else:
        raise SystemExit(f"unsupported command: {args.action}")


if __name__ == "__main__":
    main()
