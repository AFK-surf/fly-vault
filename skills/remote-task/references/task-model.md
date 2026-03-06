# Remote Task Model

## Purpose

This skill treats the `fly-vault` console as a transport for a simple task registry.

The registry exists only inside the provisioned rootfs. That means:

- reconnects preserve task state
- agent turnover preserves task state
- reprovision removes the entire registry

That matches the intended lifecycle for remote tasks.

## Task Root

Default root:

```text
/var/lib/fly-vault/remote-task
```

Override only if the user has a clear reason. The helper script accepts `--task-root`.

## Directory Layout

Each task lives in:

```text
/var/lib/fly-vault/remote-task/<task-id>/
```

Files:

```text
<task-id>/
  command.sh
  runner.sh
  status.txt
  started_at.txt
  finished_at.txt
  exit_code.txt
  pid.txt
  pgid.txt
  logs/
    combined.log
  meta/
    created_at.txt
    cwd.txt
    session_mode.txt
    session_name.txt        # tmux only
    summary.txt
    why.txt
```

## Required Metadata

Every task must carry:

- `summary`: what the task is doing
- `why`: why the task was started
- `cwd`: where it runs
- `session_mode`: always `tmux`

Without these fields, later recovery becomes guesswork.

## Session Model

### tmux

Use for all remote tasks created by this skill:

- REPLs
- development servers that benefit from live inspection
- builds and tests that may need later inspection
- manual exploratory processes

Properties:

- requires `tmux` on the remote image and is the only supported mode
- allows later `tmux attach -t <session-name>`
- still keeps durable metadata and logs

## Task ID Strategy

Use:

```text
<slug>-<utc timestamp>-<remote shell pid>
```

The slug should be short and stable enough to be recognizable in a later session.

## State Transitions

Initial state:

```text
queued
```

When `runner.sh` begins:

```text
running
```

On normal exit:

- `succeeded` when exit code is `0`
- `failed` when exit code is non-zero

The task directory is never deleted automatically. Historical tasks are useful context.

## Recovery Rules

When continuing work in a later agent session:

1. Run `list`.
2. Run `show` for the candidate task.
3. Read `summary`, `why`, `cwd`, `status`, and the command text.
4. Read recent logs before deciding whether to resume, replace, or ignore the task.

## Why This Lives In A Skill

The hard part is not launching a process. The hard part is leaving a durable explanation of:

- what the process is
- why it exists
- how to recover it later

That is procedural knowledge, so it belongs in the skill rather than in the user prompt every time.
