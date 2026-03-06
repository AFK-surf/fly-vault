---
name: remote-task
description: Run, track, and resume work on a remote VM reached through `fly-vault`, especially when multiple long-lived tasks may run concurrently and each task must carry explicit context describing what it does and why it exists. Use when the agent needs to spawn tmux-backed remote commands, persist task metadata inside the provisioned rootfs, list existing tasks, inspect status and logs, or attach to an existing task across agent sessions.
---

# Remote Task

## Overview

Use this skill when `fly-vault` should be treated as a remote task transport rather than just an interactive shell.

`fly-vault` itself only gives you:

- an authenticated console session
- optional TCP forwards

It does not provide a remote job API. This skill layers a VM-side control service on top of the console channel and then talks to that service through repeated `fly-vault exec` calls, so another agent instance can:

- start more than one remote task at a time
- persist task context across reconnects and agent turnover
- recover task state later without guessing why a process exists
- drive tmux sessions non-interactively without rendering a full-screen terminal

The default interface is [scripts/fly_vault_remote_task.py](./scripts/fly_vault_remote_task.py).
The VM-side service implementation is [scripts/remote_task_service.py](./scripts/remote_task_service.py).

Read [references/task-model.md](./references/task-model.md) when you need the exact on-disk layout or need to change how tasks are managed.

The packaged skill includes `fly-vault` binaries at:

- `./assets/bin/linux-amd64/fly-vault`
- `./assets/bin/linux-arm64/fly-vault`

Always use the packaged `fly-vault` binary that matches the current Linux architecture. Do not rely on a host-installed `fly-vault` from `PATH` when the packaged binary is present.

## fly-vault Primer

Treat this section as the authoritative system model for the distributed skill. Do not assume the local filesystem contains the `fly-vault` source tree, Rust workspace, or repository docs.

`fly-vault` is a client/server system for reaching a Fly Machine over QUIC after attestation and token verification.

Relevant pieces:

- `fly-vault`: the local CLI the agent invokes
- `init`: the VM-side server already running inside the remote machine
- shared protocol semantics: control messages for attestation, authentication, and setup, plus separate console and port-forward streams
- the remote-task control service: a small HTTP service started inside the VM and reached from later `fly-vault exec` calls over the VM's own localhost

Operational model:

- The client opens a QUIC connection to the VM.
- The client requests attestation and verifies a Fly OIDC JWT bound to TLS exporter material.
- The client authenticates with `ACCESS_TOKEN`.
- Once setup is complete, the client may open a console stream or port-forward streams.

VM lifecycle:

- `Cold`: the VM has not been provisioned yet.
- `Ready`: rootfs has already been provisioned and the VM accepts reconnects.
- `--reprovision` on a normal interactive session replaces the provisioned rootfs.

What matters for remote tasks:

- The console stream opens a fresh shell each time. There is no built-in remote job or session registry.
- `fly-vault exec` can run one remote command and exit while still reusing the console protocol underneath.
- Anything stored inside the provisioned rootfs survives reconnects but is erased by reprovision.
- The current design stores the root filesystem directly on the Fly volume without client-side disk encryption.

That is why this skill stores task metadata in the provisioned rootfs, bootstraps a localhost-only control service inside the VM, and uses later `fly-vault exec` calls for list/show/spawn/tmux control operations.

## Finding Remote VMs

The helper needs a `vault` name, which is the entry name used by `fly-vault`.

In normal setups, discover available remote VMs by inspecting the local client config:

```text
~/.config/fly-vault/config.toml
```

Look under the `[vault.<name>]` sections. Each section name is a usable vault name.

Example:

```toml
[vault.my-dev]
address = "example.fly.dev:8443"
org = "my-org"
app = "my-dev-vault"
access_token = "..."
```

In that example, the vault name is `my-dev`.

If you are unsure which vault to use:

1. Read `~/.config/fly-vault/config.toml`.
2. Enumerate the `[vault.<name>]` entries.
3. Pick the vault that matches the user’s requested environment.
4. If several entries could match, ask the user before starting work on the wrong VM.

## Operating Rules

Treat `/var/lib/fly-vault/remote-task` as the canonical task root inside the provisioned rootfs.

This is intentionally inside the provisioned rootfs:

- reconnects keep the task registry
- agent sessions can come and go without losing context
- reprovision wipes tasks, which is correct because reprovision replaces the rootfs

Before starting new work, always check for existing tasks first:

```bash
python3 skills/remote-task/scripts/fly_vault_remote_task.py list --vault <vault>
```

If an existing task already covers the work, reuse it instead of spawning a duplicate.

The first helper invocation for a vault bootstraps the VM-side service with `fly-vault exec <vault> -- /bin/sh -lc ...`. After bootstrap, normal interactions should keep using the helper so task operations go through the service instead of ad hoc shell commands.

## Spawn Workflow

1. Write a one-line `summary` that states what the task is doing.
2. Write a one-line `why` that explains why this task was started now.
3. Choose the remote `cwd`.
4. Provide the exact shell command to run.

Always use `tmux`. This skill assumes remote tasks are reattachable interactive sessions, even when the command itself is mostly batch-like.

Before real work on a new VM, run `doctor` once:

```bash
python3 skills/remote-task/scripts/fly_vault_remote_task.py doctor \
  --vault my-dev \
  --cwd /workspace/fly-vault
```

Example:

```bash
python3 skills/remote-task/scripts/fly_vault_remote_task.py spawn \
  --vault my-dev \
  --summary "Run workspace tests after refactor" \
  --why "Need a long-running verification task while continuing local edits" \
  --cwd /workspace/fly-vault \
  --command 'cargo test --workspace'
```

## Recover Workflow

List tasks:

```bash
python3 skills/remote-task/scripts/fly_vault_remote_task.py list --vault <vault>
```

Inspect one task:

```bash
python3 skills/remote-task/scripts/fly_vault_remote_task.py show --vault <vault> --task <task-id>
```

Read recent output:

```bash
python3 skills/remote-task/scripts/fly_vault_remote_task.py logs --vault <vault> --task <task-id>
```

Follow output live:

```bash
python3 skills/remote-task/scripts/fly_vault_remote_task.py logs --vault <vault> --task <task-id> --follow
```

When resuming work in a later session, read `show` before touching the task. Re-state the stored `summary` and `why` in your own words so the user can see that you recovered the correct context.

For non-interactive tmux control, use:

```bash
python3 skills/remote-task/scripts/fly_vault_remote_task.py send-keys \
  --vault <vault> \
  --task <task-id> \
  --keys 'make test' \
  --enter
```

```bash
python3 skills/remote-task/scripts/fly_vault_remote_task.py capture-pane \
  --vault <vault> \
  --task <task-id>
```

If a task is stuck in `queued` or failed during startup after prerequisites were fixed, use:

```bash
python3 skills/remote-task/scripts/fly_vault_remote_task.py repair \
  --vault <vault> \
  --task <task-id>
```

## Attach Rules

Every task created by this skill should be tmux-backed.

1. Retrieve the attach snippet:

```bash
python3 skills/remote-task/scripts/fly_vault_remote_task.py attach-snippet \
  --vault <vault> \
  --task <task-id>
```

2. Open an interactive tmux attach directly:

```bash
fly-vault exec <vault> -- tmux attach -t <session-name>
```

3. Paste the returned snippet, typically `tmux attach -t <session-name>`.

## Helper Script Notes

[scripts/fly_vault_remote_task.py](./scripts/fly_vault_remote_task.py) uses `fly-vault exec <vault> -- /bin/sh -lc ...` for bootstrap because it runs one remote shell command and exits cleanly after the bootstrap script completes.

When the skill is packaged with embedded Linux binaries, the helper auto-selects the bundled `fly-vault` binary on Linux `amd64` and `arm64`. This is the expected execution path for the distributed skill.

Use the packaged binary by default. Only use `FLY_VAULT_BIN` or `--fly-vault-bin` if you are explicitly told to override it or the packaged binary is unavailable.

Packaged binary locations:

```text
skills/remote-task/assets/bin/linux-amd64/fly-vault
skills/remote-task/assets/bin/linux-arm64/fly-vault
```

Override example:

```bash
python3 skills/remote-task/scripts/fly_vault_remote_task.py \
  --fly-vault-bin /path/to/fly-vault \
  list \
  --vault my-dev
```

The helper intentionally stores:

- `summary`
- `why`
- `cwd`
- tmux session metadata
- command text
- timestamps
- pid and pgid when available
- combined log output
- service metadata under `/var/lib/fly-vault/remote-task/.service`

Do not hand-roll tmux control over raw `fly-vault exec` sessions unless you are repairing the service itself. Use the helper so normal automation goes through the remote control service.
