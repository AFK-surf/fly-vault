---
name: remote-vm
description: Operate the `fly-vault` client CLI against configured Fly vault VMs. Use when Codex needs to connect to a vault, run one-off remote commands, inspect or reattach exec sessions, set up port forwards, reprovision a VM with a new rootfs, or troubleshoot `~/.config/fly-vault/config.toml` entries and attestation-related connection failures in this repository.
---

# Remote VM

## Overview

Use this skill to drive the real `fly-vault` client instead of describing commands abstractly. Prefer running the CLI, validating the local config first, and reporting exact commands and relevant output.

## Workflow

1. Confirm how to invoke the client.
   - Prefer `fly-vault ...` if the binary is already available.
   - Otherwise run from the repository root with `cargo run -q -p fly-vault -- ...`.
2. Read `~/.config/fly-vault/config.toml` and confirm the requested vault exists under `[vault.<name>]`.
3. Choose the narrowest command that matches the task.
   - Use `connect <vault>` for an interactive shell.
   - Use `connect <vault> --forward <local_port>:<target_host>:<target_port>` for local port forwarding.
   - Use `exec <vault> -- <command...>` for a one-shot remote command.
   - Use `list-exec <vault>` before reattaching to an existing exec session.
4. Preserve argument boundaries.
   - Put remote command arguments after `--` so local Clap parsing stops before the remote command begins.
5. If behavior is unclear, inspect `README.md`, `crates/client/src/main.rs`, and `crates/client/src/quic.rs`.

## Config Rules

Treat these config fields as the source of truth for a vault entry:

- Required for lookup and attestation matching: `address`, `org`, `app`
- Required at connection time: `access_token`
- Optional transport selector: `machine_id`
- Optional default forwards: `forward`
- Optional provisioning source: exactly one of `rootfs` or `rootfs_url`

Remember the runtime rules from the client:

- `machine_id` switches the client into proxy transport mode.
- `rootfs` or `rootfs_url` is required for a cold boot and for `connect --reprovision`.
- Setting both `rootfs` and `rootfs_url` is invalid.

## Command Selection

- Use `connect` when the user wants a shell, an interactive session, or long-lived forwards.
- Use `exec` when the user wants a single command, a scripted probe, or a resumable named session.
- Use `exec --session <id>` to reattach to an existing exec session returned by `list-exec`.
- Use `list-exec` when the user asks what is already running or how to reattach.
- Use `build` only when the task is to build the static `init` binary for image packaging.

## Troubleshooting

- `vault <name> not found` means the config entry is missing or misnamed.
- `access_token is required` means the vault config lacks `access_token`.
- Provisioning errors about `rootfs` or `rootfs_url` usually mean the vault is cold or the user requested `--reprovision` without a valid source configured.
- Attestation mismatch errors usually point to the wrong `org`, `app`, or `machine_id` in config.
- The client caches successful attestation fingerprints under the user cache directory in `fly-vault/attestation-cache-v1.json`.

## Reference

Load `references/cli.md` when you need concrete command patterns, config examples, or a short troubleshooting checklist.
