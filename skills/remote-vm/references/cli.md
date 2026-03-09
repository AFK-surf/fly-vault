# fly-vault CLI Reference

## Config File

Default config path:

```text
~/.config/fly-vault/config.toml
```

Minimal example:

```toml
[vault.my-dev]
address = "[fdaa:x:x::x]:8443"
org = "my-org"
app = "my-dev-vault"
access_token = "secret-token-here"
rootfs = "~/.config/fly-vault/rootfs/dev-env.tar.gz"
```

Proxy mode example:

```toml
[vault.my-proxy]
address = "proxy.fly.dev:443"
org = "my-org"
app = "my-proxy-vault"
machine_id = "148e21ea7e46e8"
access_token = "secret-token-here"
rootfs_url = "https://example.com/dev-env.tar.gz"
forward = ["8080:localhost:8080"]
```

Notes:

- `machine_id` enables proxy transport.
- `forward` is used only when `connect` is called without explicit `--forward`.
- Configure exactly one of `rootfs` or `rootfs_url` when provisioning is needed.

## Commands

If `fly-vault` is not installed, run the client from the repository root:

```bash
cargo run -q -p fly-vault -- connect my-dev
```

Interactive shell:

```bash
fly-vault connect my-dev
```

Port forward to a service inside the VM:

```bash
fly-vault connect my-dev --forward 3000:localhost:3000
```

Reprovision a ready VM with a new configured rootfs:

```bash
fly-vault connect my-dev --reprovision
```

Run a one-shot command:

```bash
fly-vault exec my-dev -- uname -a
```

Run a tagged exec session:

```bash
fly-vault exec my-dev --context "investigate deploy failure" -- sh -lc 'journalctl -n 200'
```

List resumable exec sessions:

```bash
fly-vault list-exec my-dev
```

Reattach to a prior exec session:

```bash
fly-vault exec my-dev --session sess-1
```

Build the static `init` binary:

```bash
fly-vault build
```

## Behavior Notes

- `connect` without forwards opens the interactive console and automatically retries reconnectable transport failures.
- `connect` with forwards opens the console in the background and keeps local forwarders running until interrupted.
- `exec` prints the generated or supplied session id before attaching.
- `list-exec` prints JSON describing `session_id`, `argv`, `context`, `attached`, and `exit_code`.

## Failure Checklist

- Missing vault entry: verify the name under `[vault.<name>]`.
- Missing token: add `access_token`.
- Provisioning failure: fix `rootfs` or `rootfs_url`.
- Attestation mismatch: verify `org`, `app`, and `machine_id`.
- Reattach failure: run `list-exec` first and confirm the session still exists.
