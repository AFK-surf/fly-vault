# fly-vault

Secure remote development VM on Fly.io where the client key holder is the only party that can unlock persistent data.

## What This Is

`fly-vault` is a Rust workspace with four binaries:

- `fly-vault` (client): runs on your laptop, performs attestation, releases the disk key only after verification, opens console/port forwards.
- `fly-vault-admin` (deployment admin): runs on your laptop or CI, manages tenant machines in `vault-tenants` via the Fly Machines API.
- `init` (server): runs as the Fly Machine entrypoint, serves QUIC, handles attestation flow, unlocks encrypted storage, and boots the workload.
- `vault-proxy` (UDP multiplexer): routes client UDP packets to tenant machines by machine id.

The full design and threat model are in [DESIGN.md](DESIGN.md).

## Security Model Summary

- Image integrity: client verifies attested `image_digest` against local allowlist.
- Channel binding: OIDC `aud` is bound to TLS exported keying material for the active QUIC session.
- Config integrity: client fetches machine config from Machines API and rejects unsafe overrides.
- Data at rest: AES-256-XTS encrypted image file; key is client-held and released only after attestation.

## Repository Layout

- `crates/protocol`: stream tags, control/console framing, shared wire types.
- `crates/crypto`: AES-256-XTS sector crypto and key handling.
- `crates/init`: VM-side server, setup manager, FUSE bridge, forwarding.
- `crates/client`: CLI client, attestation verification, config verification, console/forwarding.
- `crates/admin`: deployment admin CLI for tenant create/list/delete/update-image.
- `crates/proxy`: UDP proxy service for multi-tenant routing.
- `docs/`: protocol/API references used by the implementation.

## Prerequisites

General development:

- Rust stable toolchain
- Cargo

For real VM-side runtime (non-test mode):

- Linux with `/dev/fuse`, loop device support, and privileges for mount/chroot/namespace operations.
- `mkfs.ext4` and `losetup` available in PATH.

For client attestation in real Fly environment:

- Fly API token with read access to target app (for machine config verification).

For deployment management (`fly-vault-admin`):

- Fly API token with write access to `vault-tenants` machines and volumes.

## Build

Build everything:

```bash
cargo build
```

Build static `init` binary for container image:

```bash
cargo zigbuild --release --target x86_64-unknown-linux-musl -p init
```

## Test

Run all tests:

```bash
cargo test
```

## End-to-End (E2E) Setup Info

The project includes in-process E2E tests for the `init` state machine and control protocol in `crates/init/src/main.rs` (`#[cfg(test)]` module).

What these E2E tests verify:

- Cold boot flow: attestation reports `Cold`, then `ReleaseKey + ProvisionRootfs` transitions machine to `Ready`.
- Locked boot flow: attestation reports `Locked`, then `ReleaseKey` transitions to `Ready`.
- Reconnect behavior: after setup, a new connection sees `Ready`.

How E2E runs safely in CI/dev:

- Tests run `init` logic in `--test-mode` behavior, which bypasses privileged FUSE/loop/mount/chroot operations.
- QUIC control-plane behavior remains real (UDP + QUIC streams + protocol framing).

Run only the `init` E2E tests:

```bash
cargo test -p init --bin init
```

Environment requirements for E2E tests:

- Local UDP loopback networking must be allowed.
- Ability to bind ephemeral UDP ports on localhost.

If tests fail in sandboxed environments, rerun with permissions that allow local UDP sockets.

## Client Configuration

Example config path:

- `~/.config/fly-vault/config.toml`

Example structure:

```toml
[vault.my-dev]
address = "[fdaa:x:x::x]:8443"
org = "my-org"
app = "my-dev-vault"
fly_api_token = "fo1_..."
allowed_digests = ["sha256:..."]
forward = ["8080:localhost:8080"]
rootfs = "~/.config/fly-vault/rootfs/dev-env.tar.gz"
# Alternative to local upload: let init download a tar.gz directly
# rootfs_url = "https://example.com/dev-env.tar.gz"
```

Key path:

- `~/.config/fly-vault/keys/<vault>.key` (created with mode `0600`).

## Client CLI Commands

```bash
fly-vault connect <vault-name>
fly-vault connect <vault-name> --forward 3000:localhost:3000
fly-vault keygen <vault-name>
fly-vault allow <vault-name> sha256:<digest>
fly-vault build
```

For local development via Cargo:

```bash
cargo run -p fly-vault -- connect <vault-name>
```

## Deployment Admin CLI (`fly-vault-admin`)

`fly-vault-admin` manages tenant machines in the `vault-tenants` app. It does not manage `vault-proxy`.

Auth/config:

- `--api-token` or `FLY_API_TOKEN` (required)
- `--app` or `FLY_APP` (defaults to `vault-tenants`)
- `--api-base` or `FLY_API_BASE` (defaults to `https://api.machines.dev`)

Tenant metadata used for discovery:

- `fly_vault.tenant_id=<tenant_id>`
- `fly_vault.managed_by=fly-vault-admin`
- `fly_vault.template=<template-file>`

### Tenant Template

Creation is template-driven (`--template <path>`). Example:

```toml
version = 1
app = "vault-tenants"
machine_count = 3

[machine]
name = "tenant-{{tenant_id}}-{{index}}"
region = "ord"

[machine.config]
image = "registry.fly.io/vault-tenants/init:2026-03-02"
size = "shared-cpu-2x"

[[machine.config.mounts]]
path = "/data"
name = "tvol_{{tenant_id}}_{{index}}"

[machine.config.env]
PROVISION_TOKEN = "{{provision_token}}"

[metadata]
role = "tenant-vm"
```

Supported template variables:

- `{{tenant_id}}`
- `{{index}}` (1-based machine index)
- `{{provision_token}}` (if `--provision-token` is supplied)
- extra values from repeated `--var key=value`

Mount semantics:

- `[[machine.config.mounts]] volume = "<id>"` attaches an existing Fly volume ID.
- `[[machine.config.mounts]] name = "<name>"` auto-creates a volume in the machine region and injects the resulting `volume` ID into the create request.

### Commands

```bash
# create tenant machines from template
fly-vault-admin tenant create acme --template ./tenant.template.toml --provision-token secret

# show rendered Machines API payload without creating
fly-vault-admin tenant create acme --template ./tenant.template.toml --dry-run

# list tenants (summary / wide / json)
fly-vault-admin tenant list
fly-vault-admin tenant list --wide
fly-vault-admin tenant list --json
fly-vault-admin tenant list --tenant acme

# safe delete (requires explicit confirmation), deletes machines and attached volumes
fly-vault-admin tenant delete acme --yes
```

### Graceful Image Rollout

```bash
# update selected tenants
fly-vault-admin tenant update-image --image registry.fly.io/vault-tenants/init:2026-03-10 --tenant acme --tenant beta

# update all tenants
fly-vault-admin tenant update-image --image registry.fly.io/vault-tenants/init:2026-03-10 --all-tenants
```

Rollout behavior:

- canary-first (`--canary`, default `1`)
- rolling updates with global concurrency (`--concurrency`) and max one in-flight machine per tenant
- health/start/soak gating (`--start-timeout-secs`, `--health-timeout-secs`, `--soak-secs`)
- automatic rollback to previous image if any canary or rollout step fails

## Fly Image/Deploy Workflow

1. Build static `init` binary.
2. Build and push image (`Dockerfile` uses Alpine and copies `/init`).
3. Add new image digest to local allowlist via `fly-vault allow`.
4. For single machine/manual flow: update/deploy machine config and connect.
5. For multi-tenant flow: run `fly-vault-admin tenant update-image ...`.

## Notes

- The implementation includes a `--test-mode` path in `init` intended only for tests/dev harnesses.
- Real security properties assume normal mode with real OIDC token retrieval from `/.fly/api` and full client-side verification.
