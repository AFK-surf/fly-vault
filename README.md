# fly-vault

Remote development VM tooling for Fly.io with attestation-gated access and token authentication.

## What This Is

`fly-vault` is a Rust workspace with five binaries:

- `fly-vault` (client): runs on your laptop, verifies attestation, authenticates with `access_token`, opens console/port forwards.
- `fly-vault-admin` (deployment admin): runs on your laptop or CI, manages tenant machines in `vault-tenants` via the Fly Machines API.
- `init` (server): runs as the Fly Machine entrypoint, serves QUIC, provisions rootfs to `/data/rootfs`, preserves `/root` and `/home` under `/data/persist`, and boots the workload.
- `vault-proxy` (UDP multiplexer): routes client UDP packets to tenant machines by machine id.
- shared `protocol` crate: stream tags, control/console framing, shared wire types.

The design is documented in [DESIGN.md](DESIGN.md).

## Security Model Summary

- Attestation authenticity: client verifies Fly OIDC JWT signature and checks `iss` + `aud` channel binding + `app_name`.
- Transport security: QUIC (TLS 1.3).
- Authentication: single `ACCESS_TOKEN` used for initial provisioning and reconnects.
- Data at rest: the VM rootfs plus persistent `/root` and `/home` state are stored on the Fly volume (`/data/rootfs` and `/data/persist`) without client-side disk encryption.

Important: because data is not encrypted client-side, Fly platform operators with host/platform access can read persisted VM data.

## Repository Layout

- `crates/protocol`: stream tags, control/console framing, shared wire types.
- `crates/init`: VM-side server, setup manager, forwarding.
- `crates/client`: CLI client, attestation verification, console/forwarding.
- `crates/admin`: deployment admin CLI for tenant create/list/delete/update-image.
- `crates/proxy`: UDP proxy service for multi-tenant routing.
- `docs/`: protocol/API references used by the implementation.

## Build

```bash
cargo build
```

Build static `init` binary for container image:

```bash
cargo zigbuild --release --target x86_64-unknown-linux-musl -p init
```

## Test

```bash
cargo test
cargo test -p init --bin init
```

## Client Configuration

Config path:

- `~/.config/fly-vault/config.toml`

Example:

```toml
[vault.my-dev]
address = "[fdaa:x:x::x]:8443"
org = "my-org"
app = "my-dev-vault"
access_token = "secret-token-here"
forward = ["8080:localhost:8080"]
rootfs = "~/.config/fly-vault/rootfs/dev-env.tar.gz"
# Alternative: let init download a tar.gz directly
# rootfs_url = "https://example.com/dev-env.tar.gz"
```

## Client CLI Commands

```bash
fly-vault connect <vault-name>
fly-vault connect <vault-name> --forward 3000:localhost:3000
fly-vault connect <vault-name> --reprovision
fly-vault exec <vault-name> -- ls -lash /
fly-vault build
```

`--reprovision` sends a new rootfs tarball to a ready VM after successful token authentication. The reprovision replaces the extracted rootfs in place but preserves `/root` and `/home`.

For local development via Cargo:

```bash
cargo run -p fly-vault -- connect <vault-name>
cargo run -p fly-vault -- exec <vault-name> -- uname -a
```

## Deployment Admin CLI (`fly-vault-admin`)

Auth/config:

- `--api-token` or `FLY_API_TOKEN` (required)
- `--app` or `FLY_APP` (defaults to `vault-tenants`)
- `--api-base` or `FLY_API_BASE` (defaults to `https://api.machines.dev`)

Tenant template snippet:

```toml
version = 1
app = "vault-tenants"
machine_count = 1

[machine]
name = "tenant-{{tenant_id}}-{{index}}"
region = "ord"

[machine.config]
image = "registry.fly.io/vault-tenants/init:latest"

[[machine.config.mounts]]
path = "/data"
name = "tvol_{{tenant_id}}_{{index}}"

[machine.config.env]
ACCESS_TOKEN = "{{access_token}}"
```

Supported template variables:

- `{{tenant_id}}`
- `{{index}}` (1-based machine index)
- `{{access_token}}` (if `--access-token` is supplied)
- extra values from repeated `--var key=value`

Commands:

```bash
fly-vault-admin tenant create acme --template ./tenant.template.toml --access-token secret
fly-vault-admin tenant create acme --template ./tenant.template.toml --dry-run
fly-vault-admin tenant list --wide
fly-vault-admin tenant delete acme --yes
fly-vault-admin tenant update-image --image registry.fly.io/vault-tenants/init:latest --all-tenants
```
