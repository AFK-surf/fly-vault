# fly-vault Design

## 1. Overview

`fly-vault` provides a QUIC control channel between a local client and an `init` process running in a Fly Machine.

Current model:

- Attestation: client verifies Fly OIDC JWT (`iss`, `aud`, `app_name`) bound to TLS exporter material.
- Authentication: one shared `ACCESS_TOKEN` for both first-time provisioning and reconnect.
- Storage: rootfs is extracted directly onto the Fly volume at `/data/rootfs` (no client-side disk encryption).

Important trade-off: persisted data is not encrypted with a client-held key. Fly platform operators with sufficient infrastructure access can read data at rest.

## 2. Components

Workspace crates:

- `crates/protocol`: control/console stream framing and shared wire types.
- `crates/client`: `fly-vault` CLI.
- `crates/init`: VM-side `init` QUIC server and setup manager.
- `crates/admin`: `fly-vault-admin` tenant management tooling.
- `crates/proxy`: UDP multiplexer for routing to tenant machines.

## 3. State Machine

`VmState` has two states:

- `Cold`: no provisioning marker (`/data/.access_token_hash`) yet.
- `Ready`: provisioning completed at least once.

Transitions:

- `Cold -> Ready`: valid `ACCESS_TOKEN` and rootfs payload accepted, rootfs extracted, token hash written.
- `Ready -> Ready`: reconnect with valid `ACCESS_TOKEN`; optional reprovision with new rootfs payload.

## 4. Control Protocol

Control frames used by the provisioning/auth flow:

- `CONTROL_REQUEST_ATTESTATION` (`0x01`)
- `CONTROL_ATTESTATION` (`0x02`)
- `CONTROL_PROVISION_ROOTFS` (`0x04`)
- `CONTROL_SETUP_COMPLETE` (`0x05`)
- `CONTROL_ERROR` (`0x06`)
- `CONTROL_ACCESS_TOKEN` (`0x07`)
- `CONTROL_PROVISION_ROOTFS_URL` (`0x08`)

## 5. Authentication Flow

### 5.1 Cold Boot

1. Client requests attestation and verifies JWT (relaxed mode only).
2. Client sends `CONTROL_ACCESS_TOKEN`.
3. `init` checks token against `ACCESS_TOKEN` environment variable.
4. Client sends rootfs (`CONTROL_PROVISION_ROOTFS` or URL variant).
5. `init` extracts rootfs, stores `SHA256(ACCESS_TOKEN)` to `/data/.access_token_hash`, enters `Ready`.

### 5.2 Reconnect (Ready)

1. Client requests and verifies attestation.
2. Client sends `CONTROL_ACCESS_TOKEN`.
3. `init` verifies `SHA256(token)` against `/data/.access_token_hash`.
4. Server returns `CONTROL_SETUP_COMPLETE` and enables console/forward streams.

### 5.3 Reprovision (Ready)

1. Client authenticates with `CONTROL_ACCESS_TOKEN` as above.
2. Client sends new rootfs payload.
3. `init` extracts new rootfs and returns `CONTROL_SETUP_COMPLETE`.

## 6. Setup Manager Behavior

`crates/init/src/setup.rs`:

- Detects state from `.access_token_hash`.
- Stores and verifies token hash with SHA-256.
- Extracts rootfs tarball into configured root mount dir (`/data/rootfs` by default).
- Optionally launches inner init in PID+mount namespaces when running outside test mode.

## 7. Configuration

### 7.1 Client config

```toml
[vault.example]
address = "example.fly.dev:8443"
org = "my-org"
app = "my-app"
access_token = "secret-token"
rootfs = "~/rootfs.tar.gz"
# or rootfs_url = "https://.../rootfs.tar.gz"
```

### 7.2 Machine env

`init` expects:

- `ACCESS_TOKEN` for cold provisioning authorization.

After startup, the process removes `ACCESS_TOKEN` from environment memory via `std::env::remove_var`.

## 8. Limitations and Risks

- No strict-mode digest allowlist or machine-config verification.
- No client-held disk encryption.
- Security rests on attestation validation, transport security, and token secrecy.

## 9. Operational Notes

Recommended checks after changes:

- `cargo fmt -- --check`
- `cargo check`
- `cargo test`
- `cargo test -p init --bin init`
