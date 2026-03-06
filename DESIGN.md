# fly-vault Design

## 1. Overview

`fly-vault` provides a QUIC control channel between a local client and an `init`
process running inside a Fly Machine.

Current model:

- Attestation: the client verifies a Fly OIDC JWT (`iss`, `aud`, `app_name`)
  bound to TLS exporter material.
- Authentication: one shared `ACCESS_TOKEN` authorizes both first-time
  provisioning and reconnects.
- Storage: the active rootfs lives at `/data/rootfs`, while persistent `/root`
  and `/home` data live under `/data/persist`.
- Reprovisioning: new rootfs payloads are staged and validated before being
  promoted to `/data/rootfs`; the previous rootfs is kept until the new runtime
  starts successfully.

Important trade-off: persisted data is not encrypted with a client-held key.
Fly platform operators with sufficient infrastructure access can read data at
rest.

## 2. Components

Workspace crates:

- `crates/protocol`: shared wire protocol, typed control messages, console
  framing, and proxy packet framing.
- `crates/client`: `fly-vault` CLI.
- `crates/init`: VM-side `init` QUIC server and setup manager.
- `crates/admin`: `fly-vault-admin` tenant management tooling.
- `crates/proxy`: UDP multiplexer for routing to tenant machines.

## 3. State Model

### 3.1 VM state

`VmState` has two states:

- `Cold`: no provisioning marker (`/data/.provisioned`) exists yet.
- `Ready`: provisioning completed at least once.

Transitions:

- `Cold -> Ready`: valid `ACCESS_TOKEN` plus a rootfs payload are accepted, the
  rootfs is staged and promoted, persistent `/root` and `/home` are attached,
  and `/data/.provisioned` is written.
- `Ready -> Ready`: reconnect with a valid `ACCESS_TOKEN`; optional reprovision
  with a new rootfs payload while preserving `/root` and `/home`.

### 3.2 Runtime status

Attestation also reports runtime health separately from `VmState`:

- `NotStarted`: no inner runtime is running.
- `SystemInit`: the namespaced `/sbin/init` is running normally.
- `FallbackInit`: `/sbin/init` failed and the namespace is being held by a
  minimal fallback reaper.

Clients reject `FallbackInit` for normal reconnects. It is only tolerated as a
degraded runtime immediately before reprovision.

## 4. Control Protocol

The protocol is versioned. Current version: `1`.

Control messages:

- `CONTROL_REQUEST_ATTESTATION` (`0x01`)
- `CONTROL_ATTESTATION` (`0x02`)
- `CONTROL_SETUP_REQUEST` (`0x03`)
- `CONTROL_SETUP_COMPLETE` (`0x04`)
- `CONTROL_ERROR` (`0x05`)

`CONTROL_SETUP_REQUEST` is a single typed payload containing:

- `access_token`
- `rootfs` source:
  - `None`
  - inline tarball bytes
  - URL to download

This replaced the older multi-frame control flow. There is no backward
compatibility path for the previous frame layout or previous `VmState` values.

## 5. Authentication And Provisioning Flow

### 5.1 Cold boot

1. Client opens the control stream and requests attestation.
2. `init` returns an attestation payload containing:
   - protocol version
   - `VmState`
   - `RuntimeStatus`
   - attestation JWT
3. Client verifies protocol version, runtime status, and attestation claims.
4. Client sends one `CONTROL_SETUP_REQUEST` containing the access token and a
   rootfs source.
5. `init` verifies the token, resolves the rootfs source, stages the rootfs,
   promotes it atomically, starts the namespaced runtime, and returns
   `CONTROL_SETUP_COMPLETE`.

### 5.2 Reconnect (`Ready`)

1. Client requests and verifies attestation.
2. Client sends `CONTROL_SETUP_REQUEST` with the access token and `rootfs=None`.
3. `init` verifies the token, ensures the runtime is live, and returns
   `CONTROL_SETUP_COMPLETE`.

### 5.3 Reprovision (`Ready`)

1. Client requests and verifies attestation.
2. Client sends `CONTROL_SETUP_REQUEST` with the access token and a new rootfs
   source.
3. `init` stages the new rootfs under `/data/rootfs.staging`.
4. `init` stops the old runtime, moves the existing rootfs aside, promotes the
   staged rootfs, and starts a new runtime.
5. If runtime start fails, `init` restores the previous rootfs and attempts to
   restart the previous runtime.

## 6. Setup Manager Behavior

`crates/init/src/setup.rs`:

- Detects `Cold` vs `Ready` from `.provisioned`.
- Extracts rootfs tarballs into `/data/rootfs.staging`.
- Preserves `/root` and `/home` under `/data/persist` and mounts them into the
  active root.
- Promotes staged rootfs content into `/data/rootfs` only after extraction and
  persistent layout preparation succeed.
- Keeps the previous rootfs at `/data/rootfs.previous` until the new runtime is
  confirmed started.
- Launches an inner PID+mount namespace for the active rootfs.
- Falls back to a minimal init only if `/sbin/init` cannot be executed inside
  the new namespace.

## 7. Configuration

### 7.1 Client config

The user-facing config format is unchanged. Direct vs proxy transport is derived
from whether `machine_id` is present.

```toml
[vault.example]
address = "example.fly.dev:8443"
org = "my-org"
app = "my-app"
access_token = "secret-token"
rootfs = "~/rootfs.tar.gz"
# Optional: proxy transport when connecting through vault-proxy
# machine_id = "148e21ea7e46e8"
# or rootfs_url = "https://.../rootfs.tar.gz"
```

### 7.2 Machine env

`init` expects:

- `ACCESS_TOKEN` for provisioning and reconnect authorization.

After startup, the process removes `ACCESS_TOKEN` from the environment with
`std::env::remove_var`.

## 8. Admin And Proxy Notes

### 8.1 Admin

`fly-vault-admin`:

- requires explicit app selection (`--app` or `FLY_APP`)
- rolls back the machine that failed mid-update, not only previously successful
  machines
- preserves cleanup errors when tenant creation partially succeeds
- uses structured HTTP-status handling for Machines API wait timeouts

### 8.2 Proxy

`vault-proxy`:

- uses the shared proxy packet framing from `crates/protocol`
- treats backend UDP bind/connect failures as request errors instead of
  panicking the process
- keeps a lightweight machine-state cache for routing/start decisions

## 9. Limitations And Risks

- No client-held disk encryption.
- No strict digest allowlist or machine-config verification yet.
- Security still depends on attestation validation, transport security, and
  token secrecy.
- Fallback init is a degraded recovery path, not a full substitute for a
  healthy `/sbin/init`.

## 10. Operational Notes

Recommended checks after changes:

- `cargo fmt -- --check`
- `cargo check`
- `cargo test`
- `cargo test -p init --bin init`
