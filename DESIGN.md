# fly-vault Design

## 1. Overview

`fly-vault` provides a QUIC control channel between a local client and an `init`
process running inside a Fly Machine.

Current model:

- Attestation: the client verifies a Fly OIDC JWT (`iss`, `aud`, `app_name`)
  bound to TLS exporter material.
- Trust reuse: once a specific `init` TLS leaf certificate fingerprint has
  passed attestation for an `(org, app, machine_id)` tuple, the client may
  reuse that result from an on-disk cache until `init` restarts and rotates
  its in-memory keypair.
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

No wire-format change is required for attestation caching. The client can keep
requesting `CONTROL_ATTESTATION` on every connection and decide locally whether
the JWT needs full verification.

## 5. Authentication And Provisioning Flow

### 5.1 Cold boot

1. Client completes the QUIC handshake, extracts the server TLS leaf
   certificate fingerprint, and checks the local attestation cache.
2. Client opens the control stream and requests attestation.
3. `init` returns an attestation payload containing:
   - protocol version
   - `VmState`
   - `RuntimeStatus`
   - attestation JWT
4. On a cache miss, the client performs full JWT verification against the
   exporter-derived audience and stores the verified fingerprint on disk.
5. On a cache hit, the client skips JWT verification and trusts the connection
   based on the cached fingerprint.
6. Client still checks protocol version and consumes `VmState` and
   `RuntimeStatus` from the attestation payload.
7. Client sends one `CONTROL_SETUP_REQUEST` containing the access token and a
   rootfs source.
8. `init` verifies the token, resolves the rootfs source, stages the rootfs,
   promotes it atomically, starts the namespaced runtime, and returns
   `CONTROL_SETUP_COMPLETE`.

### 5.2 Reconnect (`Ready`)

1. Client completes the QUIC handshake, extracts the server TLS fingerprint,
   and checks the local attestation cache.
2. Client requests `CONTROL_ATTESTATION`.
3. On a cache miss, the client performs the current full attestation flow and
   stores the verified fingerprint.
4. On a cache hit, the client skips JWT verification but still checks protocol
   version and reads `VmState` and `RuntimeStatus`.
5. Client sends `CONTROL_SETUP_REQUEST` with the access token and `rootfs=None`.
6. `init` verifies the token, ensures the runtime is live, and returns
   `CONTROL_SETUP_COMPLETE`.

### 5.3 Reprovision (`Ready`)

1. Client completes the QUIC handshake, extracts the server TLS fingerprint,
   and checks the local attestation cache.
2. Client requests `CONTROL_ATTESTATION`.
3. On a cache miss, the client performs the current full attestation flow and
   stores the verified fingerprint.
4. On a cache hit, the client skips JWT verification but still checks protocol
   version and reads `VmState` and `RuntimeStatus`.
5. Client sends `CONTROL_SETUP_REQUEST` with the access token and a new rootfs
   source.
6. `init` stages the new rootfs under `/data/rootfs.staging`.
7. `init` stops the old runtime, moves the existing rootfs aside, promotes the
   staged rootfs, and starts a new runtime.
8. If runtime start fails, `init` restores the previous rootfs and attempts to
   restart the previous runtime.

### 5.4 Attestation cache

The attestation cache lives entirely on the client. `init` remains stateless
with respect to attestation reuse.

Cache key:

- `org`
- `app`
- `machine_id`
- TLS leaf certificate fingerprint: `sha256(peer_cert_der)`, derived from the
  leaf certificate returned by `quinn::Connection::peer_identity()`

Cache entry fields:

- `org`
- `app`
- `machine_id`
- `fingerprint`
- `verified_at`
- `last_seen_at`

Recommended path:

- `${XDG_CACHE_HOME}/fly-vault/attestation-cache-v1.json`
- fallback: `~/.cache/fly-vault/attestation-cache-v1.json`

Lookup rules:

- Proxy transport: require an exact match on configured `machine_id`,
  `org`, `app`, and fingerprint.
- Direct transport: allow lookup by `org`, `app`, and fingerprint, then reuse
  the cached `machine_id` learned from the last successful attestation for that
  fingerprint.
- A cache hit is only a trust shortcut. The client still requests
  `CONTROL_ATTESTATION` to learn `VmState`, `RuntimeStatus`, and protocol
  version for the current connection.

Population rules:

- Only write an entry after a full attestation succeeds.
- The `machine_id` written to the cache comes from verified attestation claims,
  never from configuration alone.
- Update `last_seen_at` on successful cache-hit connections.
- Use read-modify-write with a temp file plus atomic rename so concurrent
  client processes do not leave a truncated cache file behind.

Invalidation rules:

- If `init` restarts and generates a new ephemeral certificate, the fingerprint
  changes and the client falls back to full attestation automatically.
- If a cached entry does not match the configured proxy `machine_id`, ignore it
  and require full attestation.
- Negative results are not cached.
- Stale entries may be garbage-collected opportunistically; they are harmless
  because a mismatched fingerprint already forces re-attestation.

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

### 7.2 Client cache

No new user-managed config is required. The client maintains the attestation
cache under the OS cache directory and treats it as disposable local state.

### 7.3 Machine env

`init` expects:

- `ACCESS_TOKEN` for provisioning and reconnect authorization.

After startup, the process removes `ACCESS_TOKEN` from the environment with
`std::env::remove_var`.

## 8. Control Socket API

When `fly-vault connect --control-socket <path>` is used, the client exposes an
HTTP/1.1 API over a Unix domain socket. This lets other local processes reuse the
established QUIC session without performing their own attestation handshake.

Endpoints:

- `POST /exec` — run a command on the vault. Request body is JSON:

  ```json
  {
    "command": ["ls", "-la", "/"],
    "session_id": "optional-custom-id",
    "context": "optional audit context"
  }
  ```

  The response streams raw command output as `application/octet-stream` with
  chunked transfer encoding. The `X-Session-Id` header identifies the session.

- `GET /list-exec` — list all exec sessions. Returns a JSON array of
  `ExecSessionInfo` objects (same schema as `fly-vault list-exec`).

The control socket server shares the QUIC connection established by `connect`.
Each HTTP request opens its own QUIC stream, so multiple concurrent exec
sessions are supported. If the QUIC connection is lost, in-flight HTTP requests
receive a 502 error.

## 9. Exec Session Lifecycle

Exec sessions are managed by `ExecSessionManager` inside `init`. Each session
is a persistent PTY process identified by a `session_id`.

- **Creation**: a `CONSOLE_EXEC` frame with `argv` spawns a new session.
- **Reconnection**: a `CONSOLE_EXEC` frame with the same `session_id` and
  `argv=None` reattaches to an existing session, replaying buffered output from
  `rendered_bytes`.
- **Detach cleanup**: when a client disconnects from an exited session, it is
  removed immediately.
- **TTL cleanup**: a background reaper removes exited sessions that have had no
  client attachment for 60 seconds. This prevents unbounded accumulation when
  clients never reconnect after a session exits.

## 10. Admin And Proxy Notes

### 10.1 Admin

`fly-vault-admin`:

- requires explicit app selection (`--app` or `FLY_APP`)
- rolls back the machine that failed mid-update, not only previously successful
  machines
- preserves cleanup errors when tenant creation partially succeeds
- uses structured HTTP-status handling for Machines API wait timeouts

### 10.2 Proxy

`vault-proxy`:

- uses the shared proxy packet framing from `crates/protocol`
- treats backend UDP bind/connect failures as request errors instead of
  panicking the process
- keeps a lightweight machine-state cache for routing/start decisions

## 11. Limitations And Risks

- No client-held disk encryption.
- No strict digest allowlist or machine-config verification yet.
- Security still depends on initial attestation validation, transport security,
  and token secrecy.
- Cache hits no longer prove fresh per-connection exporter binding through the
  JWT. Instead they rely on continuity of the same ephemeral TLS private key,
  which is acceptable because that key is generated in-memory by `init`, is not
  persisted, and rotates on process restart.
- Fallback init is a degraded recovery path, not a full substitute for a
  healthy `/sbin/init`.

## 12. Operational Notes

Recommended checks after changes:

- `cargo fmt -- --check`
- `cargo check`
- `cargo test`
- `cargo test -p init --bin init`

Implementation tests to add for this change:

- cache miss performs full attestation and persists a fingerprint entry
- cache hit skips JWT verification but still reads `CONTROL_ATTESTATION`
- proxy mode rejects cache entries whose `machine_id` differs from config
- direct mode can reuse a cached fingerprint and remembered attested
  `machine_id`
- rotated server certificate causes a cache miss and re-attestation
- cache file writes are atomic and tolerate concurrent client processes
