# fly-vault Design

Secure remote development VM on Fly.io. The key holder is the only entity that
can access the VM or its persistent data — not even the Fly account owner.

## 1. Threat Model

**Trusted**: the local client machine and its operator (the key holder).

**Untrusted**: everything else, including:

- The Fly.io platform (account owner, staff, infrastructure)
- Network intermediaries
- Other tenants on shared hardware

**Goals**:

| Property | Mechanism |
|---|---|
| Authenticity | Fly OIDC attestation of `image_digest` + machine config verification, channel-bound to TLS session |
| Confidentiality of data at rest | AES-256-XTS encrypted volume; key never leaves the client except over an attested channel |
| Confidentiality of data in transit | QUIC (TLS 1.3) |
| Integrity of the VM image | `image_digest` in OIDC token checked against a client-side allowlist |
| Integrity of machine config | Machine config fetched via Machines API using attested `machine_id` + `machine_version`; see §4.4 |
| Resistance to entrypoint tampering | Minimal Alpine image + machine config validation (no overrides, no injected files); see §3, §4.4 |

**Non-goals** (out of scope for v1):

- Protection against physical/hypervisor-level memory introspection (Fly does
  not offer confidential VMs today).
- Multi-user access control (single key holder model).
- Availability guarantees (Fly can always stop the VM).

## 2. Architecture Overview

```
┌──────────────┐         QUIC (TLS 1.3)        ┌──────────────────────────┐
│  Local Client │◄──────────────────────────────►│  Fly Machine             │
│              │   channel-bound attestation     │                          │
│  - allowlist │   key release                   │  /init (static, Rust)    │
│  - LUKS key  │   port forwarding               │    ├─ QUIC server        │
│  - rootfs    │   console (PTY)                 │    ├─ FUSE (AES-XTS)     │
│    tarball   │                                 │    ├─ loop mount          │
└──────────────┘                                 │    └─ PID ns + chroot    │
                                                 │         └─ systemd       │
                                                 │                          │
                                                 │  Fly Volume (/data)      │
                                                 │    └─ encrypted.img      │
                                                 └──────────────────────────┘
```

Four binaries, one Rust workspace:

| Binary | Runs on | Linking | Purpose |
|---|---|---|---|
| `fly-vault` | Developer laptop | Dynamic | Client: connect, attest, unlock, forward |
| `fly-vault-admin` | Operator laptop / CI | Dynamic | Deployment admin: manage tenant machines in `vault-tenants` via Machines API |
| `init` | Fly Machine | Static (`x86_64-unknown-linux-musl`) | VM-side: everything before and after unlock |
| `vault-proxy` | Fly Machine (proxy service) | Dynamic | UDP multiplexer: route clients to vault VMs by machine ID |

## 3. Image Hardening

The Docker image is intentionally minimal so that `image_digest` attestation
covers every executable byte. It uses Alpine as a base to provide filesystem
utilities (`mkfs.ext4`, `losetup`, `fuse3`) required by the setup flow.
However, `image_digest` alone is **not sufficient** — the Machines API allows
overriding entrypoint, injecting files (with executable permissions via the
`mode` field), and mounting volumes, all without changing the image digest.
Machine config verification (§4.4) closes this gap.

```dockerfile
FROM alpine:3.21
RUN apk add --no-cache e2fsprogs losetup fuse3
COPY init /init
ENTRYPOINT ["/init"]
```

**Defense in depth** (image hardening + config verification):

| Attack vector | Image hardening | Config verification (§4.4) |
|---|---|---|
| Modified init binary | `image_digest` changes → rejected | — |
| Entrypoint/cmd override | Only `/init` exists in image | `config.init.{exec,entrypoint,cmd}` must be empty |
| `[[files]]` injects executable at arbitrary path | — (files API supports `mode` with execute bit) | `config.files` must be empty |
| Volume mounted over critical path | Volumes are directories, not files | `config.mounts[].path` must be exactly `/data` |
| Environment variable injection | `init` only reads `PROVISION_TOKEN` (§6.2); all other env vars ignored | `config.env` must contain only `PROVISION_TOKEN` (or be empty) |
| Sidecar container with different image | — | `config.containers` must be empty |
| Process-level overrides | — | `config.processes` must be empty |
| Kernel arg injection | — | `config.init.kernel_args` must be empty |
| `LD_PRELOAD` / dynamic linker | `init` is statically linked (musl); no dynamic linker for the entrypoint | — |
| Mount at `/` | Fly disallows mounting at `/` | — |

The `image_digest` OIDC claim is a SHA-256 over the image manifest, covering
every layer — including the single layer that contains `/init`. Any change to
the binary changes the digest. But because the Machines API can modify runtime
behavior without touching the image, the client **must** also verify the
machine config as described in §4.4.

## 4. Attestation & Channel Binding

### 4.1 Fly OIDC Token

Fly Machines can request an OIDC JWT from the local API socket:

```
POST http://localhost/v1/tokens/oidc  (via /.fly/api unix socket)
Content-Type: application/json
{"aud": "<audience>"}
```

Relevant claims:

| Claim | Use |
|---|---|
| `iss` | `https://oidc.fly.io/<org>` — used to fetch signing keys |
| `aud` | Set to channel-binding value (see §4.2) |
| `image_digest` | `sha256:<hex>` — compared against client allowlist |
| `machine_id` | Machine identifier — used to fetch config from Machines API (§4.4) |
| `machine_version` | Config version — corresponds to `instance_id` in Machines API response (§4.4) |
| `app_name` | App name — used to construct Machines API URL |
| `exp` | Token expires in ≤15 minutes |

### 4.2 TLS Channel Binding

To prevent relay/MITM attacks, the OIDC token is bound to the QUIC TLS
session using **TLS Exported Keying Material** (RFC 5705 / RFC 9266):

1. Both sides independently derive the exporter value:
   ```
   tls_exporter = TLS-Exporter(
       label = "fly-vault-channel-binding",
       context = "",
       length = 32
   )
   ```
2. The VM uses `hex(tls_exporter)` as the `aud` when requesting the OIDC token.
3. The client verifies `aud == hex(local_tls_exporter)`.

**Why this works**: a MITM has two separate TLS sessions with different keying
material. The exporter value on the client↔MITM session differs from the
MITM↔VM session, so the `aud` won't match.

### 4.3 Verification Steps (Client)

The client performs all of the following checks on the received JWT:

1. Fetch the JWKS from `https://oidc.fly.io/<org>/.well-known/openid-configuration`
   (cached, refreshed on key rotation).
2. Verify the JWT signature against the JWKS.
3. Check `exp` is in the future, `nbf` is in the past.
4. Check `aud` equals the locally-computed TLS exporter hex.
5. Check `image_digest` is in the client's allowlist.

If any check fails, the client terminates the QUIC connection immediately.

### 4.4 Machine Config Verification

The `image_digest` only covers the Docker image contents. An attacker with Fly
account access can modify the machine config (entrypoint overrides, file
injection with executable permissions, sidecar containers, etc.) without
changing the image digest. To close this gap, the client verifies the full
machine config via the Machines API.

**Flow:**

1. Extract `app_name`, `machine_id`, and `machine_version` from the verified JWT.
2. Call the Machines API:
   ```
   GET https://api.machines.dev/v1/apps/{app_name}/machines/{machine_id}
   Authorization: Bearer <fly_api_token>
   ```
3. Verify `response.instance_id == machine_version` from the JWT (the OIDC
   `machine_version` claim corresponds to the Machines API `instance_id` field).
   This ensures the config returned is the exact config the machine booted with
   (no TOCTOU race).
4. Validate the `response.config` fields against the expected safe config.

**Required config checks:**

| Field (JSON path) | Required value | Rationale |
|---|---|---|
| `config.init.exec` | empty/null | No entrypoint override |
| `config.init.entrypoint` | empty/null | No entrypoint override |
| `config.init.cmd` | empty/null | No CMD override |
| `config.init.kernel_args` | empty/null | No kernel arg injection |
| `config.env` | empty/null, or contains only `PROVISION_TOKEN` | No env var injection (except the provisioning auth token; see §6.2) |
| `config.files` | empty/null | No file injection (API supports `mode` with exec bit) |
| `config.containers` | empty/null | No sidecar containers |
| `config.processes` | empty/null | No process-level overrides |
| `config.mounts` | exactly one entry with `path: "/data"` | Only the expected data volume |
| `config.volumes` | empty/null | No image-sourced volume injection |
| `config.statics` | empty/null | No static file serving |
| `config.guest.kernel_args` | empty/null | No kernel arg injection |

If any field deviates from the expected value, the client terminates the
connection without releasing the key.

**Authentication**: the client needs a Fly API token with read access to the
app. This token is stored in the client config. Even if the Fly account is
compromised, the Machines API (hosted by Fly at `api.machines.dev`) returns
the ground truth of the machine's actual config — the attacker cannot forge
the API response.

**Why `machine_version` / `instance_id` prevents TOCTOU**: the
`machine_version` in the OIDC token is set at machine boot time and reflects
the config version the machine was started with (exposed as `instance_id` in
the Machines API response). If an attacker modifies the config after boot, the
`instance_id` changes, but the running machine still has the old version. The
client checks that the API-returned `instance_id` matches the JWT's
`machine_version`, ensuring it is inspecting the config that is actually
running, not a modified-after-boot config.

## 5. FUSE Encryption Layer

Fly Machine kernels lack `dm-crypt`, so we implement userspace block-level
encryption via FUSE.

### 5.1 Stack

```
Fly Volume (ext4, managed by Fly)
  └── /data/encrypted.img           raw ciphertext, preallocated file
         │
         ▼  FUSE  (/dev/fuse)
      /tmp/fuse/decrypted.img        virtual file, plaintext view
         │
         ▼  loop device  (LOOP_SET_FD ioctl)
      /dev/loop0                     block device
         │
         ▼  mount -t ext4
      /mnt/root                      decrypted filesystem
```

### 5.2 AES-256-XTS Parameters

| Parameter | Value |
|---|---|
| Algorithm | AES-256-XTS (IEEE 1619) |
| Key size | 512 bits (two 256-bit keys: encryption + tweak) |
| Sector size | 4096 bytes (matches ext4 block size) |
| Tweak | 128-bit little-endian sector number (`byte_offset / 4096`) |
| IV generation | Standard XTS: `AES_K2(tweak)` then GF(2^128) multiply |

### 5.3 FUSE Implementation

The FUSE filesystem is embedded in the `init` binary using the `fuser` crate,
which provides a safe Rust interface over the FUSE kernel protocol. Since we
run as root, `fuser` mounts directly via the kernel `mount()` syscall with
`SessionACL::RootAndOwner` (`allow_root`), bypassing `fusermount3`.

A struct (e.g., `CryptoFs`) implements `fuser::Filesystem` with the following
handlers. The filesystem exposes a single virtual file (`decrypted.img`) under
the root directory:

**Inode layout**: inode 1 = root directory, inode 2 = `decrypted.img`.

| `fuser::Filesystem` method | Behavior |
|---|---|
| `lookup(parent=1, name="decrypted.img")` | Return inode 2 attrs |
| `getattr(ino=1)` | Return directory attrs |
| `getattr(ino=2)` | Return regular file attrs, size = `encrypted.img` size |
| `readdir(ino=1)` | Yield `.`, `..`, `decrypted.img` |
| `open(ino=2)` | Return file handle (page-cache enabled for loop device compatibility) |
| `read(ino=2, offset, size)` | Read aligned sector(s) from `encrypted.img`, decrypt with AES-256-XTS, return plaintext |
| `write(ino=2, offset, data)` | Encrypt with AES-256-XTS, write ciphertext to `encrypted.img`, `fdatasync` |
| `flush` / `fsync` | `fdatasync` on `encrypted.img` |
| `release` | Close file handle |

The FUSE file does **not** use `FOPEN_DIRECT_IO` because the Linux loop
driver requires page-cache-backed I/O from its backing file. The kernel
page cache holds decrypted blocks, which is acceptable given the threat
model (§1) — hypervisor-level memory access is already out of scope.

Sector-aligned I/O is enforced. Partial-sector reads/writes are handled by
reading the full sector, decrypting, modifying, re-encrypting, and writing
back (read-modify-write for unaligned writes).

The FUSE event loop runs on a dedicated thread (blocking I/O), while the QUIC
server runs on the tokio async runtime.

### 5.4 Key Handling

- The 512-bit AES-XTS key is generated once on the client and stored locally.
- The key is transmitted to the VM only after attestation succeeds, over the
  attested QUIC channel.
- On the VM, the key is held in memory only for the lifetime of the FUSE
  process. It is never written to disk.
- The key is stored in `mlock`'d memory and zeroized on process exit
  (`zeroize` crate with `Zeroizing<>` wrapper).
- After the first successful unlock, the server stores `SHA-256(key)` (32
  bytes) in shared state for verifying reconnecting clients (§7.4).
- The same `SHA-256(key)` is persisted to `/data/.provisioned` (the
  provisioned marker). On warm boot, the marker hash is verified against
  the incoming key before decryption proceeds, rejecting mismatched keys
  early (§6.2).

## 6. VM Init Lifecycle

The `init` binary runs as the user entrypoint (Fly's own init runs first to
set up networking, DNS, and the `/.fly/api` socket).

### 6.1 State Machine

```
         ┌─────────┐
   boot  │  START  │
         └────┬────┘
              │
              ▼
     ┌────────────────┐     QUIC connection + attestation
     │  WAITING FOR   │◄─── (client can connect at any time)
     │  CLIENT        │
     └────────┬───────┘
              │ client sends key
              ▼
     ┌────────────────┐
     │  SETTING UP    │  FUSE → loop → mount → (mkfs on cold) → chroot → systemd
     └────────┬───────┘
              │ setup complete
              ▼
     ┌────────────────┐
     │  READY         │  port forwarding + console
     └────────┬───────┘
              │ client disconnects
              ▼
     ┌────────────────┐
     │  IDLE          │  FUSE + systemd still running, awaiting reconnect
     └────────────────┘
              │ new client connects + re-attests + verifies key
              ▼
        (back to READY)
```

### 6.2 Cold Boot vs. Warm Boot

| Scenario | `.provisioned` marker? | Client sends | VM does |
|---|---|---|---|
| Cold (first-ever boot) | No | ProvisionToken + Key + rootfs tarball | Verify token, create image, FUSE, loop, mkfs, extract rootfs, chroot, systemd; write `SHA-256(key)` to marker |
| Warm (reboot) | Yes | Key | Verify `SHA-256(key)` matches marker; FUSE, loop, mount, chroot, systemd |
| Reprovision (reboot) | Yes | ProvisionToken + rootfs tarball + Key | Verify token + key hash; FUSE, loop, mount, extract new rootfs over existing filesystem, chroot, systemd (see §6.4) |
| Reconnect (same boot) | Yes (mounted) | Key | Verify key hash matches in-memory stored hash; grant access |

Detection: the VM checks for `/data/.provisioned` at startup. This file
contains the 32-byte `SHA-256(key)` written after the first successful
provisioning. Using a marker instead of `encrypted.img` existence avoids
a race: if the process crashes after creating the image but before
`mkfs.ext4` completes, the next boot correctly re-enters cold state.
On warm boot, the marker's key hash is verified against the incoming key
before attempting to mount — this rejects invalid keys early, before
touching the FUSE/loop/mount stack.

#### Provision Token

The `init` process reads the `PROVISION_TOKEN` environment variable at startup.
This token authenticates the client during initial rootfs provisioning (cold
boot) and prevents an unauthorized party from racing to provision a malicious
rootfs onto a fresh VM.

- **Required for cold boot**: The client must send a `ProvisionToken` control
  message with the correct token before `ProvisionRootfs` is accepted. If the
  token is missing or does not match, the VM rejects the provisioning attempt.
- **Not used for warm boot or reconnect**: The token is only checked during
  cold boot (state = `Cold`). Warm boots and reconnects do not require it.
- **Set via machine config**: The deployer sets `PROVISION_TOKEN` as an
  environment variable in the Fly Machine configuration. The client stores the
  same token in its vault config and presents it during cold boot.
- **Cleared after read**: The `init` process clears the environment variable
  from its own process environment after reading it, so it is not visible to
  child processes or the chrooted systemd.

### 6.3 Namespace & Chroot Setup

After the decrypted filesystem is mounted at `/mnt/root`:

1. Bind-mount essential pseudo-filesystems into `/mnt/root`:
   - `/proc`, `/sys`, `/dev`, `/dev/pts`, `/dev/shm`
   - `/tmp` (tmpfs)
2. `clone(CLONE_NEWPID)` to create a new PID namespace.
3. In the child process:
   - `chroot("/mnt/root")`
   - `chdir("/")`
   - `exec("/sbin/init")` (systemd), which becomes PID 1 in the new namespace.
4. The parent (`init`) continues running in the original namespace, handling
   QUIC connections and the FUSE event loop.

### 6.4 Reprovisioning

Reprovisioning replaces the rootfs on an existing encrypted volume without
destroying the encryption key or the underlying image. It targets the
`Locked` state (VM has rebooted, image exists but is not yet mounted).

**Use case**: replacing the rootfs environment (e.g., upgrading packages,
switching base OS) while preserving the encrypted volume and encryption key.

**Client command**:

```
fly-vault connect <vault-name> --reprovision
```

The `--reprovision` flag requires both `provision_token` and `rootfs` to be
set in the vault config.

**Flow**:

```
┌─────────┐                                    ┌─────────┐
│ Client  │                                    │   VM    │
│         │   1. RequestAttestation             │ (Locked)│
│         │──────────────────────────────────►  │         │
│         │   2. Attestation { Locked, jwt }    │         │
│         │  ◄──────────────────────────────────│         │
│         │                                    │         │
│         │   3. ProvisionToken { token }       │         │
│         │──────────────────────────────────►  │ verify  │
│         │                                    │ token   │
│         │   4. ProvisionRootfs { tarball }    │         │
│         │──────────────────────────────────►  │ buffer  │
│         │                                    │         │
│         │   5. ReleaseKey { key }             │         │
│         │──────────────────────────────────►  │ verify  │
│         │                                    │ key vs  │
│         │                                    │ marker  │
│         │                                    │         │
│         │       ┌────────────────────────┐    │         │
│         │       │  FUSE decrypt layer    │    │         │
│         │       │  Loop device attach    │    │         │
│         │       │  ext4 mount            │    │         │
│         │       │  Extract new rootfs    │◄───│         │
│         │       │  Bind mounts + chroot  │    │         │
│         │       │  Start systemd         │    │         │
│         │       └────────────────────────┘    │         │
│         │                                    │         │
│         │   6. SetupComplete                  │         │
│         │  ◄──────────────────────────────────│ (Ready) │
└─────────┘                                    └─────────┘
```

**Key differences from cold boot**:

| Aspect | Cold boot | Reprovision |
|---|---|---|
| VM state | `Cold` (no marker) | `Locked` (marker exists) |
| Encrypted image | Created + `mkfs.ext4` | Already exists, mounted as-is |
| Key verification | None (first use) | `SHA-256(key)` checked against `.provisioned` marker |
| Rootfs | Extracted into fresh filesystem | Extracted over existing filesystem contents |
| Marker written | Yes (new marker) | No (existing marker preserved) |

**Key differences from normal warm boot**:

| Aspect | Warm boot | Reprovision |
|---|---|---|
| Provision token | Not required | Required |
| Rootfs tarball | Not sent | Sent and extracted |
| Existing rootfs | Preserved | Overwritten |

**What happens to data**: the rootfs extraction overwrites files in the
mounted filesystem. Any user data stored within the rootfs is replaced.
The encrypted image and encryption key are unchanged — only the filesystem
contents are replaced.

**Security**: reprovisioning requires the provision token (same as cold
boot) to prevent unauthorized rootfs replacement. The token must match the
`PROVISION_TOKEN` environment variable configured on the machine. If
rootfs data is received without prior token verification, the server
rejects the operation with `"provision token required for re-provisioning"`.

## 7. QUIC Protocol

### 7.1 Connection Setup

- **Transport**: QUIC (RFC 9000) over UDP.
- **Library**: `quinn` (Rust).
- **TLS**: Self-signed certificate generated at VM startup. The client does
  not verify the certificate (attestation replaces certificate trust).
- **Port**: Configurable, default `8443`.
- **Client address**: Fly Machine's public IPv6, or via `fly proxy` over
  WireGuard for development.

### 7.2 Stream Types

Each QUIC stream begins with a 1-byte type tag:

| Tag | Type | Direction | Purpose |
|---|---|---|---|
| `0x01` | Control | Client → VM (bidi) | Attestation handshake, key release |
| `0x02` | Port Forward | Client → VM (bidi) | TCP forwarding |
| `0x03` | Console | Client → VM (bidi) | PTY forwarding |

Only one control stream exists per connection. Multiple port-forward and
console streams can be open concurrently.

### 7.3 Control Protocol

Messages on the control stream are length-prefixed:

```
┌──────────┬───────────────┬─────────────────────┐
│ type: u8 │ length: u32be │ payload: [u8; length]│
└──────────┴───────────────┴─────────────────────┘
```

**Message types:**

| Type | Direction | Payload | Description |
|---|---|---|---|
| `0x01` RequestAttestation | C→V | empty | Client requests OIDC token |
| `0x02` Attestation | V→C | `state: u8 ∥ jwt_len: u32be ∥ jwt: bytes` | VM state + OIDC JWT |
| `0x03` ReleaseKey | C→V | `key: [u8; 64]` | 512-bit AES-XTS key |
| `0x04` ProvisionRootfs | C→V | streaming tarball (gzip) | Rootfs for cold boot |
| `0x05` SetupComplete | V→C | empty | VM is ready |
| `0x06` Error | V→C | `utf8 message` | Error description |
| `0x07` ProvisionToken | C→V | `utf8 token` | Provision auth token (cold boot only; see §6.2) |

**VM state** (in `Attestation` message):

| Value | Meaning | Client action |
|---|---|---|
| `0x00` | Cold — no encrypted image | Send `ReleaseKey` + `ProvisionRootfs` |
| `0x01` | Locked — image exists, not mounted | Send `ReleaseKey` |
| `0x02` | Ready — already unlocked | Send `ReleaseKey` (verified against stored hash) |

### 7.4 Per-Connection Authentication

Every QUIC connection must complete key verification on the control stream
before the server accepts port-forward or console streams. This ensures that
merely connecting to the QUIC endpoint is insufficient — the client must prove
possession of the encryption key.

**Mechanism:**

1. After the first successful setup (Cold or Locked → Ready), the server
   computes `SHA-256(key)` and stores the 32-byte hash in memory.
2. On each new connection, the server tracks a per-connection `authenticated`
   flag, initially `false`.
3. The control stream handler verifies the key:
   - **Cold/Locked**: the key is used for setup. On success, the hash is stored
     and the connection is marked authenticated.
   - **Ready**: the incoming key is hashed and compared against the stored hash.
     On match, the connection is marked authenticated. On mismatch, the server
     sends `Error("key verification failed")` and the connection remains
     unauthenticated.
4. Any `Port Forward` or `Console` stream opened before authentication is
   immediately reset by the server.
5. The control stream returns after setup/verification completes, allowing the
   connection's stream accept loop to process subsequent port-forward and
   console streams.

**Why SHA-256 rather than raw key comparison**: the hash avoids keeping an
extra copy of the raw 512-bit key in shared server state. The key itself
remains in memory only within the FUSE encryption layer.

### 7.5 Port Forward Protocol

After the 1-byte stream type tag (`0x02`), the stream header is:

```
┌────────────────────┬──────────────┐
│ target_addr: utf8  │ NUL (0x00)   │
└────────────────────┴──────────────┘
```

`target_addr` is `host:port` (e.g., `127.0.0.1:8080`). After the header,
the stream carries raw TCP payload bytes in both directions. The VM opens a
TCP connection to the target inside the PID namespace and bridges it to the
QUIC stream.

The client listens on a local TCP port and, for each incoming connection,
opens a new QUIC stream. Configuration example:

```
fly-vault connect --forward 8080:localhost:8080 --forward 5432:localhost:5432
```

### 7.6 Console Protocol

After the 1-byte stream type tag (`0x03`), the console stream uses a simple
framing layer to multiplex data and control messages:

```
┌──────────┬───────────────┬─────────────────────┐
│ type: u8 │ length: u32be │ payload: [u8; length]│
└──────────┴───────────────┴─────────────────────┘
```

| Type | Direction | Payload |
|---|---|---|
| `0x00` Data | Both | Raw PTY bytes |
| `0x01` Resize | C→V | `rows: u16be ∥ cols: u16be` |
| `0x02` Exit | V→C | `exit_code: u32be` |

The VM side:

1. Allocates a PTY pair (`openpty`).
2. Forks into the PID namespace + chroot.
3. In the child: `setsid`, sets the PTY as controlling terminal, execs
   `/bin/bash` (or a configured shell).
4. Forwards PTY master ↔ QUIC stream.
5. On `Resize`, calls `ioctl(TIOCSWINSZ)` on the PTY master.

Multiple concurrent console sessions are supported (each is a separate QUIC
stream + PTY pair).

## 8. Client Design

### 8.1 Configuration

```toml
# ~/.config/fly-vault/config.toml

[vault.my-dev]
# Fly Machine addressing
address = "[fdaa:x:x::x]:8443"     # or "my-app.fly.dev:8443"
org = "my-org"                       # for OIDC issuer URL
app = "my-dev-vault"                 # Fly app name (for Machines API)

# Optional: when connecting via vault-proxy, prepend this machine ID
# to each outgoing UDP datagram as described in §12.3.
machine_id = "e2865d95f47d38"

# Fly API token (read-only access to the app, for config verification)
# Can also be set via FLY_API_TOKEN env var
fly_api_token = "fo1_..."

# Attestation
allowed_digests = [
    "sha256:abc123...",
    "sha256:def456...",
]

# Forwarding defaults
forward = [
    "8080:localhost:8080",
    "5432:localhost:5432",
]

# Provision token (must match PROVISION_TOKEN env var on machine, used on cold boot)
provision_token = "secret-token-here"

# Path to rootfs tarball (used on cold boot)
rootfs = "~/.config/fly-vault/rootfs/dev-env.tar.gz"
```

### 8.2 Key Storage

The 512-bit AES-XTS key is stored in a file:

```
~/.config/fly-vault/keys/<vault-name>.key
```

File permissions: `0600`. On first use, if the key file does not exist, the
client generates a cryptographically random 512-bit key and writes it.

### 8.3 Client Command Interface

```
fly-vault connect <vault-name>                # connect with defaults from config
fly-vault connect <vault-name> --forward 3000:localhost:3000
fly-vault connect <vault-name> --reprovision  # replace rootfs on locked vault (§6.4)
fly-vault keygen <vault-name>                 # generate a new key (first-time setup)
fly-vault build                               # build the init image, print digest
fly-vault allow <vault-name> <digest>         # add a digest to the allowlist
```

### 8.4 Connection Flow

```
 1.  Load config + key for the named vault
 2.  Connect QUIC to the VM address (skip cert verification)
 3.  Open control stream
 4.  Send RequestAttestation
 5.  Receive Attestation { state, jwt }
 6.  Verify JWT (§4.3):
       - signature, exp/nbf, aud == local TLS exporter
       - image_digest in allowlist
 7.  Verify machine config (§4.4):
       - extract app_name, machine_id, machine_version from JWT
       - GET https://api.machines.dev/v1/apps/{app_name}/machines/{machine_id}
       - check response.instance_id == machine_version
       - validate config fields (no overrides, no files, no containers, etc.)
 8.  If state == Cold:
       Send ProvisionToken { token }
       Send ReleaseKey { key }
       Send ProvisionRootfs { rootfs tarball }
       Await SetupComplete
     Else if state == Locked && --reprovision:
       Send ProvisionToken { token }
       Send ProvisionRootfs { rootfs tarball }
       Send ReleaseKey { key }
       Await SetupComplete
     Else if state == Locked:
       Send ReleaseKey { key }
       Await SetupComplete
     Else (Ready):
       Send ReleaseKey { key }
       Await SetupComplete (key verified against stored hash)
 9.  Open console stream → attach to local terminal (stdin/stdout raw mode)
10.  For each --forward rule, listen on local TCP port
11.  Multiplex port-forward streams as connections arrive
12.  On disconnect (ctrl-c / network loss): close QUIC connection, exit
```

## 9. Image Build & Deployment

### 9.1 Build

```bash
# Build the static init binary
cargo zigbuild --release --target x86_64-unknown-linux-musl -p init

# Build the Docker image
docker build -t registry.fly.io/<app>/init:latest .

# Push and record the digest
docker push registry.fly.io/<app>/init:latest
# → sha256:abcdef...

# Add to client allowlist
fly-vault allow my-dev sha256:abcdef...
```

### 9.2 Fly Machine Configuration

```toml
# fly.toml
app = "my-dev-vault"
primary_region = "ord"

[build]
  dockerfile = "Dockerfile"

[[vm]]
  size = "shared-cpu-2x"
  memory = 2048

[mounts]
  source = "vault_data"
  destination = "/data"

[[services]]
  internal_port = 8443
  protocol = "udp"
  [[services.ports]]
    port = 8443
```

### 9.3 Image Update Workflow

Single-vault (manual) flow:

1. Modify Rust code, rebuild init binary.
2. Build and push new Docker image → get new `image_digest`.
3. `fly-vault allow my-dev sha256:<new-digest>` on the client.
4. Replace the target machine image.
5. Next `fly-vault connect` attests the new digest.
6. Optionally remove old digests from the allowlist.

Multi-tenant (`vault-tenants`) flow:

1. Build and push the new image.
2. Run `fly-vault-admin tenant update-image --all-tenants --image <image-ref>`.
3. The admin CLI performs canary + rolling update + automatic rollback on crash
   as defined in §13.6.

The encrypted volume is untouched across image updates — only the init binary
changes. The rootfs inside the encrypted volume persists.

## 10. Security Analysis

### 10.1 Attestation Guarantees

| Attack | Prevented by |
|---|---|
| Fly serves a modified image | `image_digest` won't be in the allowlist |
| MITM relays attestation from a real VM | TLS channel binding (`aud` mismatch) |
| Replay of old OIDC token | `aud` contains session-specific exporter value; token `exp` ≤15 min |
| Entrypoint override to volume-hosted binary | Config verification: `config.init.exec` must be empty (§4.4) |
| Executable file injected via `[[files]]` API | Config verification: `config.files` must be empty (§4.4) |
| Sidecar container with attacker-controlled image | Config verification: `config.containers` must be empty (§4.4) |
| Env var injection (`LD_PRELOAD`, app-specific) | Config verification: `config.env` must contain only `PROVISION_TOKEN` or be empty (§4.4); init is static and ignores all other env vars |
| Volume mounted at unexpected path | Config verification: only `/data` mount allowed (§4.4) |
| Process-level entrypoint/env overrides | Config verification: `config.processes` must be empty (§4.4) |
| Kernel arg manipulation | Config verification: `kernel_args` must be empty (§4.4) |
| Config changed after boot (TOCTOU) | `machine_version` in JWT pinned at boot; client checks API `instance_id` matches |
| DNS hijack to MITM OIDC verification | Client fetches JWKS directly from `oidc.fly.io` over HTTPS (public CA trust) |
| Unauthorized access to console/port-forward on running VM | Per-connection key verification (§7.4): client must present correct encryption key before non-control streams are accepted |
| Reconnect with wrong key to access already-unlocked VM | Key hash comparison: server stores `SHA-256(key)` on first unlock and verifies all subsequent key presentations against it (§7.4) |
| Warm boot with wrong key to mount encrypted volume | On-disk key hash: `/data/.provisioned` contains `SHA-256(key)` from provisioning; mismatch is rejected before FUSE/loop/mount (§6.2) |
| Unauthorized rootfs replacement on locked VM | Provision token required for reprovisioning; rootfs data without prior token verification is rejected (§6.4) |
| Reprovision with wrong encryption key | Key hash checked against `.provisioned` marker before mounting; mismatch rejected (§6.2, §6.4) |

### 10.2 Data Protection

| Attack | Prevented by |
|---|---|
| Fly reads the volume directly | Volume contains `encrypted.img`, encrypted with AES-256-XTS; key is never on Fly infrastructure |
| Fly snapshots VM memory to extract key | Out-of-scope (requires confidential computing); noted as non-goal |
| Key extracted from QUIC traffic | TLS 1.3 forward secrecy |
| Key leaks via swap / core dump | `mlock` + no swap in Fly VMs; key held in `Zeroizing<>` wrapper |

### 10.3 Residual Risks

- **Hypervisor-level memory access**: Fly (or the underlying cloud provider)
  could theoretically inspect VM memory and extract the AES-XTS key. This is
  inherent to non-confidential VMs and is explicitly out of scope.
- **Fly stops the VM**: Fly can stop or destroy the Machine at any time. Data
  on the encrypted volume is safe (encrypted at rest), but availability is not
  guaranteed.
- **Side-channel attacks**: Timing or cache side-channels against AES-XTS in
  userspace FUSE. Mitigated by using constant-time AES implementations
  (hardware AES-NI via the `aes` crate).

## 11. Project Structure

```
fly-vault/
├── Cargo.toml                  # workspace root
├── DESIGN.md
├── Dockerfile
├── fly.toml
└── crates/
    ├── protocol/               # shared types & serialization
    │   ├── Cargo.toml
    │   └── src/
    │       └── lib.rs          # message types, stream tags, serialization
    ├── crypto/                 # AES-XTS implementation + key types
    │   ├── Cargo.toml
    │   └── src/
    │       └── lib.rs
    ├── init/                   # VM-side binary (static, musl)
    │   ├── Cargo.toml
    │   └── src/
    │       ├── main.rs         # entrypoint, state machine
    │       ├── quic.rs         # QUIC server, stream dispatch
    │       ├── attest.rs       # OIDC token fetching
    │       ├── fuse.rs         # fuser::Filesystem impl, AES-XTS layer
    │       ├── setup.rs        # loop mount, mkfs, chroot, PID namespace
    │       └── forward.rs      # port forwarding + console PTY bridge
    ├── client/                 # local client binary
    │   ├── Cargo.toml
    │   └── src/
    │       ├── main.rs         # CLI, config loading
    │       ├── quic.rs         # QUIC client, stream dispatch
    │       ├── attest.rs       # JWT verification, JWKS fetching
    │       ├── config_verify.rs # Machines API config validation (§4.4)
    │       ├── console.rs      # local terminal raw mode, PTY bridge
    │       └── forward.rs      # local TCP listener, stream bridging
    ├── admin/                  # deployment admin CLI (`fly-vault-admin`, §13)
    │   ├── Cargo.toml
    │   └── src/
    │       ├── main.rs         # CLI entrypoint + subcommand dispatch
    │       ├── machines.rs     # Machines API client wrappers
    │       ├── template.rs     # tenant template TOML parse + validation
    │       ├── tenant.rs       # create/delete/list orchestration
    │       └── rollout.rs      # canary, rolling update, rollback logic
    └── proxy/                  # UDP multiplexer service (§12)
        ├── Cargo.toml
        └── src/
            ├── main.rs         # CLI args, env vars, tracing, task orchestration
            ├── machines.rs     # Machines API poller: machine_id → IP map
            ├── proxy.rs        # UDP proxy loop: header parse, session lookup, forward
            └── session.rs      # Per-session backend socket, relay task, idle cleanup
```

### 11.1 Key Dependencies

| Crate | Used in | Purpose |
|---|---|---|
| `quinn` | init, client | QUIC implementation |
| `rustls` | init, client | TLS 1.3 (via quinn) |
| `rcgen` | init | Self-signed cert generation at startup |
| `fuser` | init | FUSE filesystem interface (Rust `fuser::Filesystem` trait) |
| `aes` | crypto | AES-256 block cipher (AES-NI accelerated) |
| `zeroize` | crypto, init | Secure memory zeroing |
| `nix` | init | Linux syscalls (`mount`, `chroot`, `clone`, `ioctl`) |
| `tokio` | init, client | Async runtime |
| `jsonwebtoken` | client | JWT parsing and verification |
| `reqwest` | client, proxy, admin | HTTPS client for JWKS fetching, Machines API config verification, tenant machine operations |
| `clap` | client, proxy, admin | Command-line parsing |
| `toml` | admin | Parse tenant machine template files |

## 12. UDP Proxy (`vault-proxy`)

### 12.1 Purpose

The `vault-proxy` service provides a single UDP entry point that multiplexes
traffic from multiple clients to multiple vault VMs. Clients prepend a
machine-ID header to each UDP packet; the proxy strips the header, resolves the
machine ID to a backend IP via the Machines API, and forwards the raw QUIC
payload. Return traffic from vaults is forwarded back to clients as-is.

The proxy operates entirely at the UDP layer — it does not terminate QUIC, read
TLS, or understand the vault protocol. End-to-end encryption between client and
vault is preserved.

### 12.2 Architecture

```
                ┌──────────┐
                │ Client A │──┐
                └──────────┘  │  [machine_id header + QUIC]
                ┌──────────┐  │
                │ Client B │──┼──►┌─────────────┐     UDP      ┌──────────┐
                └──────────┘  │   │ vault-proxy │────────────►│ Vault VM │
                ┌──────────┐  │   │             │              │ (init)   │
                │ Client C │──┘   │  - header   │     UDP      ├──────────┤
                └──────────┘      │    parse    │────────────►│ Vault VM │
                                  │  - session  │              │ (init)   │
                                  │    mgmt     │              └──────────┘
                                  │  - machine  │
                                  │    map poll │
                                  └─────────────┘
```

### 12.3 Packet Format (Client → Proxy)

Clients prepend a machine-ID header to every UDP packet sent to the proxy:

```
┌────────────────────────────────┬───────────────────────┬──────────────────┐
│ machine_id_len: u64 LE (8 B)  │ machine_id: UTF-8     │ QUIC UDP payload │
└────────────────────────────────┴───────────────────────┴──────────────────┘
```

The proxy strips the header and forwards only the QUIC payload to the backend
vault. Return packets (vault → client) are forwarded as-is with no header.

### 12.4 Machine Map

The proxy periodically polls the Machines API to maintain a mapping of machine
IDs to private IPs:

```
GET https://api.machines.dev/v1/apps/{FLY_APP}/machines
Authorization: Bearer {FLY_API_TOKEN}
```

Only machines with `state == "started"` and a valid `private_ip` are included.
The map is refreshed every `--refresh-interval-secs` (default 15s). On fetch
failure, the previous map is retained until the next successful refresh.

### 12.5 Session Management

Sessions are keyed by client `SocketAddr` (IP + port). Each QUIC client uses a
single UDP source port, so this provides a stable session identity.

Each session consists of:

- A per-session backend `UdpSocket` bound to `[::]:0` and connected to the
  target vault's `IP:backend_port`. Using connected sockets ensures return
  packets from the vault route to the correct session.
- A relay task that reads from the backend socket and sends to the client via
  the shared frontend socket (no header added).
- An atomic `last_activity` timestamp updated on every forwarded packet.

If a client's target backend changes (e.g., reconnecting to a different vault),
the old session is torn down and a new one is created.

**Idle cleanup**: a background sweeper runs every 30 seconds and removes
sessions whose `last_activity` exceeds `--session-timeout-secs` (default 120s,
matching the QUIC `max_idle_timeout` in init and client).

### 12.6 Configuration

| Source | Name | Default | Description |
|---|---|---|---|
| CLI | `--port` | 8443 | Frontend UDP listen port |
| CLI | `--backend-port` | 8443 | Vault machine QUIC port |
| CLI | `--refresh-interval-secs` | 15 | Machines API poll interval |
| CLI | `--session-timeout-secs` | 120 | Idle session expiry |
| Env | `FLY_APP` | (required) | App name for Machines API |
| Env | `FLY_API_TOKEN` | (required) | Bearer token for Machines API |
| Env | `FLY_ORG` | (optional) | Logged at startup |

### 12.7 Concurrency Model

The proxy uses three concurrent `tokio::select!` tasks:

1. **`poll_machines`** — periodic Machines API refresh loop.
2. **`run_proxy`** — main `recv_from` packet loop: parse header, look up
   backend, get-or-create session, forward payload.
3. **`cleanup_sessions`** — idle session sweeper (every 30s).

Session state uses `tokio::sync::RwLock<HashMap>` — reads (every packet)
dominate, writes (new session, cleanup) are rare.

### 12.8 Security Considerations

- The proxy does **not** terminate QUIC or TLS. All attestation, channel
  binding, and key verification occur end-to-end between the client and vault
  VM. The proxy is a transparent UDP forwarder.
- The proxy requires `FLY_API_TOKEN` with read access to the app's machines
  list. This token is used only for the Machines API poll and is not forwarded.
- Machine IDs in packet headers are validated against the live machine map;
  packets targeting unknown machines are silently dropped.

## 13. Deployment Management CLI (`fly-vault-admin`)

### 13.1 Scope and Deployment Topology

The deployment layout has two Fly apps:

- `vault-proxy`: runs the UDP proxy service (`vault-proxy` binary).
- `vault-tenants`: runs all tenant machines (each machine runs the `init`
  container).

`fly-vault-admin` manages only `vault-tenants` machines. It does **not** create,
update, restart, or delete resources in `vault-proxy`.

### 13.2 Tenant Model and Metadata

- Tenant identity is `tenant_id` (string slug).
- A tenant can own multiple machines in `vault-tenants`.
- Tenant ownership is represented in machine metadata, not in machine names.

Required metadata keys on every managed tenant machine:

| Key | Value |
|---|---|
| `fly_vault.tenant_id` | `<tenant_id>` |
| `fly_vault.managed_by` | `fly-vault-admin` |
| `fly_vault.template` | `<template-name-or-version>` |

Additional metadata keys may be present, but these keys are reserved and
authoritative for tenant discovery and filtering.

### 13.3 Template-Driven Tenant Creation

Tenant creation is driven by a template TOML file (checked into infra config).
The template defines machine config defaults, service/mount layout, and machine
count. The CLI injects per-tenant values (`tenant_id`, machine index, names,
metadata) at render time.

Example template shape:

```toml
version = 1
app = "vault-tenants"
machine_count = 3

[machine]
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

Creation flow (`tenant create`):

1. Load and validate template (`app` must be `vault-tenants`).
2. Render template for `tenant_id` and each machine index.
3. Enforce metadata keys in §13.2 (override conflicting values).
4. `POST /v1/apps/{app}/machines` for each machine spec.
5. Wait until each machine reaches `started` (or fail atomically and clean up
   machines created in this run).

### 13.4 Command Surface

```text
fly-vault-admin tenant create <tenant_id> --template <path> [--dry-run]
fly-vault-admin tenant delete <tenant_id> --yes
fly-vault-admin tenant list [--tenant <tenant_id>] [--wide] [--json]
fly-vault-admin tenant update-image --image <ref> (--tenant <id>... | --all-tenants)
                                    [--concurrency <n>] [--canary <n>] [--soak-secs <n>]
```

### 13.5 Tenant Listing and Operator UX

`tenant list` uses `GET /v1/apps/{app}/machines`, groups by
`metadata.fly_vault.tenant_id`, and presents:

- `tenant_id`
- machine count (`total/started/stopped`)
- regions in use
- image digest summary (single digest vs drift)
- last update time (max `updated_at` across tenant machines)

`--wide` includes machine IDs, per-machine state, volume IDs, and raw image
refs. `--json` is stable for automation.

### 13.6 Graceful Image Rollout Across Tenants

`tenant update-image` performs a canary-first rolling update with automatic
rollback on crash.

Preflight:

1. Resolve target machines from tenant selectors.
2. Snapshot each target machine's `id`, `instance_id`, `config`, and current
   image ref/digest.
3. Validate that each target is managed (`fly_vault.managed_by=fly-vault-admin`).
4. Acquire per-machine lease before update to avoid concurrent writers.

Canary stage:

1. Select `--canary N` machines (default `1`), preferring distinct tenants.
2. Update each canary serially:
   - `POST /v1/apps/{app}/machines/{id}` with full config and new image.
   - Pass `current_version=<instance_id>` for optimistic concurrency.
   - Wait for `started`, then observe for `--soak-secs`.
3. If any canary crashes/fails health during soak, trigger rollback (§13.6
   rollback) and exit non-zero.

Rolling stage:

- Scheduler constraints:
  - Global concurrency: `--concurrency`.
  - Per-tenant concurrency: `1` machine max in-flight per tenant.
- For each machine:
  1. Cordon machine (`/cordon`).
  2. Update image via Machines API update endpoint.
  3. Wait for `started` and passing checks (if checks are configured).
  4. Enforce soak window; mark failed if machine leaves `started`.
  5. Uncordon (`/uncordon`).

Crash/failure conditions:

- Update request rejected (version conflict or API error).
- Machine fails to reach `started` within timeout.
- Machine exits `started` during soak window.
- Health checks remain failing after timeout (when checks exist).

Rollback (automatic):

1. Stop new rollout work immediately.
2. For every machine successfully updated in this run, restore previous image
   from the preflight snapshot.
3. Apply rollback with the same safety gates (`current_version`, wait, soak).
4. Emit machine-level rollback status; non-zero exit if any rollback fails.

### 13.7 Safe Tenant Deletion

`tenant delete <tenant_id>` is intentionally destructive and therefore requires
explicit confirmation (`--yes`).

Deletion flow:

1. Discover all machines by `metadata.fly_vault.tenant_id=<tenant_id>`.
2. Print a deletion plan (machine IDs + attached volume IDs).
3. Cordon and stop machines gracefully.
4. `DELETE /v1/apps/{app}/machines/{id}` for each machine.
5. Delete attached volumes discovered from each machine's `config.mounts`.
6. Verify no tenant machines remain; return non-zero if residual resources
   exist.

This default behavior is "safe and complete": refuse accidental deletion
without confirmation, and delete both tenant machines and their volumes.

## 14. Reference Documentation

Detailed third-party API and protocol references are in `./docs/`:

| Document | Relevant sections |
|---|---|
| [docs/fly-oidc.md](docs/fly-oidc.md) | §4.1, §4.2, §4.3 — OIDC token request, JWT claims, JWKS verification |
| [docs/fly-machines-api.md](docs/fly-machines-api.md) | §4.4 — Machine config structure, `instance_id`, security-critical fields |
| [docs/aes-xts.md](docs/aes-xts.md) | §5.2 — AES-256-XTS algorithm, tweak computation, pseudocode |
| [docs/tls-exporter.md](docs/tls-exporter.md) | §4.2 — TLS Exported Keying Material, channel binding, rustls API |
| [docs/fuse-protocol.md](docs/fuse-protocol.md) | §5.3 — FUSE kernel protocol, opcodes, message format |
| [docs/fuser.md](docs/fuser.md) | §5.3 — `fuser` crate docs |
| [docs/loop-device.md](docs/loop-device.md) | §5.1, §6 — Loop device setup, ioctls, Rust implementation |
| [docs/linux-namespaces.md](docs/linux-namespaces.md) | §6.3 — PID namespaces, chroot, bind mounts, nix crate API |
