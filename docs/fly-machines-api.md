# Fly.io Machines API Reference

> Source: <https://fly.io/docs/machines/api/machines-resource/>

---

## Base URL

```
https://api.machines.dev
```

The base URL is provided by the environment variable `FLY_API_HOSTNAME`.

## Authentication

All requests require a Bearer token in the `Authorization` header:

```
Authorization: Bearer <FLY_API_TOKEN>
```

Content type for request bodies is `application/json`.

---

## Endpoints Overview

| Method | Path | Description |
|--------|------|-------------|
| GET | `/v1/apps/{app_name}/machines` | List all machines |
| POST | `/v1/apps/{app_name}/machines` | Create a machine |
| GET | `/v1/apps/{app_name}/machines/{machine_id}` | Get machine details |
| POST | `/v1/apps/{app_name}/machines/{machine_id}` | Update a machine |
| DELETE | `/v1/apps/{app_name}/machines/{machine_id}` | Delete a machine |
| POST | `/v1/apps/{app_name}/machines/{machine_id}/start` | Start a machine |
| POST | `/v1/apps/{app_name}/machines/{machine_id}/stop` | Stop a machine |
| POST | `/v1/apps/{app_name}/machines/{machine_id}/suspend` | Suspend a machine |
| GET | `/v1/apps/{app_name}/machines/{machine_id}/wait` | Wait for a state |
| POST | `/v1/apps/{app_name}/machines/{machine_id}/lease` | Create a lease |
| GET | `/v1/apps/{app_name}/machines/{machine_id}/lease` | Get lease details |
| DELETE | `/v1/apps/{app_name}/machines/{machine_id}/lease` | Release a lease |
| POST | `/v1/apps/{app_name}/machines/{machine_id}/cordon` | Cordon machine |
| POST | `/v1/apps/{app_name}/machines/{machine_id}/uncordon` | Uncordon machine |
| GET | `/v1/apps/{app_name}/machines/{machine_id}/metadata` | Get all metadata |
| POST | `/v1/apps/{app_name}/machines/{machine_id}/metadata/{key}` | Set metadata key |
| DELETE | `/v1/apps/{app_name}/machines/{machine_id}/metadata/{key}` | Delete metadata key |

---

## GET /v1/apps/{app_name}/machines/{machine_id}

Retrieve a single machine by its ID.

### Path Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `app_name` | string | The Fly app name |
| `machine_id` | string | The machine identifier |

### Response

HTTP 200 with a full machine object (see Machine Response Object below).

### Example Response

```json
{
  "id": "a5c5de9ce64ca12",
  "name": "aged-wind-2649",
  "state": "started",
  "region": "ord",
  "image_ref": {
    "registry": "registry-1.docker.io",
    "repository": "rebelthor/sleep",
    "tag": "latest",
    "digest": "sha256:597c3e12f830132be2aa69b4c0deccb0657ea4253e6d59c6f38e41e9f69a0add"
  },
  "instance_id": "1RREBN3T5K95DK9IVP4XHTTPEY2",
  "private_ip": "fdaa:0:18:a7b:196:e274:9ce1:2",
  "created_at": "2023-10-31T02:30:10Z",
  "updated_at": "2023-10-31T02:35:26Z",
  "config": {},
  "events": [
    {
      "type": "start",
      "status": "started",
      "source": "flyd",
      "timestamp": 1698719726615
    }
  ]
}
```

---

## Machine Response Object

Top-level fields returned for every machine:

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Stable unique machine identifier. |
| `name` | string | Unique machine name. Auto-generated if omitted at creation. |
| `state` | string | Current machine state: `created`, `started`, `stopped`, `suspended`, `destroyed`. |
| `region` | string | Geographic region code (e.g., `ord`, `iad`, `lhr`). |
| `instance_id` | string | Identifier for the current running/ready version. Changes with every update request. |
| `private_ip` | string | 6PN IPv6 address for private network access. |
| `config` | object | Full machine configuration (see below). |
| `image_ref` | object | Container image details (see below). |
| `checks` | object | Health check status information. |
| `events` | array | Historical log of machine events. |
| `nonce` | string | Lease nonce, present if the machine is currently leased. Also returned on create if `lease_ttl` was provided. |
| `created_at` | datetime | Creation timestamp (ISO 8601). |
| `updated_at` | datetime | Last modification timestamp (ISO 8601). |

### Private Network Hostname

Machines are reachable on the private network at:

```
{machine_id}.vm.{app_name}.internal
```

Machines are closed to the public internet by default.

---

## Machine Versioning (instance_id)

The `instance_id` field is the primary versioning mechanism for machines:

- Every update request (POST to `/v1/apps/{app_name}/machines/{machine_id}`) potentially changes the `instance_id`.
- The `instance_id` identifies the current running/ready version of the machine.
- When waiting for a `stopped` state via the `/wait` endpoint, the `instance_id` parameter is required to target a specific version.
- When updating a machine, the optional `current_version` request parameter accepts the latest `instance_id` value.

There is no separate top-level `version` field on machine response objects. The `version` field appears only in lease responses.

---

## image_ref Object

| Field | Type | Description |
|-------|------|-------------|
| `registry` | string | Registry domain (e.g., `registry-1.docker.io`). |
| `repository` | string | Image repository path (e.g., `library/ubuntu`). |
| `tag` | string | Image tag (e.g., `latest`). |
| `digest` | string | SHA256 content digest. |
| `labels` | object | Image metadata labels (key-value string pairs). |

---

## config Object

The `config` object contains the full machine configuration. You must specify the entire config when updating a machine; partial updates are not supported.

### config.image (required)

```
image: string
```

Container image reference. Example: `"registry-1.docker.io/library/ubuntu:latest"`.

This is the only required field in `config`.

### config.init

Process initialization configuration.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `exec` | [string] | - | Command arguments to execute on boot. |
| `entrypoint` | [string] | - | Override the image ENTRYPOINT. |
| `cmd` | [string] | - | Override the image CMD. |
| `tty` | bool | `false` | Allocate a pseudo-TTY. |
| `swap_size_mb` | int | - | Swap space allocation in MB. |
| `kernel_args` | [string] | - | Kernel arguments passed at boot. |

### config.env

```
env: { "KEY": "VALUE", ... }
```

Key-value map of environment variables injected into the machine.

### config.files

Array of files to write into the machine filesystem.

| Field | Type | Description |
|-------|------|-------------|
| `guest_path` | string (required) | Absolute path where the file will be written inside the machine. |
| `raw_value` | string | Base64-encoded file content. |
| `secret_name` | string | Reference to a Fly secret whose value becomes the file content. |

Use either `raw_value` or `secret_name` for each file entry, not both.

### config.mounts

Array of persistent volume attachments.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `volume` | string (required) | - | Volume ID. |
| `path` | string (required) | - | Absolute mount path inside the machine. |
| `name` | string | - | Volume name. |
| `encrypted` | bool | `true` | Whether the volume is encrypted. |
| `extend_threshold_percent` | int | - | Disk usage percentage that triggers auto-extend. |
| `add_size_gb` | int | - | Size increment in GB when auto-extending. |
| `size_gb_limit` | int | - | Maximum total size in GB for auto-extension. |

### config.processes

Optional array of objects defining multiple processes to run within a single machine.

| Field | Type | Description |
|-------|------|-------------|
| `entrypoint` | [string] | Process entrypoint command. |
| `cmd` | [string] | Command arguments. |
| `env` | object | Process-specific environment variables. |
| `env_from` | array | Environment variable references (Kubernetes-style). |
| `exec` | [string] | Startup command. |
| `user` | string | User to run the process as. |
| `ignore_app_secrets` | bool | If true, do not inject app-level secrets. Default: `false`. |
| `secrets` | [string] | Secret names to inject into this process. |

### config.statics

Array of static file serving configurations.

| Field | Type | Description |
|-------|------|-------------|
| `guest_path` | string (required) | Path inside the machine where static files reside. |
| `url_prefix` | string (required) | URL prefix to serve these files under. |
| `tigris_bucket` | string | Tigris object storage bucket name. |
| `index_document` | string | Default index file name. |

### config.guest

Machine resource allocation.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `cpu_kind` | string | - | CPU type: `"shared"` or `"performance"`. |
| `cpus` | int | `1` | Number of CPU cores. |
| `memory_mb` | int | `256` | RAM in megabytes (must be a multiple of 256). |
| `gpu_kind` | string | - | GPU type, if applicable. |
| `gpus` | int | `1` | Number of GPUs. |
| `kernel_args` | [string] | - | Kernel arguments. |
| `host_dedication_id` | string | - | Dedicated host group ID (beta). |
| `persist_rootfs` | string | - | Root filesystem persistence mode: `"never"`, `"restart"`, `"always"`. |

Alternatively, use the top-level `config.size` field with a named size preset (e.g., `"shared-cpu-2x"`, `"performance-2x"`). The `size` and `guest` fields are mutually exclusive.

### config.dns

DNS configuration for the machine.

| Field | Type | Description |
|-------|------|-------------|
| `nameservers` | [string] | Custom DNS nameservers. |
| `searches` | [string] | DNS search domains. |
| `options` | [string] | DNS resolver options. |
| `dns_forward_rules` | object | DNS forwarding rules (for dedicated hosts). |
| `skip_registration` | bool | If true, skip 6PN DNS registration. |

### config.services

Array of network service definitions that expose the machine to traffic.

| Field | Type | Description |
|-------|------|-------------|
| `protocol` | string (required) | `"tcp"` or `"udp"`. |
| `internal_port` | int (required) | Port the machine listens on. |
| `autostart` | bool | Auto-start the machine on incoming traffic. Default: `false`. |
| `autostop` | string | Auto-stop behavior: `"off"`, `"stop"`, or `"suspend"`. |
| `min_machines_running` | int | Minimum number of machines to keep running. |
| `concurrency` | object | Concurrency limits (see below). |
| `ports` | array | External port mappings (see below). |

#### services.concurrency

| Field | Type | Description |
|-------|------|-------------|
| `type` | string | `"connections"` or `"requests"`. |
| `soft_limit` | int | Target concurrency level. Default: `20`. |
| `hard_limit` | int | Maximum concurrency before rejecting. |

#### services.ports

| Field | Type | Description |
|-------|------|-------------|
| `port` | int | External port number. |
| `start_port` | int | Start of port range. |
| `end_port` | int | End of port range. |
| `handlers` | [string] | Protocol handlers: `"http"`, `"tcp"`, `"tls"`. |
| `force_https` | bool | Redirect HTTP to HTTPS. Default: `false`. |
| `http_options` | object | HTTP handler options. |
| `tls_options` | object | TLS handler options. |
| `proxy_proto_options` | object | PROXY protocol options. |

#### services.ports.http_options

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `compress` | bool | `false` | Enable response compression. |
| `h2_backend` | bool | `false` | Use HTTP/2 to the backend. |
| `response.headers` | object | - | Headers to add to responses. |
| `response.pristine` | bool | `false` | Do not modify response headers. |

#### services.ports.tls_options

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `alpn` | [string] | - | ALPN protocol identifiers. |
| `default_self_signed` | bool | `false` | Use self-signed cert as default. |
| `versions` | [string] | - | Allowed TLS versions. |

#### services.ports.proxy_proto_options

| Field | Type | Description |
|-------|------|-------------|
| `version` | string | PROXY protocol version: `"1"` or `"2"`. |

### config.checks

Health check definitions, keyed by check name.

```json
{
  "checks": {
    "my_check": {
      "type": "http",
      "port": 8080,
      "path": "/health",
      "interval": 10000000000,
      "timeout": 2000000000,
      "grace_period": 5000000000
    }
  }
}
```

| Field | Type | Description |
|-------|------|-------------|
| `type` | string | `"tcp"` or `"http"`. |
| `port` | int | Target port for the check. |
| `interval` | int | Nanoseconds between checks. |
| `timeout` | int | Max duration per check (nanoseconds). |
| `grace_period` | int | Delay before the first check (nanoseconds). |
| `method` | string | HTTP method (e.g., `"GET"`). Only for `type: "http"`. |
| `path` | string | HTTP path. Only for `type: "http"`. |
| `protocol` | string | `"http"` or `"https"`. |
| `tls_server_name` | string | Hostname for TLS certificate validation. |
| `tls_skip_verify` | bool | Skip TLS verification. Default: `false`. |
| `headers` | object | HTTP headers as `{ "name": ["value1", "value2"] }`. |

### config.metrics

Prometheus metrics scrape endpoint configuration.

| Field | Type | Description |
|-------|------|-------------|
| `port` | int (required) | Port exposing metrics. |
| `path` | string (required) | Path to scrape (e.g., `"/metrics"`). |

### config.restart

Restart policy for the machine.

| Field | Type | Description |
|-------|------|-------------|
| `policy` | string (required) | `"no"`, `"on-failure"`, or `"always"`. |
| `max_retries` | int | Maximum restart attempts. Only applies to `"on-failure"`. |

### config.stop_config

Shutdown behavior configuration.

| Field | Type | Description |
|-------|------|-------------|
| `signal` | string | Signal to send (e.g., `"SIGTERM"`). |
| `timeout` | int | Grace period in nanoseconds before force kill. |

### config.auto_destroy

```
auto_destroy: bool (default: false)
```

If true, the machine is automatically destroyed after it exits.

### config.schedule

```
schedule: string
```

Run the machine on a schedule: `"hourly"`, `"daily"`, `"weekly"`, or `"monthly"`.

### config.standbys

```
standbys: [string]
```

Array of machine IDs that this machine acts as a standby for.

### config.metadata

```
metadata: { "key": "value", ... }
```

Custom key-value pairs for routing and organizational purposes.

### config.size

```
size: string
```

Named machine size preset (e.g., `"shared-cpu-2x"`, `"performance-2x"`). Mutually exclusive with `config.guest`.

---

## Create/Update Request Parameters

### Create Machine (POST /v1/apps/{app_name}/machines)

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `name` | string | auto-generated | Unique machine name. Immutable after creation. |
| `region` | string | nearest | Target region. Immutable after creation. Defaults to the nearest WireGuard peer. |
| `config` | object (required) | - | Full machine configuration. |
| `lease_ttl` | int | - | Acquire an exclusive lease for N seconds on creation. |
| `skip_launch` | bool | `false` | Create the machine but do not start it. |
| `lsvd` | bool | `false` | Enable LSVD storage. |
| `skip_service_registration` | bool | `false` | Cordon the machine on creation. |

### Update Machine (POST /v1/apps/{app_name}/machines/{machine_id})

Same fields as create, plus:

| Field | Type | Description |
|-------|------|-------------|
| `current_version` | string | The latest `instance_id` of the machine. Used for optimistic concurrency. |

When updating, you must specify the entire `config` object. Partial config updates are not supported.

If the machine is leased, the `fly-machine-lease-nonce` header is required.

---

## Query Parameters

### List Machines (GET /v1/apps/{app_name}/machines)

| Parameter | Type | Description |
|-----------|------|-------------|
| `include_deleted` | bool | Include destroyed machines in the response. |
| `region` | string | Filter by region code. |
| `metadata.{key}` | string | Filter by metadata key-value pair. |

### Wait for State (GET /v1/apps/{app_name}/machines/{machine_id}/wait)

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `state` | string | `"started"` | Target state: `"started"`, `"stopped"`, `"suspended"`, `"destroyed"`. |
| `timeout` | int | `60` | Seconds to wait before timing out. **Must be in [1, 60].** |
| `instance_id` | string | - | Target a specific version. Required when waiting for `"stopped"` state. |

### Delete Machine (DELETE /v1/apps/{app_name}/machines/{machine_id})

| Parameter | Type | Description |
|-----------|------|-------------|
| `force` | bool | Force-stop the machine if it is currently running. |

---

## Action Endpoint Responses

The start, stop, suspend, wait, cordon, and uncordon endpoints return simple acknowledgments, **not** Machine objects.

### Stop Machine (POST .../stop)

Request body (optional):

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `signal` | string | `"SIGINT"` | Signal to send to the machine process. |
| `timeout` | int | - | Seconds to wait before sending SIGKILL. |

Response: HTTP 200

```json
{"ok": true}
```

### Wait for State (GET .../wait)

Response: HTTP 200 when the machine reaches the requested state within the timeout.

```json
{"ok": true}
```

Returns HTTP 408 if the timeout expires before reaching the desired state.

### Start / Cordon / Uncordon

Response: HTTP 200

```json
{"ok": true}
```

---

## Lease Endpoints

### Create Lease (POST .../lease)

Request body:

| Field | Type | Description |
|-------|------|-------------|
| `ttl` | int | Lease duration in seconds. |
| `description` | string | Optional description. |

Response: HTTP 201. The lease data is nested under a `data` wrapper:

```json
{
  "status": "success",
  "data": {
    "nonce": "5c35f65c9f95",
    "expires_at": 1708569778,
    "owner": "hello@fly.io",
    "description": "",
    "version": "01HQ73A7BFFDF1B6WMGHFZZ4E7"
  }
}
```

Use the `nonce` from `data.nonce` in the `fly-machine-lease-nonce` header for subsequent requests.

### Release Lease (DELETE .../lease)

Requires the `fly-machine-lease-nonce` header. Response: HTTP 200 with empty body.

---

## Volume Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/v1/apps/{app_name}/volumes` | Create a volume |
| DELETE | `/v1/apps/{app_name}/volumes/{volume_id}` | Delete a volume |

### Create Volume (POST /v1/apps/{app_name}/volumes)

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `name` | string (required) | - | Volume name. |
| `region` | string | - | Region to create the volume in. |
| `size_gb` | int | `3` | Size in gigabytes. |
| `encrypted` | bool | `true` | Whether to encrypt the volume. |
| `snapshot_id` | string | - | Snapshot ID to restore from. |
| `source_volume_id` | string | - | Source volume ID for a fork. |
| `require_unique_zone` | bool | `false` | Provision on hardware without duplicate volume names. |
| `auto_backup_enabled` | bool | `true` | Enable automatic daily snapshots. |
| `snapshot_retention` | int | - | Days to retain snapshots (1-60). |

Response: HTTP 200 with volume object containing at minimum `id` (string).

---

## Machine States

| State | Description |
|-------|-------------|
| `created` | Machine has been created but not yet started. |
| `started` | Machine is running. |
| `stopped` | Machine has been stopped. Resets to original state on next start. |
| `suspended` | Machine has been suspended. Attempts to resume from a snapshot on next start. |
| `destroyed` | Machine has been permanently deleted. |

---

## Key Behaviors

- **Full config required on update**: You must send the complete `config` object when updating. Partial updates are not supported.
- **Closed by default**: Machines are not accessible from the public internet unless `services` are configured.
- **Capacity failures**: Create requests may fail if capacity is unavailable. The caller is responsible for retry logic.
- **Stopped vs. Suspended**: Stopped machines reset to their original state on next start. Suspended machines attempt to resume from a memory snapshot.
- **Leasing**: Use the lease endpoints to acquire an exclusive lock on a machine. When a machine is leased, the `fly-machine-lease-nonce` header must be included in update and lease release requests. The lease create response nests data under a `data` key.
- **Metadata placement**: Machine metadata belongs inside `config.metadata`, not as a top-level field in create/update requests. The separate metadata endpoint (`POST .../metadata/{key}`) can update individual keys without a full config update.
- **Action endpoint responses**: Stop, start, wait, cordon, and uncordon return `{"ok": true}`, not Machine objects. Do not attempt to deserialize their responses as machines.
