# Fly.io OIDC Token Reference

Sources:

- https://fly.io/docs/security/openid-connect/
- https://fly.io/docs/machines/api/tokens-resource/
- https://oidc.fly.io/fly-io/.well-known/openid-configuration

---

## Issuer URL

Each Fly.io organization has its own OIDC issuer. The format is:

```
https://oidc.fly.io/<org-slug>
```

For example, an organization with slug `example-org` has the issuer URL `https://oidc.fly.io/example-org`.

## Requesting a Token from Inside a Machine

Machines expose a local Unix socket that can be used to request OIDC tokens without any additional authentication.

**Unix socket path:** `/.fly/api`

**Endpoint:** `POST /v1/tokens/oidc`

**Request body (JSON, optional):**

```json
{
  "aud": "<custom-audience>"
}
```

### Example: Request via Unix socket (inside a Machine)

```bash
curl --unix-socket /.fly/api \
  -X POST \
  "http://localhost/v1/tokens/oidc" \
  -d '{"aud": "sts.amazonaws.com"}'
```

The response body is the raw JWT token string (not wrapped in JSON).

### Example: Request via Machines API (external)

```bash
curl -i -X POST \
  -H "Authorization: Bearer ${FLY_API_TOKEN}" \
  -H "Content-Type: application/json" \
  "${FLY_API_HOSTNAME}/v1/tokens/oidc" \
  -d '{"aud": "https://fly.io/my-org-slug"}'
```

**Response status:** `200 OK`

## Custom Audience Parameter

The `aud` claim can be customized by providing it in the POST request body. This lets you specify the intended recipient of the token. For example, set `"aud": "sts.amazonaws.com"` when using the token to authenticate with AWS STS.

If the `aud` parameter is omitted, the default audience is `https://fly.io/<org-slug>`.

## JWT Claims

The following claims are included in OIDC tokens. This list is sourced from the OpenID Connect discovery document and the example token in the documentation.

| Claim | Type | Description | Example Value |
|-------|------|-------------|---------------|
| `iss` | string | Issuer URL (`https://oidc.fly.io/<org-slug>`) | `"https://oidc.fly.io/example-org"` |
| `sub` | string | Subject (`<org>:<app>:<machine>`) | `"example-org:example-app:example-machine"` |
| `aud` | string | Audience (token recipient) | `"https://fly.io/example-org"` |
| `exp` | number | Expiration time (Unix timestamp) | `1712099653` |
| `iat` | number | Issued-at time (Unix timestamp) | `1712099053` |
| `nbf` | number | Not-before time (Unix timestamp) | `1712099053` |
| `jti` | string | Unique token identifier (UUID) | `"93ca09e1-70e0-477b-a260-1d8fcd4ef4f4"` |
| `org_id` | string | Organization ID | `"11111111"` |
| `org_name` | string | Organization slug | `"example-org"` |
| `app_id` | string | Application ID | `"11111111"` |
| `app_name` | string | Application name | `"example-app"` |
| `machine_id` | string | Machine ID | `"148e21ea7e46e8"` |
| `machine_name` | string | Machine name | `"example-machine"` |
| `machine_version` | string | Machine version (ULID) | `"01HTGGC1TZ2JHK83J4AC0R3VET"` |
| `region` | string | Fly.io region code | `"sea"` |
| `image` | string | Container image reference | `"docker-hub-mirror.fly.io/you/image:latest"` |
| `image_digest` | string | Image digest (sha256) | `"sha256:..."` |
| `image_tag` | string | Image tag (listed in discovery document) | *(not shown in example token)* |

## Token Lifetime and Expiration

OIDC tokens issued by Fly.io are valid for **15 minutes** before they expire. In the example token, `iat` and `nbf` are both `1712099053` and `exp` is `1712099653`, confirming a 600-second (10-minute) window in that particular example. The documentation states the general policy as 15 minutes.

## JWKS Endpoint (Signature Verification)

Tokens are signed with the **RS256** algorithm. Public keys for verifying token signatures are available at the JWKS (JSON Web Key Set) endpoint:

```
https://oidc.fly.io/<org-slug>/.well-known/jwks
```

### OpenID Connect Discovery Document

The full discovery document is available at:

```
https://oidc.fly.io/<org-slug>/.well-known/openid-configuration
```

Discovery document fields:

| Field | Value |
|-------|-------|
| `issuer` | `https://oidc.fly.io/<org-slug>` |
| `jwks_uri` | `https://oidc.fly.io/<org-slug>/.well-known/jwks` |
| `subject_types_supported` | `["public"]` |
| `response_types_supported` | `["id_token"]` |
| `id_token_signing_alg_values_supported` | `["RS256"]` |
| `scopes_supported` | `["openid"]` |
| `claims_supported` | `["sub", "aud", "exp", "iat", "iss", "jti", "nbf", "org_name", "app_name", "machine_name", "org_id", "app_id", "machine_id", "machine_version", "region", "image", "image_digest", "image_tag"]` |

## Rate Limits and Constraints

The fetched documentation does not specify any explicit rate limits or constraints on OIDC token requests.
