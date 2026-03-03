# TLS Exported Keying Material

## Sources

- RFC 5705 (TLS 1.2 Exporters): <https://www.rfc-editor.org/rfc/rfc5705.html>
- RFC 8446 (TLS 1.3), Section 7.5 -- Exporters: <https://datatracker.ietf.org/doc/html/rfc8446#section-7.5>
- RFC 9266 (TLS 1.3 Channel Bindings): <https://www.rfc-editor.org/rfc/rfc9266.html>
- RFC 5056 (On the Use of Channel Bindings): <https://www.rfc-editor.org/rfc/rfc5056.html>
- rustls `ConnectionCommon` docs: <https://docs.rs/rustls/latest/rustls/struct.ConnectionCommon.html>
- rustls issue #945 (exporter API and TLS 1.3): <https://github.com/rustls/rustls/issues/945>
- The Illustrated TLS 1.3 Connection: <https://tls13.xargs.org/>
- Channel binding overview: <https://csb.stevekerrison.com/post/2022-01-channel-binding/>

---

## Overview

TLS Exported Keying Material (EKM) is a mechanism that lets both sides of a TLS
connection derive identical secret byte strings from the shared TLS session
secrets. The derived material can be used by higher-layer protocols for their
own cryptographic purposes (authentication, channel binding, key derivation for
side channels, etc.) without exposing the TLS master secret itself.

The mechanism is defined in:

- **RFC 5705** -- "Keying Material Exporters for Transport Layer Security (TLS)"
  (March 2010). Defines the exporter interface and construction for TLS 1.2 and
  earlier.
- **RFC 8446, Section 7.5** -- Redefines the exporter construction for TLS 1.3
  using the HKDF-based key schedule.
- **RFC 9266** -- "Channel Bindings for TLS 1.3". Defines the `tls-exporter`
  channel binding type that replaces the broken `tls-unique` binding.

---

## The Exporter API

The exporter interface takes three parameters:

| Parameter   | Type               | Description |
|-------------|--------------------|-------------|
| **label**   | ASCII string       | A disambiguating label identifying the purpose of the exported material. Labels SHOULD begin with `"EXPORTER"`. Labels beginning with `"EXPERIMENTAL"` may be used without IANA registration. |
| **context** | byte string or None| Optional application-provided data mixed into the derivation. Provides domain separation when the same label is reused in different application contexts. |
| **length**  | integer            | The number of bytes of keying material to produce. |

Both the TLS client and the TLS server call this interface with the same
(label, context, length) tuple and receive identical output, because they share
the same session secrets and use a deterministic derivation function.

---

## How Exporters Work in TLS 1.2 (RFC 5705)

In TLS 1.2, the exporter uses the TLS Pseudo-Random Function (PRF) that was
negotiated for the session. The construction depends on whether a context value
is supplied.

### Without context:

```
EKM = PRF(master_secret, label,
          client_random + server_random
      )[0..length]
```

### With context:

```
EKM = PRF(master_secret, label,
          client_random + server_random +
          uint16(len(context)) + context
      )[0..length]
```

Where:
- `master_secret` is the TLS session's master secret (48 bytes).
- `client_random` and `server_random` are the 32-byte random values from the
  ClientHello and ServerHello messages.
- `PRF` is the TLS PRF for the cipher suite (typically HMAC-SHA256 based).

Note: providing no context and providing a zero-length context produce
**different** outputs in TLS 1.2 (because the length prefix is absent vs.
present-but-zero). TLS 1.3 changes this -- see below.

---

## How Exporters Work in TLS 1.3 (RFC 8446 Section 7.5)

TLS 1.3 replaces the PRF with an HKDF-based key schedule. The exporter
construction is a two-step process:

### Step 1: Derive a label-specific intermediate secret

```
intermediate = Derive-Secret(exporter_master_secret, label, "")
             = HKDF-Expand-Label(exporter_master_secret,
                                 label,
                                 Hash(""),
                                 Hash.length)
```

This binds the label into the derivation. The empty string `""` means no
handshake transcript messages are included (the transcript is already baked
into the `exporter_master_secret` itself).

### Step 2: Expand with the caller's context

```
EKM = HKDF-Expand-Label(intermediate,
                         "exporter",
                         Hash(context_value),
                         length)
```

The caller's context value is hashed before being mixed in. If no context is
provided, a zero-length context is used. Unlike TLS 1.2, providing no context
and providing an empty context produce the **same** output in TLS 1.3.

### Combined formula

```
TLS-Exporter(label, context, length) =
    HKDF-Expand-Label(
        Derive-Secret(exporter_master_secret, label, ""),
        "exporter",
        Hash(context),
        length
    )
```

### Where does exporter_master_secret come from?

The `exporter_master_secret` is derived during the TLS 1.3 key schedule:

```
exporter_master_secret =
    Derive-Secret(Master Secret, "exp master",
                  ClientHello..server Finished)
```

It incorporates:
- The (EC)DHE shared secret (from the key exchange).
- The PSK (if any).
- The full handshake transcript up through the server Finished message.

This means the exporter output is bound to the specific handshake that occurred,
including the server's identity (certificate), the negotiated parameters, and
the randomness from both sides.

### HKDF-Expand-Label internals

For reference, the TLS 1.3 helper function is defined as:

```
HKDF-Expand-Label(Secret, Label, Context, Length) =
    HKDF-Expand(Secret, HkdfLabel, Length)

where HkdfLabel = struct {
    uint16 length = Length;
    opaque label<7..255> = "tls13 " + Label;   // note the "tls13 " prefix
    opaque context<0..255> = Context;
}
```

### Early exporters

TLS 1.3 also defines an `early_exporter_master_secret` for use with 0-RTT data.
It is derived from the PSK only (no (EC)DHE contribution) and therefore is NOT
forward-secret. Implementations SHOULD expose it through a separate API to
prevent accidental misuse. For most applications, use the regular
`exporter_master_secret`.

---

## Channel Binding (RFC 9266)

### What is channel binding?

Channel binding ties an authentication exchange (e.g., SASL, EAP) to the
specific TLS channel over which it occurs. Both sides compute a "channel binding
value" derived from the TLS session and include it in their authentication
protocol messages. If a man-in-the-middle is present, the two sides will have
different TLS sessions and thus different binding values, causing authentication
to fail.

### The tls-exporter binding type

RFC 9266 defines the `tls-exporter` channel binding type, which is computed as:

```
binding_value = TLS-Exporter(
    label:   "EXPORTER-Channel-Binding",   // no NUL terminator
    context: "",                            // zero-length context
    length:  32                             // 32 bytes output
)
```

This replaces the older `tls-unique` binding type (RFC 5929), which:
- Is not defined for TLS 1.3.
- Was found to be vulnerable to the "triple handshake" (3SHAKE) attack unless
  the extended master secret extension (RFC 7627) is in use.
- Is generally considered broken and should not be used.

### tls-exporter as the new default

RFC 9266 updates several specifications to use `tls-exporter` as the default
channel binding for TLS 1.3 and later:
- RFC 5801 (GSS-API SASL mechanism)
- RFC 5802 (SCRAM)
- RFC 7677 (SCRAM-SHA-256)

For TLS 1.3, `tls-exporter` is mandatory-to-implement if any channel bindings
are implemented.

### Restrictions on tls-exporter usage

- The derived value MUST NOT be used for any purpose other than channel binding
  (not as an encryption key, not as a MAC key, etc.).
- Only one authentication exchange should use a given TLS connection's channel
  binding value. The connection should be closed after authentication completes.
- On TLS 1.2 connections with renegotiation enabled, `tls-exporter` MUST NOT be
  used (renegotiation changes the master secret, invalidating the binding).

---

## Why Both Sides Derive the Same Value

The exporter output is a deterministic function of:

1. The **session secrets** -- both sides have the same master secret (TLS 1.2)
   or the same `exporter_master_secret` (TLS 1.3), established during the
   handshake via the key exchange.
2. The **label** -- provided identically by the application on both sides.
3. The **context** -- provided identically by the application on both sides.
4. The **length** -- provided identically by the application on both sides.

Since the derivation function (PRF or HKDF) is deterministic, identical inputs
produce identical outputs. No additional round-trip or coordination is needed
beyond the initial TLS handshake.

---

## Security Properties

### Why a MITM gets different values

In a man-in-the-middle attack, the attacker terminates two separate TLS
sessions:

```
Client <--TLS session A--> Attacker <--TLS session B--> Server
```

Session A and Session B have **different**:
- (EC)DHE shared secrets (the attacker performed independent key exchanges with
  each side).
- Handshake transcripts (different random values, different certificates).
- Master secrets / exporter_master_secrets.

Therefore, the exporter output computed by the client (from session A's secrets)
will not match the exporter output computed by the server (from session B's
secrets). When these values are compared during the authentication protocol, the
mismatch reveals the MITM.

The attacker cannot forge the correct exporter value for the other session
because:
- They do not know the other session's master secret (it is derived from the
  (EC)DHE shared secret, which the attacker does not have for the legitimate
  endpoint's session).
- The exporter output is indistinguishable from random to anyone who does not
  know the master secret (by the PRF/HKDF security properties).

### Formal verification

Formal analysis (e.g., Tamarin prover models of TLS 1.3) has confirmed that
TLS 1.3 exporter-based channel binding achieves "context agreement" -- both
parties agree on the identity of the peer and the channel properties. This
property does NOT hold for all TLS versions and key exchange methods:
- TLS 1.2 with RSA key exchange is insufficient (the client alone generates the
  premaster secret, so the server has no assurance that bindings are legitimate).
- TLS 1.2 with DHE key exchange achieves server-side context agreement only with
  the extended master secret extension.

### Independence of exported values

Knowing one EKM value (for a given label/context) does not reveal any useful
information about:
- The master secret.
- Other EKM values derived with different labels or contexts.
- The TLS traffic keys.

This property follows from the PRF/HKDF security guarantees.

### Forward secrecy

The regular `exporter_master_secret` in TLS 1.3 benefits from forward secrecy
(assuming (EC)DHE key exchange was used) because it is derived from the
ephemeral DH shared secret. Compromising the server's long-term key after the
session ends does not allow an attacker to compute past exporter values.

The `early_exporter_master_secret` does NOT have forward secrecy since it is
derived solely from the PSK.

---

## Using TLS Exporters in Rust with rustls

### API (rustls 0.23.x)

The exporter is exposed on `ConnectionCommon`, which is the shared
implementation behind both `ClientConnection` and `ServerConnection`.

```rust
impl<Data> ConnectionCommon<Data> {
    pub fn export_keying_material<T: AsMut<[u8]>>(
        &self,
        output: T,
        label: &[u8],
        context: Option<&[u8]>,
    ) -> Result<T, Error>
}
```

**Parameters:**
- `output: T` -- a buffer (e.g., `[u8; 32]` or `vec![0u8; 32]`) that will be
  filled with the exported keying material. The length of this buffer determines
  how many bytes are derived.
- `label: &[u8]` -- the exporter label (e.g., `b"EXPORTER-Channel-Binding"`).
- `context: Option<&[u8]>` -- optional context value. `None` means no context.
  `Some(b"")` means empty context. In TLS 1.3 these produce the same output;
  in TLS 1.2 they differ.

**Returns:** `Result<T, Error>` -- on success, returns ownership of the filled
buffer. On failure (e.g., handshake not yet complete), returns an error. The
return-by-value design prevents leaking partial key material on error.

**Precondition:** The TLS handshake must be complete. Check with
`CommonState::is_handshaking()` before calling.

### Example: Channel Binding

```rust
use rustls::ClientConnection;

fn get_channel_binding(conn: &ClientConnection) -> Result<[u8; 32], rustls::Error> {
    conn.export_keying_material(
        [0u8; 32],
        b"EXPORTER-Channel-Binding",
        Some(b""),  // zero-length context, per RFC 9266
    )
}
```

Both the client and the server call the same function with the same arguments
and receive the same 32-byte value.

### Example: Application-Specific Key Derivation

```rust
fn derive_app_key(
    conn: &rustls::ServerConnection,
    session_id: &[u8],
) -> Result<[u8; 64], rustls::Error> {
    conn.export_keying_material(
        [0u8; 64],
        b"EXPORTER-my-app-session-key",
        Some(session_id),
    )
}
```

### Accessing via the Connection enum

If you have a `rustls::Connection` (the enum that wraps either client or
server), the method is also available:

```rust
let conn: rustls::Connection = /* ... */;
let ekm = conn.export_keying_material(
    [0u8; 32],
    b"EXPORTER-Channel-Binding",
    Some(b""),
)?;
```

### Notes on the rustls implementation

- For TLS 1.3, rustls uses the `exporter_master_secret` (never the early
  exporter).
- The `exporter_master_secret` is retained in memory for the lifetime of the
  connection, so `export_keying_material` can be called at any time after the
  handshake. RFC 8446 Appendix E.1.4 recommends erasing exporter secrets "as
  soon as possible," but the current API design requires retaining it. This is
  tracked in rustls issue #945.
- rustls does not expose a separate early exporter API as of version 0.23.x
  (tracked in issue #2406).
