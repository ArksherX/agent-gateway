# agent_gateway

An mTLS HTTP/2 CONNECT proxy that authorizes connections based on custom X.509 certificate extensions.

The proxy accepts incoming mTLS connections, extracts a custom extension value from the client certificate, and checks a PostgreSQL-backed signed permission registry to decide whether the client may connect to the requested destination. If allowed, it opens a raw TCP connection to the destination and tunnels data bidirectionally. The client is responsible for establishing its own TLS session to the destination through the tunnel.

## Building

```
cargo build --release
```

The end-to-end demo, sidecar, TPM setup, mock services, and registry helper
scripts live in the split demo repository. The demo pins a gateway image such as
`ghcr.io/sl5taskforce/agent-gateway:main` and does not require this source checkout.

## Configuration

Copy `config.example.toml` to `config.toml` and edit it. Key sections:

**`[server]`** -- Listen address and TLS material.

| Field | Required | Description |
|---|---|---|
| `listen_addr` | yes | `host:port` to bind (e.g. `0.0.0.0:8443`) |
| `tls_cert_path` | yes | PEM server certificate |
| `tls_key_path` | yes | PEM private key for the server cert |

**`[policy]`** -- Configures the certificate identity extension and Postgres registry access.

| Field | Description |
|---|---|
| `client_ext_oid` | OID of the custom X.509 extension to extract (dotted notation) |
| `database_url` | Postgres URL for the authorization registry. Prefer `database_url_env` outside local development. |
| `database_url_env` | Environment variable containing the Postgres URL. |
| `max_connections` | Maximum Postgres pool connections. Defaults to `5`. |
| `connect_timeout_ms` | Postgres connection timeout. Defaults to `5000`. |
| `pool_acquire_timeout_ms` | Pool acquire timeout per authorization check. Defaults to `1000`. |
| `query_timeout_ms` | Query timeout per registry lookup. Defaults to `500`. |

**`[observability]`** -- Logging and tracing.

| Field | Required | Description |
|---|---|---|
| `log_level` | yes | `tracing` filter (e.g. `info`, `debug`, `agent_gateway=debug`) |
| `otlp_endpoint` | no | OTLP gRPC endpoint for distributed tracing |

Set `AGENT_GATEWAY_LOG_STDOUT=false` to disable stdout/stderr formatting while
leaving OTLP export enabled.

## Running

```
agent_gateway --config config.toml
```

Run migrations explicitly before starting the gateway:

```bash
psql "$AGENT_GATEWAY_DATABASE_URL" -f migrations/0001_signed_authorization_registry.sql
```

Gateway startup verifies the authorization registry schema version and fails fast if the database is not migrated. The runtime gateway database role should be read-only for authorization tables; use a separate admin role for migrations and registry writes.

Shut down cleanly with `Ctrl-C`.

## Authorization Registry

The gateway authorizes a CONNECT only when all of these checks pass:

1. The mTLS client certificate has the configured UTF8String identity extension.
2. The requested authority normalizes to a `host:port` destination.
3. Postgres contains an active `permission_registry` row for that identity, destination, and the leaf certificate's exact SubjectPublicKeyInfo DER.
4. The row's `signature` verifies over the canonical permission row fields with the referenced active principal signing key.
5. `principal_key_permissions` confirms that the signing key was allowed to delegate that destination.

### Database Structure

The authorization registry has three main tables:

| Table | Key Columns | Purpose |
|---|---|---|
| `principal_signing_keys` | `key_id`, `algorithm`, `public_key_spki_der`, `not_before`, `not_after`, `revoked_at` | Stores trusted P-256 public keys that may sign permissions. |
| `principal_key_permissions` | `signing_key_id`, `destination`, `not_before`, `not_after`, `revoked_at` | Defines which destinations each signing key is allowed to delegate. |
| `permission_registry` | `permission_id`, `signing_key_id`, `subject_identity`, `subject_public_key_spki_der`, `destination`, `not_before`, `not_after`, `revoked_at`, `signature` | Stores signed permissions that authorize a subject identity and exact subject key to reach a normalized destination. |

`principal_key_permissions.signing_key_id` and `permission_registry.signing_key_id` both reference `principal_signing_keys.key_id`. A permission is usable only when the permission row is active, the signing key is active, the signature verifies over the canonical row fields, and the signing key has a matching destination delegation row.

The signed bytes are the following UTF-8 text, with fields in this exact order and timestamps formatted as UTC RFC 3339 with six fractional digits:

```text
agent-gateway-permission-v1
permission_id=perm-1
signing_key_id=org-alice
subject_identity=agent-alpha
subject_public_key_spki_der=3059301306072a8648ce3d020106082a8648ce3d03010703420004...
destination=api.example.com:443
not_before=2026-05-01T00:00:00.000000Z
not_after=2026-06-01T00:00:00.000000Z
```

Destination strings are normalized with the same rules used for CONNECT requests: hostnames are lowercased, omitted ports default to `443`, and IPv6 destinations use bracketed `host:port` form.

## Client requirements

Clients must:

1. **Connect over HTTP/2 with mTLS.** Present a structurally valid client certificate and prove possession of the certificate private key during the TLS handshake. The certificate must contain a custom X.509 extension at the OID configured in `policy.client_ext_oid`, with a DER-encoded UTF8String value. The full leaf SubjectPublicKeyInfo DER must match an active signed permission row.

2. **Use the HTTP CONNECT method.** The request authority must be `host:port` (port defaults to 443 if omitted). Example using `hyper`:

   ```rust
   let req = Request::builder()
       .method(Method::CONNECT)
       .uri("api.example.com:443")
       .body(Empty::<Bytes>::new())?;
   ```

3. **Handle TLS to the destination.** After receiving `200 OK`, the tunnel is an opaque TCP pipe. The client must perform its own TLS handshake with the destination through the tunnel.

### Response codes

| Status | Meaning |
|---|---|
| `200` | Tunnel established -- begin sending data |
| `400` | Malformed request (missing/invalid authority) |
| `403` | Policy denied the connection |
| `405` | Non-CONNECT method used |
| `502` | Could not reach the destination |

### Client certificate extension

The extension value is matched exactly (case-sensitive) against signed permission rows. The extension must be an X.509 extension at the configured OID containing a single DER-encoded ASN.1 UTF8String.

Example certificate generation with `rcgen`:

```rust
use rcgen::{CertificateParams, CustomExtension};

let oid: &[u64] = &[1, 3, 6, 1, 4, 1, 57264, 1, 1];
let value = der_encode_utf8_string("agent-alpha");
params.custom_extensions.push(
    CustomExtension::from_oid_content(oid, value),
);
```

## Tests

```
cargo test
```

Database-backed policy and e2e tests require `TEST_DATABASE_URL` to point at a Postgres database that the test process can migrate and write to. The tests cover policy evaluation, signed-permission verification, signer delegation scope enforcement, destination normalization, config validation, TLS PKI generation, and proxy request parsing.

## SQLx Query Metadata

Checked SQLx query macros compile against committed `.sqlx` metadata by default, so normal builds do not need database access. The metadata is derived from the migrations; it does not replace the migration SQL used to create or update the database schema.

Regenerate the metadata after changing migrations or SQL query text:

```bash
cargo install sqlx-cli --version 0.8.6 --locked --no-default-features --features postgres
SQLX_OFFLINE=false DATABASE_URL="$TEST_DATABASE_URL" cargo sqlx database setup
SQLX_OFFLINE=false DATABASE_URL="$TEST_DATABASE_URL" cargo sqlx prepare -- --all-targets --locked
```
