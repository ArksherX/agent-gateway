# agent_gateway

An mTLS HTTP/2 CONNECT proxy that authorizes connections based on custom X.509 certificate extensions.

The proxy accepts incoming mTLS connections, extracts a custom extension value from the client certificate, and checks a PostgreSQL-backed signed permission registry to decide whether the client may connect to the requested destination. If allowed, it opens a raw TCP connection to the destination and tunnels data bidirectionally. The client is responsible for establishing its own TLS session to the destination through the tunnel.

## Building

```
cargo build --release
```

The sidecar uses a simulated TPM identity. Install the native TPM stack before
building or running it:

```bash
sudo apt-get install libtss2-dev swtpm tpm2-tools pkg-config
```

## Quick start

```bash
./examples/generate-certs.sh          # server CA + gateway cert under certs/
cp config.example.toml config.toml    # edit to taste
docker compose -f docker-compose.postgres.yml up -d
export AGENT_GATEWAY_DATABASE_URL=postgres://agent_gateway_admin:agent_gateway_dev@localhost:5432/agent_gateway
cargo run -- --config config.toml migrate
```

`generate-certs.sh` only creates **server** TLS material (`server-ca.pem`, `server.pem`, ...). Each agent platform enrolls with `./examples/connect.sh`, which starts a local `swtpm`, creates a persistent P-256 signing key in that simulated TPM, and issues `machine-client.pem` for the TPM public key. The gateway needs the generated `machine-client-ca.pem` in `certs/client-ca-bundle.pem` before it can trust that sidecar.

Typical first-time flow:

1. `./examples/generate-certs.sh` and `cp config.example.toml config.toml`.
2. `./examples/connect.sh --gateway 127.0.0.1:8443 --gateway-ca certs/server-ca.pem` creates `machine-client-ca.pem` under `~/.local/share/agent-gateway/` (or `$XDG_DATA_HOME`). Append that file to `client_ca_path` (for example, `cat ~/.local/share/agent-gateway/machine-client-ca.pem >> certs/client-ca-bundle.pem`).
3. Insert a trusted principal signing key, its delegation scope, and signed permission rows into Postgres.
4. Start the gateway (`cargo run -- --config config.toml`), then return to the terminal running `connect.sh` and press Enter to start the sidecar and Claude.

On later runs, start the gateway first, run `connect.sh`, and press Enter after confirming the machine CA is still registered. If `connect.sh` finds an existing simulated TPM key but the saved `machine-client.pem` was issued for a different public key, it reissues `machine-client.pem` for the current TPM key using the existing machine client CA. `--regenerate-certs` creates a fresh simulated TPM state and machine client CA, so the new CA must be appended to `client_ca_path`.

Pass a custom policy extension value: `connect.sh ... --extension-value agent-beta`. The extension value must match `permission_registry.subject_identity` in an active signed permission row.

The simulated TPM state lives under `~/.local/share/agent-gateway/swtpm/` unless
`XDG_DATA_HOME` is set. By default, the sidecar uses TCTI
`swtpm:host=127.0.0.1,port=2321` and persistent handle `0x81010004`; override
the handle or simulator data port with `connect.sh --tpm-handle` and
`--swtpm-port`. The swtpm control port is always the data port plus one, which
matches the TSS swtpm TCTI convention.

## Configuration

Copy `config.example.toml` to `config.toml` and edit it. Key sections:

**`[server]`** -- Listen address and TLS material.

| Field | Required | Description |
|---|---|---|
| `listen_addr` | yes | `host:port` to bind (e.g. `0.0.0.0:8443`) |
| `tls_cert_path` | yes | PEM server certificate |
| `tls_key_path` | yes | PEM private key for the server cert |
| `client_ca_path` | yes | PEM bundle of per-machine client CAs (append each `machine-client-ca.pem`) |

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
leaving OTLP export enabled. The sidecar reads observability settings from
environment variables. Use `RUST_LOG` for its tracing filter and set
`OTEL_EXPORTER_OTLP_ENDPOINT` (for example, `http://localhost:4317`) to export
sidecar spans over OTLP. When enabled, the sidecar injects W3C trace-context
headers into the CONNECT request it sends to the gateway, and the gateway
continues the same trace.

## Running

```
agent_gateway --config config.toml
```

Run migrations explicitly before starting the gateway:

```bash
agent_gateway --config config.toml migrate
```

Gateway startup verifies the authorization registry schema version and fails fast if the database is not migrated. The runtime gateway database role should be read-only for authorization tables; use a separate admin role for migrations and registry writes.

Shut down cleanly with `Ctrl-C`.

Register a demo principal signing key with:

```bash
./examples/register-principal-key.sh org-alice
```

The script creates a P-256 private key under `certs/principals/`, stores the public key in `principal_signing_keys`, and uses the friendly `key_id` (`org-alice`, `org-bob`, etc.) for the registry row.

## Authorization Registry

The gateway authorizes a CONNECT only when all of these checks pass:

1. The mTLS client certificate has the configured UTF8String identity extension.
2. The requested authority normalizes to a `host:port` destination.
3. Postgres contains an active `permission_registry` row for that identity and destination.
4. The row's `signature` verifies over the canonical permission row fields with the referenced active principal signing key.
5. `principal_key_permissions` confirms that the signing key was allowed to delegate that identity/destination scope.

### Database Structure

The authorization registry has three main tables:

| Table | Key Columns | Purpose |
|---|---|---|
| `principal_signing_keys` | `key_id`, `algorithm`, `public_key_spki_der`, `not_before`, `not_after`, `revoked_at` | Stores trusted P-256 public keys that may sign permissions. |
| `principal_key_permissions` | `signing_key_id`, `subject_identity`, `destination`, `not_before`, `not_after`, `revoked_at` | Defines what each signing key is allowed to delegate. |
| `permission_registry` | `permission_id`, `signing_key_id`, `subject_identity`, `destination`, `not_before`, `not_after`, `revoked_at`, `signature` | Stores signed permissions that authorize a subject identity to reach a normalized destination. |

`principal_key_permissions.signing_key_id` and `permission_registry.signing_key_id` both reference `principal_signing_keys.key_id`. A permission is usable only when the permission row is active, the signing key is active, the signature verifies over the canonical row fields, and the signing key has a matching delegation scope row.

The signed bytes are the following UTF-8 text, with fields in this exact order and timestamps formatted as UTC RFC 3339 with six fractional digits:

```text
agent-gateway-permission-v1
permission_id=perm-1
signing_key_id=org-alice
subject_identity=agent-alpha
destination=api.example.com:443
not_before=2026-05-01T00:00:00.000000Z
not_after=2026-06-01T00:00:00.000000Z
```

Destination strings are normalized with the same rules used for CONNECT requests: hostnames are lowercased, omitted ports default to `443`, and IPv6 destinations use bracketed `host:port` form.

## Client requirements

Clients must:

1. **Connect over HTTP/2 with mTLS.** Present a client certificate signed by the CA specified in `client_ca_path`. The certificate must contain a custom X.509 extension at the OID configured in `policy.client_ext_oid`, with a DER-encoded UTF8String value.

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
