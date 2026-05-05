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

`generate-certs.sh` only creates **server** TLS material (`server-ca.pem`, `server.pem`, ...). Each agent platform enrolls with `./examples/demo-agent.sh`, which starts a local `swtpm`, creates a persistent P-256 signing key in that simulated TPM, and prepares `machine-client.pem` as a certificate carrier for that public key and identity extension. The gateway does not trust a client CA bundle; it authorizes the exact subject public key recorded in signed Postgres permission rows.

Typical first-time flow:

1. `./examples/generate-certs.sh` and `cp config.example.toml config.toml`.
2. Enroll a trusted principal signing key and grant its destination delegation scope.
3. The principal creates an agent handle; the script prepares the subject certificate, signs permission rows for its exact SPKI DER, and starts the sidecar.
4. Start the gateway (`cargo run -- --config config.toml`) before sending prompts through the sidecar.

On later runs, start the gateway first and use `demo-agent.sh prompt`. `connect.sh` prepares `machine-client.pem` for the current simulated TPM key and identity extension whenever it prepares or starts the sidecar. `--regenerate-certs` creates a fresh simulated TPM state; any permissions for the old subject key will no longer match.

Pass a custom policy extension value: `connect.sh start-sidecar ... --extension-value agent-beta`. The extension value must match `permission_registry.subject_identity` in an active signed permission row.

The simulated TPM state lives under `$AGENT_STATE/client/swtpm/`. By default,
the sidecar uses TCTI `swtpm:host=127.0.0.1,port=2321` and persistent handle
`0x81010004`; override the handle or simulator data port with
`connect.sh start-sidecar --tpm-handle` and
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

Register a principal signing key from the TPM owner machine with:

```bash
./examples/register-principal-key.sh org-alice
```

The script creates or reuses a non-exportable TPM-backed P-256 key through `tpm2_ptool` and PKCS#11, stores only the public key in `principal_signing_keys`, and uses the friendly `key_id` (`org-alice`, `org-bob`, etc.) for the registry row. Run it on the machine that owns the TPM, with `AGENT_GATEWAY_DATABASE_URL` or `DATABASE_URL` pointing at Postgres.

For the demo, use three windows:

```bash
# Principal shell: enroll the principal TPM public key.
./examples/register-principal-key.sh org-alice

# Admin shell: grant destination delegation authority to that principal.
./examples/grant-principal-scope.sh org-alice api.anthropic.com example.com

# Principal shell: create a local agent handle with initial signed permissions.
AGENT_HANDLE="$(./examples/demo-agent.sh create \
  --identity agent-alpha \
  --grant api.anthropic.com)"

# Principal shell: send the first prompt through that agent.
./examples/demo-agent.sh prompt "$AGENT_HANDLE" --prompt "test prompt"

# Principal shell: grant another destination, then continue the same Claude session.
./examples/demo-agent.sh grant "$AGENT_HANDLE" --grant example.com
./examples/demo-agent.sh prompt "$AGENT_HANDLE" --prompt "now try the second destination"
```

The dashboard runs separately and observes Postgres plus OpenTelemetry. `demo-agent.sh` keeps gateway connection details out of the principal-facing command; set `AGENT_GATEWAY_DEMO_GATEWAY` and `AGENT_GATEWAY_DEMO_GATEWAY_CA` only when overriding the local defaults. `AGENT_GATEWAY_DEMO_GATEWAY_CA` is the CA for the gateway's server certificate, not a client trust root. The first prompt uses `claude -p`; later prompts for the same handle use `claude -c -p` from the handle's working directory.

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
