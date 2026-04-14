# agent_gateway

An mTLS HTTP/2 CONNECT proxy that authorizes connections based on custom X.509 certificate extensions.

The proxy accepts incoming mTLS connections, extracts a custom extension value from the client certificate, and checks it against a TOML policy file to decide whether the client may connect to the requested destination. If allowed, it opens a raw TCP connection to the destination and tunnels data bidirectionally. The client is responsible for establishing its own TLS session to the destination through the tunnel.

## Building

```
cargo build --release
```

## Quick start

```bash
./examples/generate-certs.sh          # creates certs/ directory
cp config.example.toml config.toml    # edit to taste
cargo run -- --config config.toml
```

The generated filenames match `config.example.toml` so no editing is needed for local development. Pass a custom extension value as an argument: `./examples/generate-certs.sh agent-beta`.

## Configuration

Copy `config.example.toml` to `config.toml` and edit it. Key sections:

**`[server]`** -- Listen address and TLS material.

| Field | Required | Description |
|---|---|---|
| `listen_addr` | yes | `host:port` to bind (e.g. `0.0.0.0:8443`) |
| `tls_cert_path` | yes | PEM server certificate |
| `tls_key_path` | yes | PEM private key for the server cert |
| `client_ca_path` | yes | PEM CA that issued client certificates |

**`[policy]`** -- Maps certificate extension values to allowed destinations.

| Field | Description |
|---|---|
| `client_ext_oid` | OID of the custom X.509 extension to extract (dotted notation) |
| `rules[].extension_value` | Value to match in the extension |
| `rules[].allowed_destinations` | List of `host` or `host:port` entries. Port defaults to `443` if omitted. |

**`[observability]`** -- Logging and tracing.

| Field | Required | Description |
|---|---|---|
| `log_level` | yes | `tracing` filter (e.g. `info`, `debug`, `agent_gateway=debug`) |
| `otlp_endpoint` | no | OTLP gRPC endpoint for distributed tracing |

## Running

```
agent_gateway --config config.toml
```

Shut down cleanly with `Ctrl-C`.

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

The extension value is matched exactly (case-sensitive) against policy rules. The extension must be an X.509 extension at the configured OID containing a single DER-encoded ASN.1 UTF8String.

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

38 integration tests cover policy evaluation, destination normalization (including IPv6 and default port), config validation, TLS PKI generation, and proxy request parsing.
