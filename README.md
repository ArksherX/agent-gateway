# agent_gateway

An mTLS HTTP/2 CONNECT proxy that authorizes connections based on custom X.509 certificate extensions.

The proxy accepts incoming mTLS connections, extracts a custom extension value from the client certificate, and checks it against a TOML policy file to decide whether the client may connect to the requested destination. If allowed, it opens a raw TCP connection to the destination and tunnels data bidirectionally. The client is responsible for establishing its own TLS session to the destination through the tunnel.

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
```

`generate-certs.sh` only creates **server** TLS material (`server-ca.pem`, `server.pem`, ...). Each agent platform enrolls with `./examples/connect.sh`, which starts a local `swtpm`, creates a persistent P-256 signing key in that simulated TPM, and issues `machine-client.pem` for the TPM public key. The gateway needs the generated `machine-client-ca.pem` in `certs/client-ca-bundle.pem` before it can trust that sidecar.

Typical first-time flow:

1. `./examples/generate-certs.sh` and `cp config.example.toml config.toml`.
2. `./examples/connect.sh --gateway 127.0.0.1:8443 --gateway-ca certs/server-ca.pem` creates `machine-client-ca.pem` under `~/.local/share/agent-gateway/` (or `$XDG_DATA_HOME`). Append that file to `client_ca_path` (for example, `cat ~/.local/share/agent-gateway/machine-client-ca.pem >> certs/client-ca-bundle.pem`).
3. Start the gateway (`cargo run -- --config config.toml`), then return to the terminal running `connect.sh` and press Enter to start the sidecar and Claude.

On later runs, start the gateway first, run `connect.sh`, and press Enter after confirming the machine CA is still registered. `--regenerate-certs` creates a fresh simulated TPM state and machine client CA, so the new CA must be appended to `client_ca_path`.

Pass a custom policy extension value: `connect.sh ... --extension-value agent-beta`.

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
