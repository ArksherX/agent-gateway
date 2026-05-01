#!/usr/bin/env bash
# Per-machine client certs → $XDG_DATA_HOME/.../agent-gateway; then sidecar + claude. Dev: --gateway-ca certs/server-ca.pem

set -euo pipefail

LISTEN="127.0.0.1:3128"
EXTENSION_VALUE="agent-alpha"
SIDECAR_BIN=""
REGENERATE_CERTS=false
GATEWAY=""
GATEWAY_CA=""
TPM_HANDLE="0x81010004"
SWTPM_HOST="127.0.0.1"
SWTPM_PORT="2321"

usage() {
    cat <<'EOF'
Usage: connect.sh [OPTIONS]

Required:
  --gateway HOST:PORT Gateway address
  --gateway-ca PATH CA that issued tls_cert_path (dev: certs/server-ca.pem)

Optional:
  --extension-value VALUE  (default: agent-alpha)
  --listen ADDR:PORT
  --sidecar-bin PATH
  --tpm-handle HANDLE      Persistent simulated TPM handle (default: 0x81010004)
  --swtpm-port PORT        swtpm server TCP port (default: 2321)
  --regenerate-certs
  -h, --help
EOF
    exit "${1:-0}"
}

need_arg() { [[ $# -ge 2 ]] || { echo "error: $1 requires a value" >&2; exit 1; }; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --gateway)          need_arg "$@"; GATEWAY="$2"; shift 2 ;;
        --gateway-ca)       need_arg "$@"; GATEWAY_CA="$2"; shift 2 ;;
        --extension-value)  need_arg "$@"; EXTENSION_VALUE="$2"; shift 2 ;;
        --listen)           need_arg "$@"; LISTEN="$2"; shift 2 ;;
        --sidecar-bin)      need_arg "$@"; SIDECAR_BIN="$2"; shift 2 ;;
        --tpm-handle)       need_arg "$@"; TPM_HANDLE="$2"; shift 2 ;;
        --swtpm-port)       need_arg "$@"; SWTPM_PORT="$2"; shift 2 ;;
        --regenerate-certs) REGENERATE_CERTS=true; shift ;;
        -h|--help)          usage 0 ;;
        *)                  echo "Unknown option: $1" >&2; usage 1 ;;
    esac
done

[[ -n "$GATEWAY" ]]    || { echo "error: --gateway is required" >&2; usage 1; }
[[ -n "$GATEWAY_CA" ]] || { echo "error: --gateway-ca is required" >&2; usage 1; }
[[ -f "$GATEWAY_CA" ]] || { echo "error: gateway CA file not found: $GATEWAY_CA" >&2; exit 1; }

CERT_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/agent-gateway"
SWTPM_DIR="$CERT_DIR/swtpm"
SWTPM_CTRL_PORT=$((SWTPM_PORT + 1))
TPM_TCTI="swtpm:host=$SWTPM_HOST,port=$SWTPM_PORT"
mkdir -p "$CERT_DIR"

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "error: required command not found: $1" >&2
        exit 1
    }
}

for cmd in openssl swtpm tpm2_createprimary tpm2_evictcontrol tpm2_readpublic; do
    require_cmd "$cmd"
done

tpm2() {
    TPM2TOOLS_TCTI="$TPM_TCTI" "$@"
}

der_utf8string() {
    local val="$1"
    local len=${#val}
    local result
    result=$(printf '0c:%02x' "$len")
    for (( i=0; i<len; i++ )); do
        result=$(printf '%s:%02x' "$result" "'${val:$i:1}")
    done
    printf '%s' "$result"
}

generate_certs() {
    if [[ ! -f "$CERT_DIR/machine-client-ca.pem" || ! -f "$CERT_DIR/machine-client-ca-key.pem" ]]; then
        echo "==> Generating per-machine client CA"
        openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
            -keyout "$CERT_DIR/machine-client-ca-key.pem" -out "$CERT_DIR/machine-client-ca.pem" \
            -days 365 -nodes -subj "/CN=agent-gateway machine client CA" 2>/dev/null
    fi

    echo "==> Issuing machine client certificate for simulated TPM key (extension_value=$EXTENSION_VALUE)"
    local der_hex
    der_hex=$(der_utf8string "$EXTENSION_VALUE")
    local extfile="$CERT_DIR/machine-client.ext"
    {
        printf 'keyUsage=digitalSignature\n'
        printf 'extendedKeyUsage=clientAuth\n'
        printf '1.3.6.1.4.1.57264.1.1=DER:%s\n' "$der_hex"
    } > "$extfile"
    openssl x509 -new -force_pubkey "$CERT_DIR/machine-client-public.pem" \
        -subj "/CN=machine-client" \
        -CA "$CERT_DIR/machine-client-ca.pem" -CAkey "$CERT_DIR/machine-client-ca-key.pem" -CAcreateserial \
        -out "$CERT_DIR/machine-client.pem" -days 365 -extfile "$extfile" 2>/dev/null
    rm -f "$CERT_DIR/machine-client-ca.srl" "$extfile"
}

needs_certs() {
    [[ "$REGENERATE_CERTS" == "true" ]] && return 0
    for f in machine-client-ca.pem machine-client-ca-key.pem machine-client.pem machine-client-public.pem; do
        [[ -f "$CERT_DIR/$f" ]] || return 0
    done
    return 1
}

port_open() {
    (echo > "/dev/tcp/$1/$2") >/dev/null 2>&1
}

SWTPM_PID=""
SIDECAR_PID=""

start_swtpm() {
    if [[ "$REGENERATE_CERTS" == "true" ]]; then
        if port_open "$SWTPM_HOST" "$SWTPM_PORT"; then
            echo "error: cannot regenerate simulated TPM state while $SWTPM_HOST:$SWTPM_PORT is already in use" >&2
            exit 1
        fi
        rm -rf "$SWTPM_DIR"
    fi

    mkdir -p "$SWTPM_DIR"
    if port_open "$SWTPM_HOST" "$SWTPM_PORT"; then
        echo "==> Using existing swtpm at $TPM_TCTI"
        return
    fi

    echo "==> Starting swtpm at $TPM_TCTI"
    swtpm socket \
        --tpm2 \
        --tpmstate "dir=$SWTPM_DIR" \
        --server "type=tcp,bindaddr=$SWTPM_HOST,port=$SWTPM_PORT" \
        --ctrl "type=tcp,bindaddr=$SWTPM_HOST,port=$SWTPM_CTRL_PORT" \
        --flags startup-clear &
    SWTPM_PID=$!

    for _ in $(seq 1 50); do
        port_open "$SWTPM_HOST" "$SWTPM_PORT" && return
        if ! kill -0 "$SWTPM_PID" 2>/dev/null; then
            echo "error: swtpm exited unexpectedly" >&2
            wait "$SWTPM_PID" 2>/dev/null || true
            SWTPM_PID=""
            exit 1
        fi
        sleep 0.1
    done

    echo "error: swtpm did not become ready within 5 seconds" >&2
    exit 1
}

ensure_tpm_key() {
    if tpm2 tpm2_readpublic -Q -c "$TPM_HANDLE" -f pem -o "$CERT_DIR/machine-client-public.pem" 2>/dev/null; then
        echo "==> Using simulated TPM key $TPM_HANDLE"
        return
    fi

    echo "==> Creating simulated TPM P-256 signing key at $TPM_HANDLE"
    tpm2 tpm2_createprimary -Q -C o -g sha256 -G ecc256:ecdsa \
        -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign" \
        -c "$CERT_DIR/tpm-signing-key.ctx"
    tpm2 tpm2_evictcontrol -Q -C o -c "$CERT_DIR/tpm-signing-key.ctx" "$TPM_HANDLE"
    tpm2 tpm2_readpublic -Q -c "$TPM_HANDLE" -f pem -o "$CERT_DIR/machine-client-public.pem"
    rm -f "$CERT_DIR/tpm-signing-key.ctx"
}

verify_cert_matches_tpm_key() {
    openssl pkey -pubin -in "$CERT_DIR/machine-client-public.pem" -outform DER \
        > "$CERT_DIR/machine-client-public.der"
    openssl x509 -in "$CERT_DIR/machine-client.pem" -pubkey -noout \
        | openssl pkey -pubin -outform DER > "$CERT_DIR/machine-client-cert-public.der"
    if ! cmp -s "$CERT_DIR/machine-client-public.der" "$CERT_DIR/machine-client-cert-public.der"; then
        echo "error: machine-client.pem public key does not match simulated TPM key $TPM_HANDLE" >&2
        exit 1
    fi
}

start_swtpm
ensure_tpm_key

if needs_certs; then
    generate_certs
fi
verify_cert_matches_tpm_key

echo "Append $CERT_DIR/machine-client-ca.pem to client_ca_path; restart gateway."
read -r -p "Press Enter when done. " _

find_sidecar() {
    if [[ -n "$SIDECAR_BIN" ]]; then
        if [[ ! -x "$SIDECAR_BIN" ]]; then
            echo "error: sidecar binary not found or not executable: $SIDECAR_BIN" >&2
            exit 1
        fi
        printf '%s' "$SIDECAR_BIN"
        return
    fi

    if command -v agent_gateway_sidecar &>/dev/null; then
        command -v agent_gateway_sidecar
        return
    fi

    local candidates=(
        "./target/release/agent_gateway_sidecar"
        "./target/debug/agent_gateway_sidecar"
    )
    for candidate in "${candidates[@]}"; do
        if [[ -x "$candidate" ]]; then
            printf '%s' "$candidate"
            return
        fi
    done

    echo "error: could not find agent_gateway_sidecar binary" >&2
    echo "hint: build with 'cargo build -p agent_gateway_sidecar' or pass --sidecar-bin" >&2
    exit 1
}

SIDECAR="$(find_sidecar)"

cleanup() {
    if [[ -n "$SIDECAR_PID" ]]; then
        kill "$SIDECAR_PID" 2>/dev/null || true
        wait "$SIDECAR_PID" 2>/dev/null || true
    fi
    if [[ -n "$SWTPM_PID" ]]; then
        kill "$SWTPM_PID" 2>/dev/null || true
        wait "$SWTPM_PID" 2>/dev/null || true
    fi
}

trap cleanup EXIT

"$SIDECAR" \
    --listen "$LISTEN" \
    --gateway "$GATEWAY" \
    --client-cert "$CERT_DIR/machine-client.pem" \
    --tpm-tcti "$TPM_TCTI" \
    --tpm-key-handle "$TPM_HANDLE" \
    --ca-cert "$GATEWAY_CA" &
SIDECAR_PID=$!

parse_listen_addr() {
    local addr="$1"
    if [[ "$addr" == \[* ]]; then
        LISTEN_HOST="${addr%%\]:*}"
        LISTEN_HOST="${LISTEN_HOST#\[}"
        LISTEN_PORT="${addr##*\]:}"
    else
        LISTEN_HOST="${addr%:*}"
        LISTEN_PORT="${addr##*:}"
    fi
}

parse_listen_addr "$LISTEN"

echo "Waiting for sidecar on $LISTEN..."
for _ in $(seq 1 50); do
    if (echo > "/dev/tcp/$LISTEN_HOST/$LISTEN_PORT") 2>/dev/null; then
        break
    fi
    if ! kill -0 "$SIDECAR_PID" 2>/dev/null; then
        echo "error: sidecar exited unexpectedly" >&2
        wait "$SIDECAR_PID" 2>/dev/null || true
        SIDECAR_PID=""
        exit 1
    fi
    sleep 0.1
done

if ! (echo > "/dev/tcp/$LISTEN_HOST/$LISTEN_PORT") 2>/dev/null; then
    echo "error: sidecar did not become ready within 5 seconds" >&2
    exit 1
fi

echo "Sidecar ready on $LISTEN"

PROXY_URL="http://$LISTEN"

HTTP_PROXY="$PROXY_URL" \
HTTPS_PROXY="$PROXY_URL" \
    claude
