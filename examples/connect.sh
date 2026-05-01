#!/usr/bin/env bash
# Per-machine client certs → $XDG_DATA_HOME/.../agent-gateway; then sidecar + claude. Dev: --gateway-ca certs/server-ca.pem

set -euo pipefail

LISTEN="127.0.0.1:3128"
EXTENSION_VALUE="agent-alpha"
SIDECAR_BIN=""
REGENERATE_CERTS=false
GATEWAY=""
GATEWAY_CA=""

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
        --regenerate-certs) REGENERATE_CERTS=true; shift ;;
        -h|--help)          usage 0 ;;
        *)                  echo "Unknown option: $1" >&2; usage 1 ;;
    esac
done

[[ -n "$GATEWAY" ]]    || { echo "error: --gateway is required" >&2; usage 1; }
[[ -n "$GATEWAY_CA" ]] || { echo "error: --gateway-ca is required" >&2; usage 1; }
[[ -f "$GATEWAY_CA" ]] || { echo "error: gateway CA file not found: $GATEWAY_CA" >&2; exit 1; }

CERT_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/agent-gateway"
mkdir -p "$CERT_DIR"

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
    echo "==> Generating per-machine client CA"
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -keyout "$CERT_DIR/machine-client-ca-key.pem" -out "$CERT_DIR/machine-client-ca.pem" \
        -days 365 -nodes -subj "/CN=agent-gateway machine client CA" 2>/dev/null

    echo "==> Generating machine client certificate (extension_value=$EXTENSION_VALUE)"
    local der_hex
    der_hex=$(der_utf8string "$EXTENSION_VALUE")
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -keyout "$CERT_DIR/machine-client-key.pem" -out "$CERT_DIR/machine-client.csr" \
        -nodes -subj "/CN=machine-client" 2>/dev/null
    openssl x509 -req -in "$CERT_DIR/machine-client.csr" \
        -CA "$CERT_DIR/machine-client-ca.pem" -CAkey "$CERT_DIR/machine-client-ca-key.pem" -CAcreateserial \
        -out "$CERT_DIR/machine-client.pem" -days 365 \
        -extfile <(printf '1.3.6.1.4.1.57264.1.1=DER:%s' "$der_hex") 2>/dev/null
    rm -f "$CERT_DIR/machine-client.csr" "$CERT_DIR/machine-client-ca.srl"
}

needs_certs() {
    [[ "$REGENERATE_CERTS" == "true" ]] && return 0
    for f in machine-client-ca.pem machine-client-ca-key.pem machine-client.pem machine-client-key.pem; do
        [[ -f "$CERT_DIR/$f" ]] || return 0
    done
    return 1
}

if needs_certs; then
    generate_certs
fi

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

SIDECAR_PID=""

cleanup() {
    if [[ -n "$SIDECAR_PID" ]]; then
        kill "$SIDECAR_PID" 2>/dev/null || true
        wait "$SIDECAR_PID" 2>/dev/null || true
    fi
}

trap cleanup EXIT

"$SIDECAR" \
    --listen "$LISTEN" \
    --gateway "$GATEWAY" \
    --client-cert "$CERT_DIR/machine-client.pem" \
    --client-key "$CERT_DIR/machine-client-key.pem" \
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
