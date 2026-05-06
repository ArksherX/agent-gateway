#!/usr/bin/env bash
# Starts a persistent local sidecar backed by a simulated TPM, or runs Claude through it.

set -euo pipefail

LISTEN="127.0.0.1:3128"
EXTENSION_VALUE="agent-alpha"
SIDECAR_BIN=""
REGENERATE_CERTS=false
GATEWAY=""
GATEWAY_CA=""
PROMPT=""
STATE_DIR=""
WORK_DIR=""
TPM_HANDLE="0x81010004"
SWTPM_HOST="127.0.0.1"
SWTPM_PORT="2321"
COMMAND=""

usage() {
    cat <<'EOF'
Usage:
  connect.sh prepare-client --state-dir PATH [OPTIONS]
  connect.sh start-sidecar --state-dir PATH [OPTIONS]
  connect.sh prompt --state-dir PATH --prompt TEXT [--work-dir PATH]

Required:
  prepare-client: --state-dir PATH
  start-sidecar: --state-dir PATH --gateway HOST:PORT --gateway-ca PATH
  prompt:        --state-dir PATH --prompt TEXT

prepare-client options:
  --extension-value VALUE  (default: agent-alpha)
  --tpm-handle HANDLE      Persistent simulated TPM handle (default: 0x81010004)
  --swtpm-port PORT        swtpm server TCP port (default: 2321)
  --regenerate-certs

start-sidecar options:
  --extension-value VALUE  (default: agent-alpha)
  --listen ADDR:PORT
  --sidecar-bin PATH
  --tpm-handle HANDLE      Persistent simulated TPM handle (default: 0x81010004)
  --swtpm-port PORT        swtpm server TCP port (default: 2321)
  --regenerate-certs

prompt options:
  --work-dir PATH

General:
  -h, --help
EOF
    exit "${1:-0}"
}

need_arg() { [[ $# -ge 2 ]] || { echo "error: $1 requires a value" >&2; exit 1; }; }

[[ $# -gt 0 ]] || usage 1
COMMAND="$1"
shift

case "$COMMAND" in
    prepare-client)
        while [[ $# -gt 0 ]]; do
            case "$1" in
                --extension-value)  need_arg "$@"; EXTENSION_VALUE="$2"; shift 2 ;;
                --state-dir)        need_arg "$@"; STATE_DIR="$2"; shift 2 ;;
                --tpm-handle)       need_arg "$@"; TPM_HANDLE="$2"; shift 2 ;;
                --swtpm-port)       need_arg "$@"; SWTPM_PORT="$2"; shift 2 ;;
                --regenerate-certs) REGENERATE_CERTS=true; shift ;;
                -h|--help)          usage 0 ;;
                *)                  echo "Unknown prepare-client option: $1" >&2; usage 1 ;;
            esac
        done

        [[ -n "$STATE_DIR" ]]  || { echo "error: prepare-client requires --state-dir" >&2; usage 1; }
        ;;
    start-sidecar)
        while [[ $# -gt 0 ]]; do
            case "$1" in
                --gateway)          need_arg "$@"; GATEWAY="$2"; shift 2 ;;
                --gateway-ca)       need_arg "$@"; GATEWAY_CA="$2"; shift 2 ;;
                --extension-value)  need_arg "$@"; EXTENSION_VALUE="$2"; shift 2 ;;
                --listen)           need_arg "$@"; LISTEN="$2"; shift 2 ;;
                --sidecar-bin)      need_arg "$@"; SIDECAR_BIN="$2"; shift 2 ;;
                --state-dir)        need_arg "$@"; STATE_DIR="$2"; shift 2 ;;
                --tpm-handle)       need_arg "$@"; TPM_HANDLE="$2"; shift 2 ;;
                --swtpm-port)       need_arg "$@"; SWTPM_PORT="$2"; shift 2 ;;
                --regenerate-certs) REGENERATE_CERTS=true; shift ;;
                -h|--help)          usage 0 ;;
                *)                  echo "Unknown start-sidecar option: $1" >&2; usage 1 ;;
            esac
        done

        [[ -n "$STATE_DIR" ]]  || { echo "error: start-sidecar requires --state-dir" >&2; usage 1; }
        [[ -n "$GATEWAY" ]]    || { echo "error: --gateway is required" >&2; usage 1; }
        [[ -n "$GATEWAY_CA" ]] || { echo "error: --gateway-ca is required" >&2; usage 1; }
        [[ -f "$GATEWAY_CA" ]] || { echo "error: gateway CA file not found: $GATEWAY_CA" >&2; exit 1; }
        ;;
    prompt)
        while [[ $# -gt 0 ]]; do
            case "$1" in
                --state-dir) need_arg "$@"; STATE_DIR="$2"; shift 2 ;;
                --work-dir)  need_arg "$@"; WORK_DIR="$2"; shift 2 ;;
                --prompt)    need_arg "$@"; PROMPT="$2"; shift 2 ;;
                -h|--help)   usage 0 ;;
                *)           echo "Unknown prompt option: $1" >&2; usage 1 ;;
            esac
        done

        [[ -n "$STATE_DIR" ]] || { echo "error: prompt requires --state-dir" >&2; usage 1; }
        [[ -n "$PROMPT" ]] || { echo "error: prompt requires --prompt" >&2; usage 1; }
        ;;
    -h|--help)
        usage 0
        ;;
    *)
        echo "Unknown command: $COMMAND" >&2
        usage 1
        ;;
esac

if [[ "$COMMAND" != "prompt" ]]; then
    CERT_DIR="$STATE_DIR/client"
    SWTPM_DIR="$CERT_DIR/swtpm"
    SWTPM_CTRL_PORT=$((SWTPM_PORT + 1))
    TPM_TCTI="swtpm:host=$SWTPM_HOST,port=$SWTPM_PORT"
    mkdir -p "$CERT_DIR"
fi

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "error: required command not found: $1" >&2
        exit 1
    }
}

if [[ "$COMMAND" != "prompt" ]]; then
    for cmd in openssl swtpm tpm2_createprimary tpm2_evictcontrol tpm2_readpublic; do
        require_cmd "$cmd"
    done
fi

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
    if [[ ! -f "$CERT_DIR/machine-client-cert-signer-key.pem" ]]; then
        echo "==> Generating local certificate signer key"
        openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
            -keyout "$CERT_DIR/machine-client-cert-signer-key.pem" \
            -out "$CERT_DIR/machine-client-cert-signer.pem" \
            -days 365 -nodes -subj "/CN=agent-gateway local cert signer" 2>/dev/null
    fi

    echo "==> Preparing subject client certificate for simulated TPM key (extension_value=$EXTENSION_VALUE)"
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
        -key "$CERT_DIR/machine-client-cert-signer-key.pem" \
        -out "$CERT_DIR/machine-client.pem" -days 365 -extfile "$extfile" 2>/dev/null
    rm -f "$extfile"
}

port_open() {
    (echo > "/dev/tcp/$1/$2") >/dev/null 2>&1
}

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

run_prompt() {
    [[ -n "$STATE_DIR" ]] || { echo "error: --state-dir is required" >&2; exit 1; }
    [[ -n "$PROMPT" ]] || { echo "error: --prompt is required" >&2; exit 1; }
    require_cmd claude
    local proxy_file="$STATE_DIR/proxy_url"
    [[ -f "$proxy_file" ]] || { echo "error: sidecar state missing proxy_url: $proxy_file" >&2; exit 1; }

    PROXY_URL="$(<"$proxy_file")"
    WORK_DIR="${WORK_DIR:-$STATE_DIR/work}"
    mkdir -p "$WORK_DIR"
    CLAUDE_CURL_PERMISSIONS=(
        --allowedTools "Bash(curl *)"
    )

    if [[ -f "$STATE_DIR/claude_started" ]]; then
        (
            cd "$WORK_DIR"
            HTTP_PROXY="$PROXY_URL" HTTPS_PROXY="$PROXY_URL" CURL_CA_BUNDLE="${CURL_CA_BUNDLE:-}" SSL_CERT_FILE="${SSL_CERT_FILE:-}" claude "${CLAUDE_CURL_PERMISSIONS[@]}" -c -p "$PROMPT"
        )
    else
        (
            cd "$WORK_DIR"
            HTTP_PROXY="$PROXY_URL" HTTPS_PROXY="$PROXY_URL" CURL_CA_BUNDLE="${CURL_CA_BUNDLE:-}" SSL_CERT_FILE="${SSL_CERT_FILE:-}" claude "${CLAUDE_CURL_PERMISSIONS[@]}" -p "$PROMPT"
        )
        : > "$STATE_DIR/claude_started"
    fi
}

if [[ "$COMMAND" == "prompt" ]]; then
    run_prompt
    exit 0
fi

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
    nohup swtpm socket \
        --tpm2 \
        --tpmstate "dir=$SWTPM_DIR" \
        --server "type=tcp,bindaddr=$SWTPM_HOST,port=$SWTPM_PORT" \
        --ctrl "type=tcp,bindaddr=$SWTPM_HOST,port=$SWTPM_CTRL_PORT" \
        --flags startup-clear > "$STATE_DIR/swtpm.log" 2>&1 &
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

cert_matches_tpm_key() {
    [[ -f "$CERT_DIR/machine-client.pem" ]] || return 1
    openssl pkey -pubin -in "$CERT_DIR/machine-client-public.pem" -outform DER \
        > "$CERT_DIR/machine-client-public.der"
    openssl x509 -in "$CERT_DIR/machine-client.pem" -pubkey -noout \
        | openssl pkey -pubin -outform DER > "$CERT_DIR/machine-client-cert-public.der"
    cmp -s "$CERT_DIR/machine-client-public.der" "$CERT_DIR/machine-client-cert-public.der"
}

verify_cert_matches_tpm_key() {
    if ! cert_matches_tpm_key; then
        echo "error: machine-client.pem public key does not match simulated TPM key $TPM_HANDLE" >&2
        exit 1
    fi
}

write_subject_spki_der() {
    openssl x509 -in "$CERT_DIR/machine-client.pem" -pubkey -noout \
        | openssl pkey -pubin -outform DER > "$CERT_DIR/machine-client-spki.der"
}

start_swtpm
ensure_tpm_key

generate_certs
verify_cert_matches_tpm_key
write_subject_spki_der

mkdir -p "$STATE_DIR"
printf '%s\n' "$CERT_DIR" > "$STATE_DIR/cert_dir"
printf '%s\n' "$CERT_DIR/machine-client-spki.der" > "$STATE_DIR/subject_public_key_spki_der_path"
if [[ -n "$SWTPM_PID" ]]; then
    printf '%s\n' "$SWTPM_PID" > "$STATE_DIR/swtpm_pid"
fi

if [[ "$COMMAND" == "prepare-client" ]]; then
    printf '%s\n' "$CERT_DIR/machine-client-spki.der"
    exit 0
fi

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

nohup "$SIDECAR" \
    --listen "$LISTEN" \
    --gateway "$GATEWAY" \
    --client-cert "$CERT_DIR/machine-client.pem" \
    --tpm-tcti "$TPM_TCTI" \
    --tpm-key-handle "$TPM_HANDLE" \
    --ca-cert "$GATEWAY_CA" > "$STATE_DIR/sidecar.log" 2>&1 &
SIDECAR_PID=$!

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

mkdir -p "$STATE_DIR"
printf '%s\n' "$PROXY_URL" > "$STATE_DIR/proxy_url"
printf '%s\n' "$SIDECAR_PID" > "$STATE_DIR/sidecar_pid"
printf '%s\n' "$LISTEN" > "$STATE_DIR/listen"
printf '%s\n' "$CERT_DIR" > "$STATE_DIR/cert_dir"
printf '%s\n' "$CERT_DIR/machine-client-spki.der" > "$STATE_DIR/subject_public_key_spki_der_path"
if [[ -n "$SWTPM_PID" ]]; then
    printf '%s\n' "$SWTPM_PID" > "$STATE_DIR/swtpm_pid"
fi
