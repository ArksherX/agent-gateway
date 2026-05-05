#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
STATE_ROOT="${AGENT_GATEWAY_DEMO_STATE_DIR:-${XDG_STATE_HOME:-$HOME/.local/state}/agent-gateway/demo-agents}"
DEFAULT_VALID_DAYS="${AGENT_GATEWAY_PERMISSION_VALID_DAYS:-30}"
DEFAULT_GATEWAY="${AGENT_GATEWAY_DEMO_GATEWAY:-127.0.0.1:8443}"
DEFAULT_GATEWAY_CA="${AGENT_GATEWAY_DEMO_GATEWAY_CA:-$REPO_ROOT/certs/server-ca.pem}"
DEFAULT_LISTEN_HOST="${AGENT_GATEWAY_DEMO_LISTEN_HOST:-127.0.0.1}"
DEFAULT_LISTEN_PORT="${AGENT_GATEWAY_DEMO_LISTEN_PORT:-3128}"
DEFAULT_SWTPM_PORT="${AGENT_GATEWAY_DEMO_SWTPM_PORT:-2321}"
TPM2_PKCS11_STORE="${TPM2_PKCS11_STORE:-$HOME/.tpm2_pkcs11}"
TOKEN_LABEL="${AGENT_GATEWAY_TPM_TOKEN_LABEL:-agent-gateway}"
USER_PIN="${AGENT_GATEWAY_TPM_USER_PIN:-}"
export TPM2_PKCS11_STORE

usage() {
  cat >&2 <<'EOF'
Usage:
  demo-agent.sh create --identity AGENT_ID --grant DESTINATION [--grant DESTINATION ...]
  demo-agent.sh grant AGENT_HANDLE --grant DESTINATION [--grant DESTINATION ...]
  demo-agent.sh prompt AGENT_HANDLE --prompt TEXT

Environment:
  AGENT_GATEWAY_DEMO_GATEWAY defaults to 127.0.0.1:8443.
  AGENT_GATEWAY_DEMO_GATEWAY_CA defaults to certs/server-ca.pem.
  AGENT_GATEWAY_DEMO_STATE_DIR overrides the local agent handle directory.
  AGENT_GATEWAY_PERMISSION_VALID_DAYS defaults to 30.
  TPM2_PKCS11_STORE defaults to $HOME/.tpm2_pkcs11.
  AGENT_GATEWAY_TPM_TOKEN_LABEL defaults to agent-gateway.
  AGENT_GATEWAY_TPM_USER_PIN avoids the PIN prompt.
EOF
}

need_arg() { [[ $# -ge 2 ]] || { echo "error: $1 requires a value" >&2; exit 2; }; }

sanitize_handle() {
  printf '%s' "$1" | tr -cs 'A-Za-z0-9_.-' '-'
}

state_dir() {
  printf '%s/%s\n' "$STATE_ROOT" "$1"
}

prompt_secret() {
  local prompt="$1"
  local value
  read -r -s -p "$prompt" value
  echo >&2
  printf '%s\n' "$value"
}

discover_pkcs11_module() {
  if [[ -n "${TPM2_PKCS11_MODULE:-}" ]]; then
    printf '%s\n' "$TPM2_PKCS11_MODULE"
    return
  fi

  local candidate
  for candidate in \
    /usr/lib/libtpm2_pkcs11.so.0 \
    /usr/lib/libtpm2_pkcs11.so \
    /usr/lib/*/libtpm2_pkcs11.so.0 \
    /usr/lib/*/libtpm2_pkcs11.so \
    /usr/lib/*/pkcs11/libtpm2_pkcs11.so \
    /usr/local/lib/pkcs11/libtpm2_pkcs11.so \
    /usr/local/lib/libtpm2_pkcs11.so; do
    if [[ -e "$candidate" ]]; then
      printf '%s\n' "$candidate"
      return
    fi
  done

  echo "Set TPM2_PKCS11_MODULE to the path of libtpm2_pkcs11.so" >&2
  exit 2
}

run_pkcs11_tool() {
  pkcs11-tool "$@" 2> >(
    grep -v \
      -e '^WARNING:fapi:' \
      -e '^ERROR:fapi:.*Fapi_List' \
      -e '^ERROR:fapi:.*Entities_List' \
      -e '^WARNING: Listing FAPI token objects failed:' \
      -e '^Please see https://github.com/tpm2-software/tpm2-pkcs11/blob/.*/docs/FAPI.md' \
      -e '^WARNING: Getting tokens from fapi backend failed\.' >&2
  )
}

discover_principal() {
  command -v pkcs11-tool >/dev/null || { echo "pkcs11-tool is required" >&2; exit 1; }
  local module labels count
  module="$(discover_pkcs11_module)"
  if [[ -z "$USER_PIN" ]]; then
    USER_PIN="$(prompt_secret "TPM token user PIN: ")"
    export AGENT_GATEWAY_TPM_USER_PIN="$USER_PIN"
  fi
  labels="$(
    run_pkcs11_tool --module "$module" --token-label "$TOKEN_LABEL" --login --pin "$USER_PIN" --list-objects \
      | awk '
        /Private Key Object/ { in_private = 1; next }
        /Public Key Object/ { in_private = 0; next }
        in_private && /^[[:space:]]*label:/ {
          sub(/^[[:space:]]*label:[[:space:]]*/, "")
          if ($0 != "") print
        }
      ' \
      | sort -u
  )"
  count="$(printf '%s\n' "$labels" | sed '/^$/d' | wc -l | tr -d ' ')"
  if [[ "$count" -ne 1 ]]; then
    echo "expected exactly one TPM principal key label in token '$TOKEN_LABEL', found $count" >&2
    echo "hint: run ./examples/register-principal-key.sh KEY_ID first on this machine" >&2
    [[ -n "$labels" ]] && printf '%s\n' "$labels" >&2
    exit 1
  fi
  printf '%s\n' "$labels"
}

read_state() {
  local dir="$1"
  [[ -d "$dir" ]] || { echo "error: unknown agent handle: ${dir##*/}" >&2; exit 1; }
  PRINCIPAL="$(<"$dir/principal")"
  IDENTITY="$(<"$dir/identity")"
  VALID_DAYS="$(<"$dir/valid_days")"
  GATEWAY="$(<"$dir/gateway")"
  GATEWAY_CA="$(<"$dir/gateway_ca")"
  LISTEN="$(<"$dir/listen")"
  SWTPM_PORT="$(<"$dir/swtpm_port")"
  SUBJECT_PUBLIC_KEY_SPKI_DER="$(<"$dir/subject_public_key_spki_der_path")"
}

write_state() {
  local dir="$1"
  mkdir -p "$dir/work"
  printf '%s\n' "$PRINCIPAL" > "$dir/principal"
  printf '%s\n' "$IDENTITY" > "$dir/identity"
  printf '%s\n' "$VALID_DAYS" > "$dir/valid_days"
  printf '%s\n' "$GATEWAY" > "$dir/gateway"
  printf '%s\n' "$GATEWAY_CA" > "$dir/gateway_ca"
  printf '%s\n' "$LISTEN" > "$dir/listen"
  printf '%s\n' "$SWTPM_PORT" > "$dir/swtpm_port"
}

sidecar_running() {
  local dir="$1"
  [[ -f "$dir/sidecar_pid" ]] && kill -0 "$(<"$dir/sidecar_pid")" 2>/dev/null
}

ensure_sidecar() {
  local dir="$1"
  if sidecar_running "$dir"; then
    return
  fi

  "$SCRIPT_DIR/connect.sh" start-sidecar \
    --state-dir "$dir" \
    --gateway "$GATEWAY" \
    --gateway-ca "$GATEWAY_CA" \
    --extension-value "$IDENTITY" \
    --listen "$LISTEN" \
    --swtpm-port "$SWTPM_PORT" >&2
}

prepare_subject_certificate() {
  local dir="$1"
  "$SCRIPT_DIR/connect.sh" prepare-client \
    --state-dir "$dir" \
    --extension-value "$IDENTITY" \
    --swtpm-port "$SWTPM_PORT" >/dev/null
  SUBJECT_PUBLIC_KEY_SPKI_DER="$(<"$dir/subject_public_key_spki_der_path")"
}

grant_permissions() {
  local destination
  for destination in "${GRANTS[@]}"; do
    "$SCRIPT_DIR/register-permission.sh" \
      "$PRINCIPAL" \
      "$IDENTITY" \
      "$SUBJECT_PUBLIC_KEY_SPKI_DER" \
      "$destination" \
      "$VALID_DAYS" >&2
    printf '%s\n' "$destination" >> "$STATE_DIR_CURRENT/grants"
  done
}

cmd_create() {
  PRINCIPAL="$(discover_principal)"
  IDENTITY="agent-alpha"
  VALID_DAYS="$DEFAULT_VALID_DAYS"
  GATEWAY="$DEFAULT_GATEWAY"
  GATEWAY_CA="$DEFAULT_GATEWAY_CA"
  SWTPM_PORT="$DEFAULT_SWTPM_PORT"
  HANDLE=""
  GRANTS=()

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --identity) need_arg "$@"; IDENTITY="$2"; shift 2 ;;
      --grant) need_arg "$@"; GRANTS+=("$2"); shift 2 ;;
      --handle) need_arg "$@"; HANDLE="$2"; shift 2 ;;
      --valid-days) need_arg "$@"; VALID_DAYS="$2"; shift 2 ;;
      -h|--help) usage; exit 0 ;;
      *) echo "Unknown option: $1" >&2; usage; exit 2 ;;
    esac
  done

  [[ ${#GRANTS[@]} -gt 0 ]] || { echo "error: create requires at least one --grant" >&2; exit 2; }

  HANDLE="${HANDLE:-$(sanitize_handle "$IDENTITY")}"
  STATE_DIR_CURRENT="$(state_dir "$HANDLE")"
  LISTEN="$DEFAULT_LISTEN_HOST:$DEFAULT_LISTEN_PORT"
  mkdir -p "$STATE_DIR_CURRENT"
  : > "$STATE_DIR_CURRENT/grants"
  write_state "$STATE_DIR_CURRENT"
  prepare_subject_certificate "$STATE_DIR_CURRENT"
  grant_permissions
  ensure_sidecar "$STATE_DIR_CURRENT"

  echo "$HANDLE"
}

cmd_grant() {
  [[ $# -ge 1 ]] || { echo "error: grant requires AGENT_HANDLE" >&2; usage; exit 2; }
  HANDLE="$1"
  shift
  STATE_DIR_CURRENT="$(state_dir "$HANDLE")"
  read_state "$STATE_DIR_CURRENT"
  GRANTS=()

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --grant) need_arg "$@"; GRANTS+=("$2"); shift 2 ;;
      --valid-days) need_arg "$@"; VALID_DAYS="$2"; shift 2 ;;
      -h|--help) usage; exit 0 ;;
      *) echo "Unknown option: $1" >&2; usage; exit 2 ;;
    esac
  done

  [[ ${#GRANTS[@]} -gt 0 ]] || { echo "error: grant requires at least one --grant" >&2; exit 2; }
  printf '%s\n' "$VALID_DAYS" > "$STATE_DIR_CURRENT/valid_days"
  grant_permissions
}

cmd_prompt() {
  [[ $# -ge 1 ]] || { echo "error: prompt requires AGENT_HANDLE" >&2; usage; exit 2; }
  HANDLE="$1"
  shift
  STATE_DIR_CURRENT="$(state_dir "$HANDLE")"
  read_state "$STATE_DIR_CURRENT"
  PROMPT=""

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --prompt) need_arg "$@"; PROMPT="$2"; shift 2 ;;
      -h|--help) usage; exit 0 ;;
      *) echo "Unknown option: $1" >&2; usage; exit 2 ;;
    esac
  done

  [[ -n "$PROMPT" ]] || { echo "error: prompt requires --prompt" >&2; exit 2; }
  ensure_sidecar "$STATE_DIR_CURRENT"
  "$SCRIPT_DIR/connect.sh" prompt \
    --state-dir "$STATE_DIR_CURRENT" \
    --work-dir "$STATE_DIR_CURRENT/work" \
    --prompt "$PROMPT"
}

[[ $# -gt 0 ]] || { usage; exit 2; }
COMMAND="$1"
shift

case "$COMMAND" in
  create) cmd_create "$@" ;;
  grant) cmd_grant "$@" ;;
  prompt) cmd_prompt "$@" ;;
  -h|--help) usage ;;
  *) echo "Unknown command: $COMMAND" >&2; usage; exit 2 ;;
esac
