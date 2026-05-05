#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "Usage: $0 KEY_ID [VALID_DAYS]" >&2
  echo "Example: $0 org-alice 365" >&2
  echo >&2
  echo "Environment:" >&2
  echo "  AGENT_GATEWAY_DATABASE_URL or DATABASE_URL must point at Postgres." >&2
  echo "  TPM2_PKCS11_STORE defaults to \$HOME/.tpm2_pkcs11." >&2
  echo "  TPM2_PKCS11_MODULE may override libtpm2_pkcs11.so discovery." >&2
  echo "  AGENT_GATEWAY_TPM_TOKEN_LABEL defaults to agent-gateway." >&2
  echo "  AGENT_GATEWAY_TPM_USER_PIN and AGENT_GATEWAY_TPM_SO_PIN avoid PIN prompts." >&2
  echo "  AGENT_GATEWAY_RESET_TPM_STORE=true recreates the local tpm2-pkcs11 store." >&2
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if [[ $# -lt 1 || $# -gt 2 ]]; then
  usage
  exit 2
fi

KEY_ID="$1"
VALID_DAYS="${2:-365}"
DATABASE_URL="${AGENT_GATEWAY_DATABASE_URL:-${DATABASE_URL:-}}"
TPM2_PKCS11_STORE="${TPM2_PKCS11_STORE:-$HOME/.tpm2_pkcs11}"
TOKEN_LABEL="${AGENT_GATEWAY_TPM_TOKEN_LABEL:-agent-gateway}"
USER_PIN="${AGENT_GATEWAY_TPM_USER_PIN:-}"
SO_PIN="${AGENT_GATEWAY_TPM_SO_PIN:-}"
RESET_TPM_STORE="${AGENT_GATEWAY_RESET_TPM_STORE:-false}"
export TPM2_PKCS11_STORE

if [[ -z "$DATABASE_URL" ]]; then
  echo "Set AGENT_GATEWAY_DATABASE_URL or DATABASE_URL" >&2
  exit 2
fi

command -v tpm2_ptool >/dev/null || { echo "tpm2_ptool is required" >&2; exit 1; }
command -v pkcs11-tool >/dev/null || { echo "pkcs11-tool is required" >&2; exit 1; }
command -v openssl >/dev/null || { echo "openssl is required" >&2; exit 1; }
command -v psql >/dev/null || { echo "psql is required" >&2; exit 1; }

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

public_der="$tmpdir/public.der"
public_spki_der="$tmpdir/public-spki.der"

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

prompt_secret() {
  local prompt="$1"
  local value
  read -r -s -p "$prompt" value
  echo >&2
  printf '%s\n' "$value"
}

hex_file() {
  od -An -tx1 -v "$1" | tr -d ' \n'
}

run_tpm2_ptool() {
  local warnings_filter="ignore::DeprecationWarning"
  if [[ -n "${PYTHONWARNINGS:-}" ]]; then
    PYTHONWARNINGS="${PYTHONWARNINGS},${warnings_filter}" tpm2_ptool "$@" 2> >(
      grep -v \
        -e 'CryptographyDeprecationWarning:' \
        -e 'from cryptography\.hazmat\.primitives\.ciphers\.' >&2
    )
  else
    PYTHONWARNINGS="$warnings_filter" tpm2_ptool "$@" 2> >(
      grep -v \
        -e 'CryptographyDeprecationWarning:' \
        -e 'from cryptography\.hazmat\.primitives\.ciphers\.' >&2
    )
  fi
}

filter_tpm2_ptool_stderr() {
  grep -v \
    -e 'CryptographyDeprecationWarning:' \
    -e 'from cryptography\.hazmat\.primitives\.ciphers\.' \
    -e '^[[:space:]]*(TPM2_ALG\.CFB, modes\.CFB),'
}

run_tpm2_ptool_quiet() {
  local warnings_filter="ignore::DeprecationWarning"
  if [[ -n "${PYTHONWARNINGS:-}" ]]; then
    PYTHONWARNINGS="${PYTHONWARNINGS},${warnings_filter}" tpm2_ptool "$@" 2> >(filter_tpm2_ptool_stderr >/dev/null)
  else
    PYTHONWARNINGS="$warnings_filter" tpm2_ptool "$@" 2> >(filter_tpm2_ptool_stderr >/dev/null)
  fi
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

create_token() {
  local init_output primary_id
  init_output="$(run_tpm2_ptool init --path "$TPM2_PKCS11_STORE")"
  primary_id="$(printf '%s\n' "$init_output" | awk -F': *' '$1 == "id" { print $2; exit }')"
  if [[ -z "$primary_id" ]]; then
    echo "Could not determine tpm2-pkcs11 primary id from tpm2_ptool init output" >&2
    exit 1
  fi
  if [[ -z "$SO_PIN" ]]; then
    SO_PIN="$(prompt_secret "New TPM token SO PIN: ")"
  fi
  run_tpm2_ptool addtoken \
    --path "$TPM2_PKCS11_STORE" \
    --pid "$primary_id" \
    --sopin "$SO_PIN" \
    --userpin "$USER_PIN" \
    --label "$TOKEN_LABEL"
}

reset_store() {
  local backup
  backup="${TPM2_PKCS11_STORE}.stale.$(date +%Y%m%d%H%M%S)"
  if [[ -e "$TPM2_PKCS11_STORE" ]]; then
    mv "$TPM2_PKCS11_STORE" "$backup"
    echo "Moved stale tpm2-pkcs11 store to $backup" >&2
  fi
  mkdir -p "$TPM2_PKCS11_STORE"
  create_token
}

ensure_token() {
  if [[ "$RESET_TPM_STORE" == "true" ]]; then
    reset_store
    return
  fi

  mkdir -p "$TPM2_PKCS11_STORE"
  if ! run_pkcs11_tool --module "$PKCS11_MODULE" --token-label "$TOKEN_LABEL" --list-objects >/dev/null 2>&1; then
    create_token
  fi
}

add_key() {
  local runner="${1:-run_tpm2_ptool}"
  "$runner" addkey \
    --path "$TPM2_PKCS11_STORE" \
    --label "$TOKEN_LABEL" \
    --userpin "$USER_PIN" \
    --algorithm ecc256 \
    --key-label "$KEY_ID"
}

PKCS11_MODULE="$(discover_pkcs11_module)"

if [[ -z "$USER_PIN" ]]; then
  USER_PIN="$(prompt_secret "TPM token user PIN: ")"
fi

ensure_token

if ! run_pkcs11_tool \
  --module "$PKCS11_MODULE" \
  --token-label "$TOKEN_LABEL" \
  --login \
  --pin "$USER_PIN" \
  --read-object \
  --type pubkey \
  --label "$KEY_ID" \
  --output-file "$public_der" >/dev/null 2>&1; then
  if ! add_key run_tpm2_ptool_quiet; then
    echo "Could not add TPM key with the existing local tpm2-pkcs11 store; recreating it and retrying once." >&2
    reset_store
    add_key
  fi

  run_pkcs11_tool \
    --module "$PKCS11_MODULE" \
    --token-label "$TOKEN_LABEL" \
    --login \
    --pin "$USER_PIN" \
    --read-object \
    --type pubkey \
    --label "$KEY_ID" \
    --output-file "$public_der"
fi

openssl pkey -pubin -inform DER -in "$public_der" -pubout -outform DER -out "$public_spki_der" 2>/dev/null
PUBLIC_KEY_HEX="$(hex_file "$public_spki_der")"

psql "$DATABASE_URL" \
  --set=ON_ERROR_STOP=1 \
  --set=key_id="$KEY_ID" \
  --set=public_key_spki_der="$PUBLIC_KEY_HEX" \
  --set=valid_days="$VALID_DAYS" <<'SQL'
WITH input AS (
  SELECT
    :'key_id'::text AS key_id,
    decode(:'public_key_spki_der', 'hex') AS public_key_spki_der,
    :'valid_days'::int AS valid_days
)
INSERT INTO principal_signing_keys (
  key_id, algorithm, public_key_spki_der,
  not_before, not_after, revoked_at
)
SELECT
  key_id, 'ecdsa_p256_sha256', public_key_spki_der,
  now(), now() + make_interval(days => valid_days), NULL
FROM input
ON CONFLICT (key_id) DO UPDATE SET
  public_key_spki_der = EXCLUDED.public_key_spki_der,
  not_before = now(),
  not_after = EXCLUDED.not_after,
  revoked_at = NULL,
  updated_at = now()
RETURNING key_id, not_after;
SQL

echo "TPM token: $TOKEN_LABEL"
echo "TPM key label: $KEY_ID"
