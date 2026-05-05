#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "Usage: $0 SIGNING_KEY_ID SUBJECT_IDENTITY SUBJECT_PUBLIC_KEY_SPKI_DER DESTINATION [VALID_DAYS] [PERMISSION_ID]" >&2
  echo "Example: $0 org-alice agent-alpha ./machine-client-spki.der api.anthropic.com 30" >&2
  echo "SUBJECT_PUBLIC_KEY_SPKI_DER may be a DER file path or lowercase/uppercase hex." >&2
  echo >&2
  echo "Environment:" >&2
  echo "  AGENT_GATEWAY_DATABASE_URL or DATABASE_URL must point at Postgres." >&2
  echo "  TPM2_PKCS11_STORE defaults to \$HOME/.tpm2_pkcs11." >&2
  echo "  TPM2_PKCS11_MODULE may override libtpm2_pkcs11.so discovery." >&2
  echo "  AGENT_GATEWAY_TPM_TOKEN_LABEL defaults to agent-gateway." >&2
  echo "  AGENT_GATEWAY_TPM_USER_PIN avoids the PIN prompt." >&2
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if [[ $# -lt 4 || $# -gt 6 ]]; then
  usage
  exit 2
fi

SIGNING_KEY_ID="$1"
SUBJECT_IDENTITY="$2"
SUBJECT_PUBLIC_KEY_SPKI_DER="$3"
DESTINATION="$4"
VALID_DAYS="${5:-30}"
DATABASE_URL="${AGENT_GATEWAY_DATABASE_URL:-${DATABASE_URL:-}}"
TPM2_PKCS11_STORE="${TPM2_PKCS11_STORE:-$HOME/.tpm2_pkcs11}"
TOKEN_LABEL="${AGENT_GATEWAY_TPM_TOKEN_LABEL:-agent-gateway}"
USER_PIN="${AGENT_GATEWAY_TPM_USER_PIN:-}"
export TPM2_PKCS11_STORE

if [[ -n "${6:-}" ]]; then
  PERMISSION_ID="$6"
else
  PERMISSION_ID="perm-${SIGNING_KEY_ID}-$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
fi

if [[ -z "$DATABASE_URL" ]]; then
  echo "Set AGENT_GATEWAY_DATABASE_URL or DATABASE_URL" >&2
  exit 2
fi

command -v pkcs11-tool >/dev/null || { echo "pkcs11-tool is required" >&2; exit 1; }
command -v openssl >/dev/null || { echo "openssl is required" >&2; exit 1; }
command -v psql >/dev/null || { echo "psql is required" >&2; exit 1; }
command -v od >/dev/null || { echo "od is required" >&2; exit 1; }

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

canonical_file="$tmpdir/canonical.txt"
digest_file="$tmpdir/canonical.sha256"
signature_raw="$tmpdir/signature.raw"
signature_der="$tmpdir/signature.der"

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

subject_spki_hex() {
  local input="$1"
  local hex
  if [[ -f "$input" ]]; then
    hex="$(hex_file "$input")"
  else
    hex="$(printf '%s' "$input" | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')"
  fi

  if [[ -z "$hex" || $(( ${#hex} % 2 )) -ne 0 || ! "$hex" =~ ^[0-9a-f]+$ ]]; then
    echo "subject public key SPKI DER must be a file path or even-length hex" >&2
    return 1
  fi
  printf '%s\n' "$hex"
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

validate_port() {
  local port="$1"
  if [[ ! "$port" =~ ^[0-9]+$ ]] || (( port < 1 || port > 65535 )); then
    echo "invalid destination port: $port" >&2
    return 1
  fi
}

normalize_destination() {
  local input="$1"
  local trimmed host port rest colon_count
  trimmed="$(printf '%s' "$input" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
  if [[ -z "$trimmed" ]]; then
    echo "empty destination" >&2
    return 1
  fi

  if [[ "$trimmed" == \[* ]]; then
    host="${trimmed#\[}"
    host="${host%%\]*}"
    rest="${trimmed#*\]}"
    if [[ "$rest" == :* ]]; then
      port="${rest#:}"
    elif [[ -z "$rest" ]]; then
      port="443"
    else
      echo "invalid bracketed destination: $input" >&2
      return 1
    fi
    [[ -n "$host" ]] || { echo "empty destination host: $input" >&2; return 1; }
    validate_port "$port" || return 1
    printf '[%s]:%s\n' "$(printf '%s' "$host" | tr '[:upper:]' '[:lower:]')" "$port"
    return
  fi

  colon_count="$(awk -F: '{ print NF - 1 }' <<<"$trimmed")"
  if [[ "$colon_count" -eq 0 ]]; then
    host="$trimmed"
    printf '%s:443\n' "$(printf '%s' "$host" | tr '[:upper:]' '[:lower:]')"
  elif [[ "$colon_count" -eq 1 ]]; then
    host="${trimmed%:*}"
    port="${trimmed##*:}"
    [[ -n "$host" ]] || { echo "empty destination host: $input" >&2; return 1; }
    validate_port "$port" || return 1
    printf '%s:%s\n' "$(printf '%s' "$host" | tr '[:upper:]' '[:lower:]')" "$port"
  else
    printf '[%s]:443\n' "$(printf '%s' "$trimmed" | tr '[:upper:]' '[:lower:]')"
  fi
}

is_der_ecdsa_signature() {
  local file="$1"
  local first_byte
  first_byte="$(od -An -tx1 -N1 "$file" | tr -d ' \n')"
  [[ "$first_byte" == "30" ]] && openssl asn1parse -inform DER -in "$file" -noout >/dev/null 2>&1
}

der_integer_hex() {
  local value="$1"
  while [[ ${#value} -gt 2 && "${value:0:2}" == "00" ]]; do
    value="${value:2}"
  done
  [[ -n "$value" ]] || value="00"

  local first_byte="${value:0:2}"
  if (( 16#$first_byte >= 128 )); then
    value="00$value"
  fi
  printf '%s\n' "$value"
}

raw_p256_signature_to_der() {
  local input="$1"
  local output="$2"
  local hex r s conf
  hex="$(hex_file "$input")"
  if [[ ${#hex} -ne 128 ]]; then
    echo "expected raw P-256 ECDSA signature to be 64 bytes, got $((${#hex} / 2)) bytes" >&2
    return 1
  fi

  r="$(der_integer_hex "${hex:0:64}")"
  s="$(der_integer_hex "${hex:64:64}")"
  conf="$tmpdir/ecdsa-signature.asn1"
  {
    printf 'asn1=SEQUENCE:sig\n'
    printf '[sig]\n'
    printf 'r=INTEGER:0x%s\n' "$r"
    printf 's=INTEGER:0x%s\n' "$s"
  } > "$conf"
  openssl asn1parse -genconf "$conf" -out "$output" -noout
}

normalize_signature_to_der() {
  local input="$1"
  local output="$2"
  local size
  if is_der_ecdsa_signature "$input"; then
    cp "$input" "$output"
    return
  fi

  size="$(wc -c < "$input" | tr -d ' ')"
  if [[ "$size" == "64" ]]; then
    raw_p256_signature_to_der "$input" "$output"
    return
  fi

  echo "signature is neither DER ECDSA nor raw 64-byte P-256 r||s" >&2
  return 1
}

sign_with_mechanism() {
  local mechanism="$1"
  local input_file="$2"
  local format
  for format in openssl sequence none; do
    rm -f "$signature_raw"
    if [[ "$format" == "none" ]]; then
      if run_pkcs11_tool \
        --module "$PKCS11_MODULE" \
        --token-label "$TOKEN_LABEL" \
        --login \
        --pin "$USER_PIN" \
        --sign \
        --mechanism "$mechanism" \
        --label "$SIGNING_KEY_ID" \
        --input-file "$input_file" \
        --output-file "$signature_raw"; then
        if normalize_signature_to_der "$signature_raw" "$signature_der"; then
          return 0
        fi
      fi
    elif run_pkcs11_tool \
      --module "$PKCS11_MODULE" \
      --token-label "$TOKEN_LABEL" \
      --login \
      --pin "$USER_PIN" \
      --sign \
      --mechanism "$mechanism" \
      --signature-format "$format" \
      --label "$SIGNING_KEY_ID" \
      --input-file "$input_file" \
      --output-file "$signature_raw"; then
      if normalize_signature_to_der "$signature_raw" "$signature_der"; then
        return 0
      fi
    fi
  done

  return 1
}

sign_permission() {
  if sign_with_mechanism ECDSA-SHA256 "$canonical_file"; then
    return
  fi
  if sign_with_mechanism ECDSA "$digest_file"; then
    return
  fi

  echo "failed to sign permission with TPM key label $SIGNING_KEY_ID" >&2
  return 1
}

PKCS11_MODULE="$(discover_pkcs11_module)"
if [[ -z "$USER_PIN" ]]; then
  USER_PIN="$(prompt_secret "TPM token user PIN: ")"
fi

NORMALIZED_DESTINATION="$(normalize_destination "$DESTINATION")"
SUBJECT_PUBLIC_KEY_SPKI_HEX="$(subject_spki_hex "$SUBJECT_PUBLIC_KEY_SPKI_DER")"
timestamp_row="$(
  psql "$DATABASE_URL" \
    --set=ON_ERROR_STOP=1 \
    --set=valid_days="$VALID_DAYS" \
    --no-align \
    --tuples-only \
    --field-separator='|' <<'SQL'
WITH bounds AS (
  SELECT now() AS not_before, now() + make_interval(days => :'valid_days'::int) AS not_after
)
SELECT
  to_char(not_before AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
  to_char(not_after AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
FROM bounds;
SQL
)"
IFS='|' read -r NOT_BEFORE NOT_AFTER <<< "$timestamp_row"

cat > "$canonical_file" <<EOF
agent-gateway-permission-v1
permission_id=$PERMISSION_ID
signing_key_id=$SIGNING_KEY_ID
subject_identity=$SUBJECT_IDENTITY
subject_public_key_spki_der=$SUBJECT_PUBLIC_KEY_SPKI_HEX
destination=$NORMALIZED_DESTINATION
not_before=$NOT_BEFORE
not_after=$NOT_AFTER
EOF

openssl dgst -sha256 -binary "$canonical_file" > "$digest_file"
sign_permission
SIGNATURE_HEX="$(hex_file "$signature_der")"

psql "$DATABASE_URL" \
  --set=ON_ERROR_STOP=1 \
  --set=permission_id="$PERMISSION_ID" \
  --set=signing_key_id="$SIGNING_KEY_ID" \
  --set=subject_identity="$SUBJECT_IDENTITY" \
  --set=subject_public_key_spki_der="$SUBJECT_PUBLIC_KEY_SPKI_HEX" \
  --set=destination="$NORMALIZED_DESTINATION" \
  --set=not_before="$NOT_BEFORE" \
  --set=not_after="$NOT_AFTER" \
  --set=signature="$SIGNATURE_HEX" <<'SQL'
INSERT INTO permission_registry (
  permission_id, signing_key_id, subject_identity, subject_public_key_spki_der, destination,
  not_before, not_after, revoked_at, signature
)
VALUES (
  :'permission_id',
  :'signing_key_id',
  :'subject_identity',
  decode(:'subject_public_key_spki_der', 'hex'),
  :'destination',
  :'not_before'::timestamptz,
  :'not_after'::timestamptz,
  NULL,
  decode(:'signature', 'hex')
)
ON CONFLICT (permission_id) DO UPDATE SET
  signing_key_id = EXCLUDED.signing_key_id,
  subject_identity = EXCLUDED.subject_identity,
  subject_public_key_spki_der = EXCLUDED.subject_public_key_spki_der,
  destination = EXCLUDED.destination,
  not_before = EXCLUDED.not_before,
  not_after = EXCLUDED.not_after,
  revoked_at = NULL,
  signature = EXCLUDED.signature,
  updated_at = now()
RETURNING permission_id, signing_key_id, subject_identity, destination, not_after;
SQL
