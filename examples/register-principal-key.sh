#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "Usage: $0 KEY_ID [PRIVATE_KEY_PATH] [VALID_DAYS]" >&2
  echo "Example: $0 org-alice certs/principals/org-alice.pem 365" >&2
}

if [[ $# -lt 1 || $# -gt 3 ]]; then
  usage
  exit 2
fi

KEY_ID="$1"
PRIVATE_KEY="${2:-certs/principals/${KEY_ID}.pem}"
VALID_DAYS="${3:-365}"
DATABASE_URL="${AGENT_GATEWAY_DATABASE_URL:-${DATABASE_URL:-}}"

if [[ -z "$DATABASE_URL" ]]; then
  echo "Set AGENT_GATEWAY_DATABASE_URL or DATABASE_URL" >&2
  exit 2
fi

command -v openssl >/dev/null || { echo "openssl is required" >&2; exit 1; }
command -v psql >/dev/null || { echo "psql is required" >&2; exit 1; }

mkdir -p "$(dirname "$PRIVATE_KEY")"
if [[ ! -f "$PRIVATE_KEY" ]]; then
  openssl ecparam -name prime256v1 -genkey -noout -out "$PRIVATE_KEY"
  chmod 600 "$PRIVATE_KEY"
fi

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

public_der="$tmpdir/public.der"
openssl ec -in "$PRIVATE_KEY" -pubout -outform DER -out "$public_der" 2>/dev/null

hex_file() {
  od -An -tx1 -v "$1" | tr -d ' \n'
}

PUBLIC_KEY_HEX="$(hex_file "$public_der")"

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

echo "Private key: $PRIVATE_KEY"
