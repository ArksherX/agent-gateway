#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "Usage: $0 SIGNING_KEY_ID DESTINATION... [--valid-days DAYS]" >&2
  echo "Example: $0 org-alice api.anthropic.com example.com:443 --valid-days 30" >&2
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if [[ $# -lt 2 ]]; then
  usage
  exit 2
fi

SIGNING_KEY_ID="$1"
shift
VALID_DAYS=365
DESTINATIONS=()
DATABASE_URL="${AGENT_GATEWAY_DATABASE_URL:-${DATABASE_URL:-}}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --valid-days)
      [[ $# -ge 2 ]] || { echo "error: --valid-days requires a value" >&2; exit 2; }
      VALID_DAYS="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --*)
      echo "Unknown option: $1" >&2
      usage
      exit 2
      ;;
    *)
      DESTINATIONS+=("$1")
      shift
      ;;
  esac
done

if [[ -z "$DATABASE_URL" ]]; then
  echo "Set AGENT_GATEWAY_DATABASE_URL or DATABASE_URL" >&2
  exit 2
fi
if [[ ${#DESTINATIONS[@]} -eq 0 ]]; then
  echo "error: at least one destination is required" >&2
  usage
  exit 2
fi

command -v psql >/dev/null || { echo "psql is required" >&2; exit 1; }

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
    port="443"
    [[ -n "$host" ]] || { echo "empty destination host: $input" >&2; return 1; }
    printf '%s:%s\n' "$(printf '%s' "$host" | tr '[:upper:]' '[:lower:]')" "$port"
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

validate_port() {
  local port="$1"
  if [[ ! "$port" =~ ^[0-9]+$ ]] || (( port < 1 || port > 65535 )); then
    echo "invalid destination port: $port" >&2
    return 1
  fi
}

for destination in "${DESTINATIONS[@]}"; do
  normalized_destination="$(normalize_destination "$destination")"

  psql "$DATABASE_URL" \
    --set=ON_ERROR_STOP=1 \
    --set=signing_key_id="$SIGNING_KEY_ID" \
    --set=destination="$normalized_destination" \
    --set=valid_days="$VALID_DAYS" <<'SQL'
WITH input AS (
  SELECT
    :'signing_key_id'::text AS signing_key_id,
    :'destination'::text AS destination,
    :'valid_days'::int AS valid_days
),
refreshed AS (
  UPDATE principal_key_permissions p
  SET
    not_before = now(),
    not_after = now() + make_interval(days => input.valid_days),
    revoked_at = NULL,
    updated_at = now()
  FROM input
  WHERE p.signing_key_id = input.signing_key_id
    AND p.destination = input.destination
    AND p.revoked_at IS NULL
  RETURNING p.signing_key_id, p.destination, p.not_after
),
inserted AS (
  INSERT INTO principal_key_permissions (
    signing_key_id, destination, not_before, not_after, revoked_at
  )
  SELECT
    input.signing_key_id,
    input.destination,
    now(),
    now() + make_interval(days => input.valid_days),
    NULL
  FROM input
  WHERE NOT EXISTS (SELECT 1 FROM refreshed)
  RETURNING signing_key_id, destination, not_after
)
SELECT signing_key_id, destination, not_after FROM refreshed
UNION ALL
SELECT signing_key_id, destination, not_after FROM inserted;
SQL
done
