#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
COMPOSE_FILE="$REPO_ROOT/docker-compose.demo.yml"
COMPOSE_PROJECT_NAME="${AGENT_GATEWAY_DEMO_COMPOSE_PROJECT:-agent_gateway_demo}"
COMPOSE_CMD=()
COMPOSE_DISPLAY=""

PRINCIPAL="${AGENT_GATEWAY_DEMO_PRINCIPAL:-org-alice}"
IDENTITY="${AGENT_GATEWAY_DEMO_IDENTITY:-agent-alpha}"
HANDLE="${AGENT_GATEWAY_DEMO_HANDLE:-$IDENTITY}"
STATE_ROOT="${AGENT_GATEWAY_DEMO_STATE_DIR:-${XDG_STATE_HOME:-$HOME/.local/state}/agent-gateway/demo-agents}"
TPM2_PKCS11_STORE="${AGENT_GATEWAY_DEMO_TPM2_PKCS11_STORE:-$STATE_ROOT/tpm2-pkcs11}"
USER_PIN="${AGENT_GATEWAY_TPM_USER_PIN:-agentgateway}"
SO_PIN="${AGENT_GATEWAY_TPM_SO_PIN:-agentgateway-so}"
DATABASE_URL="${AGENT_GATEWAY_DATABASE_URL:-postgres://agent_gateway_admin:agent_gateway_dev@127.0.0.1:5432/agent_gateway}"
GATEWAY="${AGENT_GATEWAY_DEMO_GATEWAY:-127.0.0.1:8443}"
GATEWAY_CA="${AGENT_GATEWAY_DEMO_GATEWAY_CA:-$REPO_ROOT/certs/server-ca.pem}"
MOCK_CA="${AGENT_GATEWAY_DEMO_MOCK_CA:-$REPO_ROOT/certs/mock-ca.pem}"
SIDECAR_BIN="$REPO_ROOT/target/debug/agent_gateway_sidecar"
VERIFY_TIMEOUT_SECONDS="${AGENT_GATEWAY_DEMO_VERIFY_TIMEOUT_SECONDS:-120}"

export COMPOSE_PROJECT_NAME

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "error: required command not found: $1" >&2
    exit 1
  }
}

select_compose() {
  if command -v podman >/dev/null 2>&1; then
    if podman compose version >/dev/null 2>&1; then
      COMPOSE_CMD=(podman compose)
      COMPOSE_DISPLAY="podman compose"
      return
    fi
    if command -v podman-compose >/dev/null 2>&1; then
      COMPOSE_CMD=(podman-compose)
      COMPOSE_DISPLAY="podman-compose"
      return
    fi

    echo "error: podman is installed, but neither 'podman compose' nor 'podman-compose' is available" >&2
    exit 1
  fi

  if command -v docker >/dev/null 2>&1; then
    if docker compose version >/dev/null 2>&1; then
      COMPOSE_CMD=(docker compose)
      COMPOSE_DISPLAY="docker compose"
      return
    fi

    echo "error: docker is installed, but 'docker compose' is not available" >&2
    exit 1
  fi

  echo "error: install podman with compose support or docker with the compose plugin" >&2
  exit 1
}

compose() {
  "${COMPOSE_CMD[@]}" -p "$COMPOSE_PROJECT_NAME" -f "$COMPOSE_FILE" "$@"
}

wait_for_postgres() {
  echo "==> Waiting for Postgres"
  for _ in $(seq 1 60); do
    if psql "$DATABASE_URL" -tAc "SELECT 1" >/dev/null 2>&1; then
      return
    fi
    sleep 1
  done

  echo "error: Postgres did not become ready" >&2
  compose logs --no-color postgres >&2 || true
  exit 1
}

apply_migrations() {
  echo "==> Applying database migrations"
  if [[ "$(psql "$DATABASE_URL" -tAc "SELECT to_regclass('public.agent_gateway_schema_version') IS NOT NULL")" == "t" ]]; then
    echo "authorization registry already migrated"
    return
  fi

  psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f "$REPO_ROOT/migrations/0001_signed_authorization_registry.sql"
}

state_dir() {
  printf '%s/%s\n' "$STATE_ROOT" "$HANDLE"
}

print_verification_diagnostics() {
  local sidecar_log
  sidecar_log="$(state_dir)/sidecar.log"

  echo "Check the gateway, sidecar, and mock service logs before retrying." >&2
  echo "Sidecar log: $sidecar_log" >&2
  if [[ -f "$sidecar_log" ]]; then
    echo >&2
    echo "Recent sidecar log lines:" >&2
    tail -n 80 "$sidecar_log" >&2 || true
  fi
}

demo_env=(
  "AGENT_GATEWAY_DATABASE_URL=$DATABASE_URL"
  "AGENT_GATEWAY_DEMO_GATEWAY=$GATEWAY"
  "AGENT_GATEWAY_DEMO_GATEWAY_CA=$GATEWAY_CA"
  "AGENT_GATEWAY_DEMO_MOCK_CA=$MOCK_CA"
  "AGENT_GATEWAY_DEMO_SIDECAR_BIN=$SIDECAR_BIN"
  "AGENT_GATEWAY_DEMO_STATE_DIR=$STATE_ROOT"
  "AGENT_GATEWAY_TPM_USER_PIN=$USER_PIN"
  "AGENT_GATEWAY_TPM_SO_PIN=$SO_PIN"
  "AGENT_GATEWAY_RESET_TPM_STORE=false"
  "CLAUDE_CODE_PROXY_RESOLVES_HOSTS=1"
  "CURL_CA_BUNDLE=$MOCK_CA"
  "NODE_EXTRA_CA_CERTS=$MOCK_CA"
  "SSL_CERT_FILE=$MOCK_CA"
  "TPM2_PKCS11_STORE=$TPM2_PKCS11_STORE"
)

select_compose
require_cmd cargo
require_cmd openssl
require_cmd psql
require_cmd timeout

cd "$REPO_ROOT"

echo "==> Generating demo TLS certificates"
"$SCRIPT_DIR/generate-server-certs.sh"

if [[ ! -f "$REPO_ROOT/config.toml" ]]; then
  echo "==> Creating config.toml from config.example.toml"
  cp "$REPO_ROOT/config.example.toml" "$REPO_ROOT/config.toml"
fi

echo "==> Building local sidecar"
cargo build -p agent_gateway_sidecar

echo "==> Building gateway image"
compose build gateway

echo "==> Starting Postgres and mock HTTPS services"
compose up -d --force-recreate postgres mock-services
wait_for_postgres
apply_migrations

echo "==> Starting gateway"
compose up -d --force-recreate gateway

echo "==> Registering demo principal $PRINCIPAL"
env "${demo_env[@]}" "$REPO_ROOT/registry-cli/register-principal-key.sh" "$PRINCIPAL"

echo "==> Granting demo scopes"
env "${demo_env[@]}" "$REPO_ROOT/registry-cli/grant-principal-scope.sh" "$PRINCIPAL" docstore messaging api.anthropic.com

echo "==> Creating demo agent $HANDLE"
env "${demo_env[@]}" "$SCRIPT_DIR/demo-agent.sh" create \
  --identity "$IDENTITY" \
  --handle "$HANDLE" \
  --grant docstore \
  --grant api.anthropic.com \
  --grant messaging >/dev/null

echo "==> Verifying Claude Code HTTP requests through the gateway"
if ! timeout "$VERIFY_TIMEOUT_SECONDS" env "${demo_env[@]}" "$SCRIPT_DIR/demo-agent.sh" prompt "$HANDLE" --prompt \
  "Use the Bash tool to run exactly this command: curl -sS https://docstore/health
Return only the raw response body."; then
  cat >&2 <<EOF
error: Claude Code could not fetch https://docstore/health through the demo gateway.

Expected environment:
  HTTPS_PROXY=http://127.0.0.1:3128
  CURL_CA_BUNDLE=$MOCK_CA
  NODE_EXTRA_CA_CERTS=$MOCK_CA
  SSL_CERT_FILE=$MOCK_CA
  CLAUDE_CODE_PROXY_RESOLVES_HOSTS=1
  AGENT_GATEWAY_DEMO_SIDECAR_BIN=$SIDECAR_BIN

EOF
  print_verification_diagnostics
  exit 1
fi

rm -f "$(state_dir)/claude_started"

cat <<EOF

Demo is ready.

Mock service URLs available through the gateway:
  https://docstore/health
  https://docstore/documents
  https://messaging/health
  https://messaging/messages

Prompt the demo agent with:
  ./demo/demo-agent.sh prompt "$HANDLE" --prompt "Use the Bash tool to run exactly these commands: curl -sS https://docstore/documents and curl -sS https://messaging/messages. Then summarize what you found."

Useful logs:
  $COMPOSE_DISPLAY -p "$COMPOSE_PROJECT_NAME" -f docker-compose.demo.yml logs -f gateway
  $(state_dir)/sidecar.log
EOF
