#!/usr/bin/env bash
# Demo gateway server TLS only: certs/server-ca*.pem and certs/server*.pem.

set -euo pipefail

DIR="certs"

mkdir -p "$DIR"

echo "==> Generating server CA"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "$DIR/server-ca-key.pem" -out "$DIR/server-ca.pem" \
    -days 365 -nodes -subj "/CN=agent-gateway server CA" 2>/dev/null

echo "==> Generating gateway server cert (localhost / 127.0.0.1)"
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "$DIR/server-key.pem" -out "$DIR/server.csr" \
    -nodes -subj "/CN=localhost" 2>/dev/null
openssl x509 -req -in "$DIR/server.csr" \
    -CA "$DIR/server-ca.pem" -CAkey "$DIR/server-ca-key.pem" -CAcreateserial \
    -out "$DIR/server.pem" -days 365 \
    -extfile <(printf 'subjectAltName=DNS:localhost,IP:127.0.0.1') 2>/dev/null
rm -f "$DIR/server.csr" "$DIR/server-ca.srl"

echo ""
echo "Generated in $DIR/:"
ls -1 "$DIR"
