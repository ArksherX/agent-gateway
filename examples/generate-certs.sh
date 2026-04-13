#!/usr/bin/env bash
# Generate a self-signed CA, proxy server cert, and client cert for local
# development. Writes PEM files to a certs/ directory (created if absent).
#
# Usage:
#   ./examples/generate-certs.sh                  # extension_value defaults to "agent-alpha"
#   ./examples/generate-certs.sh agent-beta        # custom extension value
#
# The client cert contains a custom X.509 extension at OID 1.3.6.1.4.1.57264.1.1
# with the given value encoded as a DER UTF8String.

set -euo pipefail

EXT_VALUE="${1:-agent-alpha}"
DIR="certs"

mkdir -p "$DIR"

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

echo "==> Generating CA"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "$DIR/client-ca-key.pem" -out "$DIR/client-ca.pem" \
    -days 365 -nodes -subj "/CN=agent-gateway CA" 2>/dev/null

echo "==> Generating proxy server cert (localhost / 127.0.0.1)"
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "$DIR/proxy-key.pem" -out "$DIR/proxy.csr" \
    -nodes -subj "/CN=localhost" 2>/dev/null
openssl x509 -req -in "$DIR/proxy.csr" \
    -CA "$DIR/client-ca.pem" -CAkey "$DIR/client-ca-key.pem" -CAcreateserial \
    -out "$DIR/proxy.pem" -days 365 \
    -extfile <(printf 'subjectAltName=DNS:localhost,IP:127.0.0.1') 2>/dev/null
rm -f "$DIR/proxy.csr"

echo "==> Generating client cert (extension_value=$EXT_VALUE)"
DER_HEX=$(der_utf8string "$EXT_VALUE")
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "$DIR/client-key.pem" -out "$DIR/client.csr" \
    -nodes -subj "/CN=agent-client" 2>/dev/null
openssl x509 -req -in "$DIR/client.csr" \
    -CA "$DIR/client-ca.pem" -CAkey "$DIR/client-ca-key.pem" -CAcreateserial \
    -out "$DIR/client.pem" -days 365 \
    -extfile <(printf '1.3.6.1.4.1.57264.1.1=DER:%s' "$DER_HEX") 2>/dev/null
rm -f "$DIR/client.csr" "$DIR/client-ca.srl"

echo ""
echo "Generated in $DIR/:"
ls -1 "$DIR"
echo ""
echo "Client extension: OID 1.3.6.1.4.1.57264.1.1 = \"$EXT_VALUE\""
