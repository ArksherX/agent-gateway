#!/usr/bin/env bash
# Demo TLS material: gateway server certs plus mock HTTPS service certs.

set -euo pipefail

DIR="certs"

mkdir -p "$DIR"

have_files() {
    local file
    for file in "$@"; do
        [[ -f "$file" ]] || return 1
    done
}

if have_files "$DIR/server-ca-key.pem" "$DIR/server-ca.pem" "$DIR/server-key.pem" "$DIR/server.pem"; then
    echo "==> Using existing gateway server certs"
else
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
fi

if have_files "$DIR/mock-ca-key.pem" "$DIR/mock-ca.pem" "$DIR/mock-services-key.pem" "$DIR/mock-services.pem"; then
    echo "==> Using existing mock service certs"
else
    echo "==> Generating mock service CA"
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -keyout "$DIR/mock-ca-key.pem" -out "$DIR/mock-ca.pem" \
        -days 365 -nodes -subj "/CN=agent-gateway mock service CA" 2>/dev/null

    echo "==> Generating mock service cert (docstore / messaging)"
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -keyout "$DIR/mock-services-key.pem" -out "$DIR/mock-services.csr" \
        -nodes -subj "/CN=agent-gateway mock services" 2>/dev/null
    openssl x509 -req -in "$DIR/mock-services.csr" \
        -CA "$DIR/mock-ca.pem" -CAkey "$DIR/mock-ca-key.pem" -CAcreateserial \
        -out "$DIR/mock-services.pem" -days 365 \
        -extfile <(printf 'subjectAltName=DNS:docstore,DNS:messaging\nextendedKeyUsage=serverAuth') 2>/dev/null
    rm -f "$DIR/mock-services.csr" "$DIR/mock-ca.srl"
fi

echo ""
echo "Generated in $DIR/:"
ls -1 "$DIR"
