#!/usr/bin/env bash

set -euo pipefail

cert_dir="certs"

mkdir -p "$cert_dir"

server_ext="$cert_dir/server-ext.cnf"

cat > "$server_ext" <<'EOF'
basicConstraints=critical,CA:false
keyUsage=critical,digitalSignature,keyEncipherment
subjectAltName=DNS:localhost,IP:127.0.0.1
extendedKeyUsage=serverAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF

openssl req -x509 -new -nodes -days 365 -newkey rsa:2048 \
  -keyout "$cert_dir/ca-key.pem" \
  -out "$cert_dir/ca-cert.pem" \
  -subj "/CN=Messenger Local CA" \
  -addext "basicConstraints=critical,CA:true" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"

openssl req -new -nodes -newkey rsa:2048 \
  -keyout "$cert_dir/server-key.pem" \
  -out "$cert_dir/server.csr" \
  -subj "/CN=localhost"

openssl x509 -req -days 365 \
  -in "$cert_dir/server.csr" \
  -CA "$cert_dir/ca-cert.pem" \
  -CAkey "$cert_dir/ca-key.pem" \
  -CAcreateserial \
  -out "$cert_dir/server-cert.pem" \
  -extfile "$server_ext"

printf 'Wrote CA and server certificates to %s\n' "$cert_dir"
