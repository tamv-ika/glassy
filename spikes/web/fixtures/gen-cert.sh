#!/usr/bin/env bash
# Generates a short-lived ECDSA P-256 certificate usable with WebTransport serverCertificateHashes.
# Outputs: cert.pem, key.pem, cert.sha256 (hex SHA-256 of the DER), cert.fp (AA:BB:.. fingerprint).
set -euo pipefail

out="${1:?usage: gen-cert.sh OUTDIR}"
mkdir -p "$out"
openssl ecparam -name prime256v1 -genkey -noout -out "$out/key.pem"
# serverCertificateHashes requires validity <= 14 days; 13 leaves room for clock skew.
openssl req -x509 -new -key "$out/key.pem" -days 13 -subj /CN=localhost \
  -addext subjectAltName=DNS:localhost -out "$out/cert.pem" 2>/dev/null
openssl x509 -in "$out/cert.pem" -outform DER | sha256sum | cut -d' ' -f1 > "$out/cert.sha256"
openssl x509 -in "$out/cert.pem" -noout -fingerprint -sha256 | cut -d= -f2 > "$out/cert.fp"
