#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 OUTPUT_DIRECTORY [ORGANIZATION]" >&2
}

if [[ $# -lt 1 || $# -gt 2 ]]; then
  usage
  exit 2
fi

output_directory=$1
organization=${2:-Camellia Computing}

if [[ ! "$organization" =~ ^[A-Za-z0-9][A-Za-z0-9\ ._-]{1,62}[A-Za-z0-9]$ ]]; then
  echo "organization contains unsupported characters" >&2
  exit 2
fi
if [[ -e "$output_directory" ]]; then
  echo "refusing to overwrite existing path: $output_directory" >&2
  exit 1
fi
command -v openssl >/dev/null

read -r -s -p "Code-signing P12 password: " p12_password
echo
if [[ -z "$p12_password" ]]; then
  echo "P12 password must not be empty" >&2
  exit 1
fi

umask 077
mkdir -p "$output_directory"
root_config="$output_directory/root.cnf"
leaf_config="$output_directory/leaf.cnf"
leaf_extensions="$output_directory/leaf.ext"

cleanup() {
  unset p12_password
  rm -f -- "$root_config" "$leaf_config" "$leaf_extensions"
}
trap cleanup EXIT

printf '%s\n' \
  '[req]' \
  'distinguished_name = dn' \
  'x509_extensions = v3_ca' \
  'prompt = no' \
  '[dn]' \
  "CN = $organization Private Code Signing Root CA" \
  "O = $organization" \
  '[v3_ca]' \
  'basicConstraints = critical,CA:TRUE,pathlen:0' \
  'keyUsage = critical,keyCertSign,cRLSign' \
  'subjectKeyIdentifier = hash' \
  > "$root_config"

printf '%s\n' \
  '[req]' \
  'distinguished_name = dn' \
  'prompt = no' \
  '[dn]' \
  "CN = $organization Private Code Signing" \
  "O = $organization" \
  > "$leaf_config"

printf '%s\n' \
  'basicConstraints = critical,CA:FALSE' \
  'keyUsage = critical,digitalSignature' \
  'extendedKeyUsage = codeSigning' \
  'subjectKeyIdentifier = hash' \
  'authorityKeyIdentifier = keyid,issuer' \
  > "$leaf_extensions"

openssl genpkey \
  -algorithm RSA \
  -pkeyopt rsa_keygen_bits:4096 \
  -out "$output_directory/camellia-private-code-signing-root.key"
openssl req \
  -x509 \
  -new \
  -sha256 \
  -days 3650 \
  -key "$output_directory/camellia-private-code-signing-root.key" \
  -config "$root_config" \
  -out "$output_directory/camellia-private-code-signing-root.crt"

openssl genpkey \
  -algorithm RSA \
  -pkeyopt rsa_keygen_bits:3072 \
  -out "$output_directory/camellia-private-code-signing-leaf.key"
openssl req \
  -new \
  -sha256 \
  -key "$output_directory/camellia-private-code-signing-leaf.key" \
  -config "$leaf_config" \
  -out "$output_directory/camellia-private-code-signing-leaf.csr"
openssl x509 \
  -req \
  -sha256 \
  -days 825 \
  -in "$output_directory/camellia-private-code-signing-leaf.csr" \
  -CA "$output_directory/camellia-private-code-signing-root.crt" \
  -CAkey "$output_directory/camellia-private-code-signing-root.key" \
  -CAcreateserial \
  -extfile "$leaf_extensions" \
  -out "$output_directory/camellia-private-code-signing-leaf.crt"

exec 3<<<"$p12_password"
openssl pkcs12 \
  -export \
  -name "$organization Private Code Signing" \
  -inkey "$output_directory/camellia-private-code-signing-leaf.key" \
  -in "$output_directory/camellia-private-code-signing-leaf.crt" \
  -certfile "$output_directory/camellia-private-code-signing-root.crt" \
  -passout fd:3 \
  -out "$output_directory/camellia-private-code-signing-leaf.p12"
exec 3<&-

openssl verify \
  -CAfile "$output_directory/camellia-private-code-signing-root.crt" \
  "$output_directory/camellia-private-code-signing-leaf.crt"
openssl x509 \
  -in "$output_directory/camellia-private-code-signing-leaf.crt" \
  -noout \
  -fingerprint \
  -sha256

rm -f -- \
  "$output_directory/camellia-private-code-signing-leaf.csr" \
  "$output_directory/camellia-private-code-signing-root.srl"
chmod 600 "$output_directory"/*

echo "Created private macOS test identity in: $output_directory"
echo "Keep all .key and .p12 files offline; distribute only the public root certificate to managed test Macs."
