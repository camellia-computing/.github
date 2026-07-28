#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 OUTPUT_DIRECTORY USER_ID" >&2
}

if [[ $# -ne 2 ]]; then
  usage
  exit 2
fi

output_directory=$1
user_id=$2
if [[ -e "$output_directory" ]]; then
  echo "refusing to overwrite existing path: $output_directory" >&2
  exit 1
fi
if [[ -z "$user_id" || "$user_id" == *$'\n'* || "$user_id" == *$'\r'* ]]; then
  echo "USER_ID must be a non-empty single line" >&2
  exit 2
fi
command -v gpg >/dev/null

read -r -s -p "OpenPGP signing-key passphrase: " key_passphrase
echo
if [[ -z "$key_passphrase" ]]; then
  echo "OpenPGP passphrase must not be empty" >&2
  exit 1
fi

umask 077
temporary_home=$(mktemp -d)
cleanup() {
  unset key_passphrase
  rm -rf -- "$temporary_home"
}
trap cleanup EXIT
export GNUPGHOME=$temporary_home

run_secret_gpg() {
  exec 3<<<"$key_passphrase"
  gpg --batch --yes --pinentry-mode loopback --passphrase-fd 3 "$@"
  local status=$?
  exec 3<&-
  return "$status"
}

run_secret_gpg --quick-generate-key "$user_id" ed25519 cert 1y
primary_fingerprint=$(
  gpg --batch --with-colons --list-secret-keys "$user_id" |
    awk -F: '$1 == "fpr" { print $10; exit }'
)
if [[ ! "$primary_fingerprint" =~ ^[0-9A-F]{40,64}$ ]]; then
  echo "failed to resolve the generated primary fingerprint" >&2
  exit 1
fi

run_secret_gpg --quick-add-key "$primary_fingerprint" ed25519 sign 1y
signing_fingerprint=$(
  gpg --batch --with-colons --list-secret-keys "$primary_fingerprint" |
    awk -F: '$1 == "ssb" { want_fingerprint = 1; next } want_fingerprint && $1 == "fpr" { print $10; exit }'
)
if [[ ! "$signing_fingerprint" =~ ^[0-9A-F]{40,64}$ ]]; then
  echo "failed to resolve the generated signing-subkey fingerprint" >&2
  exit 1
fi

mkdir -p "$output_directory"
gpg --batch --armor --export "$primary_fingerprint" \
  > "$output_directory/camellia-linux-release-public.asc"
run_secret_gpg --armor --export-secret-subkeys "$signing_fingerprint!" \
  > "$output_directory/camellia-linux-release-private.asc"
printf '%s\n' "$signing_fingerprint" \
  > "$output_directory/camellia-linux-release-signing-fingerprint.txt"
chmod 600 "$output_directory"/*

verification_home=$(mktemp -d)
GNUPGHOME=$verification_home gpg --batch \
  --import "$output_directory/camellia-linux-release-public.asc" >/dev/null 2>&1
if ! GNUPGHOME=$verification_home gpg --batch --with-colons --fingerprint |
  awk -F: -v expected="$signing_fingerprint" \
    '$1 == "fpr" && $10 == expected { found = 1 } END { exit(found ? 0 : 1) }'; then
  rm -rf -- "$verification_home"
  echo "exported public key does not contain the expected signing fingerprint" >&2
  exit 1
fi
rm -rf -- "$verification_home"

echo "Created OpenPGP release material in: $output_directory"
echo "Primary fingerprint: $primary_fingerprint"
echo "Signing fingerprint: $signing_fingerprint"
echo "Keep the private export and passphrase offline; publish the public key and signing fingerprint separately."
