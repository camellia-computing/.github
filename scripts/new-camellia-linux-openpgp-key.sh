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
script_directory="$(
  CDPATH=
  cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
  pwd -P
)"
bundle_generator="$script_directory/create-github-signing-bundle.py"
[[ -f "$bundle_generator" && ! -L "$bundle_generator" ]] || {
  echo "GitHub Actions bundle generator is unavailable or unsafe: $bundle_generator" >&2
  exit 1
}
command -v gpg >/dev/null 2>&1 || {
  echo 'gpg is required' >&2
  exit 127
}
command -v python3 >/dev/null 2>&1 || {
  echo 'python3 is required to create the standardized GitHub Actions bundle' >&2
  exit 127
}

read -r -s -p "OpenPGP signing-key passphrase: " key_passphrase
echo
if [[ -z "$key_passphrase" ]]; then
  echo "OpenPGP passphrase must not be empty" >&2
  exit 1
fi

umask 077
temporary_home=$(mktemp -d)
verification_home=''
cleanup() {
  unset key_passphrase
  [[ -z "$verification_home" ]] || rm -rf -- "$verification_home"
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

verification_home=$(mktemp -d)
GNUPGHOME=$verification_home gpg --batch \
  --import "$output_directory/camellia-linux-release-public.asc" >/dev/null 2>&1
if ! GNUPGHOME=$verification_home gpg --batch --with-colons --fingerprint |
  awk -F: -v expected="$signing_fingerprint" \
    '$1 == "fpr" && $10 == expected { found = 1 } END { exit(found ? 0 : 1) }'; then
  echo "exported public key does not contain the expected signing fingerprint" >&2
  exit 1
fi
rm -rf -- "$verification_home"
verification_home=''

identity_path="$output_directory/camellia-linux-release-signing-identity.json"
printf '%s\n' \
  '{' \
  '  "schemaVersion": 1,' \
  '  "platform": "linux",' \
  '  "distributionTrust": "platform-key",' \
  "  \"primaryFingerprint\": \"$primary_fingerprint\"," \
  "  \"signingFingerprint\": \"$signing_fingerprint\"" \
  '}' > "$identity_path"
bundle_passphrase_path="$temporary_home/LINUX_GPG_PASSPHRASE"
printf '%s' "$key_passphrase" > "$bundle_passphrase_path"
chmod 600 "$bundle_passphrase_path"
python3 "$bundle_generator" \
  "$output_directory" \
  --platform linux \
  --distribution-trust platform-key \
  --identity-file "$identity_path" \
  --variable "LINUX_GPG_FINGERPRINT=$signing_fingerprint" \
  --secret "LINUX_GPG_PRIVATE_KEY=$output_directory/camellia-linux-release-private.asc" \
  --secret "LINUX_GPG_PASSPHRASE=$bundle_passphrase_path"

chmod 700 "$output_directory" "$output_directory/github-actions"
chmod 600 "$output_directory/camellia-linux-release-private.asc"
chmod 644 \
  "$output_directory/camellia-linux-release-public.asc" \
  "$output_directory/camellia-linux-release-signing-fingerprint.txt" \
  "$identity_path"

echo "Created OpenPGP release material in: $output_directory"
echo "Primary fingerprint: $primary_fingerprint"
echo "Signing fingerprint: $signing_fingerprint"
echo "Public identity metadata: $identity_path"
echo "GitHub Actions configuration bundle: $output_directory/github-actions"
echo "Keep the private export and passphrase offline; publish the public key and signing fingerprint separately."
