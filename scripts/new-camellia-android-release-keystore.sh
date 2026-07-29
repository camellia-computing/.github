#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 OUTPUT_DIRECTORY [ALIAS] [ORGANIZATION]" >&2
}

if [[ $# -lt 1 || $# -gt 3 ]]; then
  usage
  exit 2
fi

output_directory=$1
alias=${2:-camellia-remote-release}
organization=${3:-Camellia Computing}

if [[ -e "$output_directory" ]]; then
  echo "refusing to overwrite existing path: $output_directory" >&2
  exit 1
fi
if [[ ! "$alias" =~ ^[A-Za-z0-9._-]{1,128}$ ]]; then
  echo 'Android alias contains unsupported characters' >&2
  exit 2
fi
if [[ ! "$organization" =~ ^[A-Za-z0-9][A-Za-z0-9\ ._-]{1,62}[A-Za-z0-9]$ ]]; then
  echo 'organization contains unsupported characters' >&2
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
command -v keytool >/dev/null 2>&1 || {
  echo 'keytool from a current JDK is required' >&2
  exit 127
}
command -v python3 >/dev/null 2>&1 || {
  echo 'python3 is required to create the standardized GitHub Actions bundle' >&2
  exit 127
}

read -r -s -p 'Android keystore password: ' store_password
echo
read -r -s -p 'Android key password (must match the PKCS#12 keystore password): ' key_password
echo
if [[ -z "$store_password" || -z "$key_password" ]]; then
  echo 'Android keystore and key passwords must not be empty' >&2
  exit 1
fi
if [[ "$store_password" != "$key_password" ]]; then
  echo 'PKCS#12 keystores use one password; enter the same password for both values' >&2
  exit 2
fi

umask 077
mkdir -p "$output_directory"
temporary_directory=$(mktemp -d)
cleanup() {
  unset store_password key_password CAMELLIA_ANDROID_STORE_PASSWORD CAMELLIA_ANDROID_KEY_PASSWORD
  rm -rf -- "$temporary_directory"
}
trap cleanup EXIT

keystore_path="$output_directory/camellia-android-release.keystore"
export CAMELLIA_ANDROID_STORE_PASSWORD=$store_password
export CAMELLIA_ANDROID_KEY_PASSWORD=$key_password
keytool -J-Duser.language=en -genkeypair \
  -storetype PKCS12 \
  -keystore "$keystore_path" \
  -storepass:env CAMELLIA_ANDROID_STORE_PASSWORD \
  -keypass:env CAMELLIA_ANDROID_KEY_PASSWORD \
  -alias "$alias" \
  -dname "CN=$organization Android Release, O=$organization" \
  -keyalg RSA \
  -keysize 3072 \
  -sigalg SHA384withRSA \
  -validity 825 \
  -noprompt

certificate_output="$(
  keytool -J-Duser.language=en -list -v \
    -keystore "$keystore_path" \
    -storepass:env CAMELLIA_ANDROID_STORE_PASSWORD \
    -alias "$alias"
)"
certificate_sha256="$(
  sed -n 's/^[[:space:]]*SHA256:[[:space:]]*//p' <<< "$certificate_output" |
    tr -d ':[:space:]' |
    tr '[:lower:]' '[:upper:]' |
    head -n 1
)"
[[ "$certificate_sha256" =~ ^[0-9A-F]{64}$ ]] || {
  echo 'failed to calculate the Android signing certificate SHA-256 digest' >&2
  exit 1
}
certificate_valid_from="$(
  sed -n 's/^[[:space:]]*Valid from:[[:space:]]*//p' <<< "$certificate_output" |
    head -n 1
)"
identity_path="$output_directory/camellia-android-release-identity.json"
printf '%s\n' \
  '{' \
  '  "schemaVersion": 1,' \
  '  "platform": "android",' \
  '  "distributionTrust": "platform-key",' \
  "  \"alias\": \"$alias\"," \
  "  \"certificateSha256\": \"$certificate_sha256\"," \
  "  \"validity\": \"$certificate_valid_from\"" \
  '}' > "$identity_path"

bundle_input_directory="$temporary_directory/github-actions-input"
mkdir -m 700 "$bundle_input_directory"
store_password_path="$bundle_input_directory/ANDROID_KEY_STORE_PASSWORD"
key_password_path="$bundle_input_directory/ANDROID_KEY_PASSWORD"
alias_path="$bundle_input_directory/ANDROID_ALIAS"
printf '%s' "$store_password" > "$store_password_path"
printf '%s' "$key_password" > "$key_password_path"
printf '%s' "$alias" > "$alias_path"
chmod 600 "$store_password_path" "$key_password_path" "$alias_path"
python3 "$bundle_generator" \
  "$output_directory" \
  --platform android \
  --distribution-trust platform-key \
  --identity-file "$identity_path" \
  --variable "ANDROID_SIGNING_CERTIFICATE_SHA256=$certificate_sha256" \
  --secret-base64 "ANDROID_SIGNING_KEY=$keystore_path" \
  --secret "ANDROID_KEY_STORE_PASSWORD=$store_password_path" \
  --secret "ANDROID_KEY_PASSWORD=$key_password_path" \
  --secret "ANDROID_ALIAS=$alias_path"

chmod 700 "$output_directory" "$output_directory/github-actions"
chmod 600 "$keystore_path"
chmod 644 "$identity_path"

echo "Created a new Android release identity in: $output_directory"
echo "Certificate SHA-256: $certificate_sha256"
echo "Public identity metadata: $identity_path"
echo "GitHub Actions configuration bundle: $output_directory/github-actions"
echo 'This is a new update identity. Never use it to replace a known existing application-update keystore.'
