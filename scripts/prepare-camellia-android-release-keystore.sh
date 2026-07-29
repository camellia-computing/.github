#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 OUTPUT_DIRECTORY EXISTING_KEYSTORE ALIAS" >&2
}

if [[ $# -ne 3 ]]; then
  usage
  exit 2
fi

output_directory=$1
keystore_path=$2
alias=$3

if [[ -e "$output_directory" ]]; then
  echo "refusing to overwrite existing path: $output_directory" >&2
  exit 1
fi
if [[ ! -f "$keystore_path" || -L "$keystore_path" ]]; then
  echo "existing keystore must be a regular, non-symbolic-link file: $keystore_path" >&2
  exit 1
fi
if [[ ! "$alias" =~ ^[A-Za-z0-9._-]{1,128}$ ]]; then
  echo 'Android alias contains unsupported characters' >&2
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

read -r -s -p 'Existing Android keystore password: ' store_password
echo
read -r -s -p 'Existing Android key password: ' key_password
echo
if [[ -z "$store_password" || -z "$key_password" ]]; then
  echo 'Android keystore and key passwords must not be empty' >&2
  exit 1
fi

umask 077
mkdir -m 700 "$output_directory"
temporary_directory=$(mktemp -d)
cleanup() {
  unset store_password key_password CAMELLIA_ANDROID_STORE_PASSWORD CAMELLIA_ANDROID_KEY_PASSWORD
  rm -rf -- "$temporary_directory"
}
trap cleanup EXIT

export CAMELLIA_ANDROID_STORE_PASSWORD=$store_password
export CAMELLIA_ANDROID_KEY_PASSWORD=$key_password
certificate_output="$(
  keytool -J-Duser.language=en -J-Duser.country=US -list -v \
    -keystore "$keystore_path" \
    -storepass:env CAMELLIA_ANDROID_STORE_PASSWORD \
    -alias "$alias"
)"
if ! grep -Fqx 'Entry type: PrivateKeyEntry' <<< "$certificate_output"; then
  echo "Android alias does not resolve to a private-key entry: $alias" >&2
  exit 1
fi

# `-certreq` is non-mutating and confirms that the separately supplied key
# password can access the historical private key before it is uploaded.
keytool -J-Duser.language=en -J-Duser.country=US -certreq -rfc \
  -keystore "$keystore_path" \
  -storepass:env CAMELLIA_ANDROID_STORE_PASSWORD \
  -keypass:env CAMELLIA_ANDROID_KEY_PASSWORD \
  -alias "$alias" \
  -file "$temporary_directory/certificate-request.pem" >/dev/null

keystore_type="$(
  sed -n 's/^Keystore type: //p' <<< "$certificate_output" | head -n 1
)"
certificate_sha256="$(
  sed -n 's/^[[:space:]]*SHA256:[[:space:]]*//p' <<< "$certificate_output" |
    tr -d ':[:space:]' |
    tr '[:lower:]' '[:upper:]' |
    head -n 1
)"
certificate_subject="$(
  sed -n 's/^Owner: //p' <<< "$certificate_output" | head -n 1
)"
certificate_issuer="$(
  sed -n 's/^Issuer: //p' <<< "$certificate_output" | head -n 1
)"
certificate_validity="$(
  sed -n 's/^[[:space:]]*Valid from:[[:space:]]*//p' <<< "$certificate_output" | head -n 1
)"
[[ -n "$keystore_type" ]] || {
  echo 'failed to determine Android keystore type' >&2
  exit 1
}
[[ "$certificate_sha256" =~ ^[0-9A-F]{64}$ ]] || {
  echo 'failed to calculate the Android signing certificate SHA-256 digest' >&2
  exit 1
}
[[ -n "$certificate_subject" && -n "$certificate_issuer" && -n "$certificate_validity" ]] || {
  echo 'failed to extract complete public Android certificate metadata' >&2
  exit 1
}

identity_path="$output_directory/camellia-android-release-identity.json"
python3 - \
  "$identity_path" \
  "$alias" \
  "$keystore_type" \
  "$certificate_sha256" \
  "$certificate_subject" \
  "$certificate_issuer" \
  "$certificate_validity" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
identity = {
    "schemaVersion": 1,
    "platform": "android",
    "distributionTrust": "platform-key",
    "alias": sys.argv[2],
    "keystoreType": sys.argv[3],
    "certificateSha256": sys.argv[4],
    "subject": sys.argv[5],
    "issuer": sys.argv[6],
    "validity": sys.argv[7],
}
path.write_text(json.dumps(identity, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

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
chmod 644 "$identity_path"

echo "Prepared existing Android update identity in: $output_directory"
echo "Keystore type: $keystore_type"
echo "Alias: $alias"
echo "Certificate subject: $certificate_subject"
echo "Certificate issuer: $certificate_issuer"
echo "Certificate validity: $certificate_validity"
echo "Certificate SHA-256: $certificate_sha256"
echo "Public identity metadata: $identity_path"
echo "GitHub Actions configuration bundle: $output_directory/github-actions"
echo 'The original keystore was not modified. Preserve its controlled backup before uploading the bundle.'
