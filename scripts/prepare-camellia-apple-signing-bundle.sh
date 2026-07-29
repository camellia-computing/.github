#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'USAGE'
usage:
  prepare-camellia-apple-signing-bundle.sh macos OUTPUT_DIRECTORY P12_PATH SIGNING_IDENTITY TRUST_MODE
  prepare-camellia-apple-signing-bundle.sh ios OUTPUT_DIRECTORY P12_PATH PROFILE_PATH SIGNING_IDENTITY TEAM_ID EXPORT_METHOD

macOS TRUST_MODE is private-trust or public-trust.
iOS EXPORT_METHOD is app-store-connect, release-testing, debugging, or enterprise.
USAGE
}

if [[ $# -lt 1 ]]; then
  usage
  exit 2
fi

mode=$1
case "$mode" in
  macos)
    if [[ $# -ne 5 ]]; then
      usage
      exit 2
    fi
    output_directory=$2
    p12_path=$3
    signing_identity=$4
    trust_mode=$5
    profile_path=''
    team_id=''
    export_method=''
    ;;
  ios)
    if [[ $# -ne 7 ]]; then
      usage
      exit 2
    fi
    output_directory=$2
    p12_path=$3
    profile_path=$4
    signing_identity=$5
    team_id=$6
    export_method=$7
    trust_mode=platform-key
    ;;
  *)
    usage
    exit 2
    ;;
esac

if [[ -e "$output_directory" ]]; then
  echo "refusing to overwrite existing path: $output_directory" >&2
  exit 1
fi
for source_path in "$p12_path" "$profile_path"; do
  [[ -z "$source_path" ]] && continue
  [[ -f "$source_path" && ! -L "$source_path" ]] || {
    echo "signing input must be a regular, non-symbolic-link file: $source_path" >&2
    exit 2
  }
  [[ -s "$source_path" ]] || {
    echo "signing input must not be empty: $source_path" >&2
    exit 2
  }
done
if [[ -z "$signing_identity" ||
      "$signing_identity" == *$'\n'* ||
      "$signing_identity" == *$'\r'* ||
      "$signing_identity" == *'"'* ||
      "$signing_identity" == *\\* ]]; then
  echo 'SIGNING_IDENTITY must be a non-empty single line without quote or backslash characters' >&2
  exit 2
fi

if [[ "$mode" == macos ]]; then
  case "$trust_mode" in
    private-trust|public-trust) ;;
    *)
      echo 'macOS TRUST_MODE must be private-trust or public-trust' >&2
      exit 2
      ;;
  esac
else
  [[ "$signing_identity" != *'$'* &&
     "$signing_identity" != *'#'* &&
     "$signing_identity" != *'='* &&
     "$signing_identity" != *';'* &&
     "$signing_identity" != *'//'* ]] || {
    echo 'iOS SIGNING_IDENTITY contains characters unsafe for Xcode settings' >&2
    exit 2
  }
  [[ "$team_id" =~ ^[A-Z0-9]{10}$ ]] || {
    echo 'iOS TEAM_ID must be a 10-character uppercase Apple Developer Team ID' >&2
    exit 2
  }
  case "$export_method" in
    app-store-connect|release-testing|debugging|enterprise) ;;
    *)
      echo 'iOS EXPORT_METHOD must be app-store-connect, release-testing, debugging, or enterprise' >&2
      exit 2
      ;;
  esac
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
command -v openssl >/dev/null 2>&1 || {
  echo 'openssl is required' >&2
  exit 127
}
command -v python3 >/dev/null 2>&1 || {
  echo 'python3 is required to create the standardized GitHub Actions bundle' >&2
  exit 127
}

read -r -s -p 'P12 password: ' p12_password
echo
if [[ -z "$p12_password" ]]; then
  echo 'P12 password must not be empty' >&2
  exit 1
fi

umask 077
mkdir -p "$output_directory"
temporary_directory=$(mktemp -d)
cleanup() {
  unset p12_password
  rm -rf -- "$temporary_directory"
}
trap cleanup EXIT

password_path="$temporary_directory/p12-password"
certificate_pem="$temporary_directory/certificate.pem"
printf '%s' "$p12_password" > "$password_path"
chmod 600 "$password_path"
if ! openssl pkcs12 \
  -in "$p12_path" \
  -clcerts \
  -nokeys \
  -passin "file:$password_path" \
  -out "$certificate_pem" >/dev/null 2>&1; then
  echo 'P12 is not a valid password-protected identity with a readable leaf certificate' >&2
  exit 1
fi
certificate_count=$(grep -c '^-----BEGIN CERTIFICATE-----$' "$certificate_pem" || true)
[[ "$certificate_count" == 1 ]] || {
  echo "P12 must contain exactly one leaf certificate; found $certificate_count" >&2
  exit 1
}
certificate_sha256="$(
  openssl x509 -in "$certificate_pem" -outform DER |
    openssl dgst -sha256 -hex |
    awk '{ print toupper($NF) }'
)"
[[ "$certificate_sha256" =~ ^[0-9A-F]{64}$ ]] || {
  echo 'failed to calculate the P12 leaf certificate SHA-256 digest' >&2
  exit 1
}
certificate_not_after="$(
  openssl x509 -in "$certificate_pem" -noout -enddate |
    cut -d= -f2-
)"
identity_path="$output_directory/camellia-$mode-signing-identity.json"
printf '%s\n' \
  '{' \
  '  "schemaVersion": 1,' \
  "  \"platform\": \"$mode\"," \
  "  \"distributionTrust\": \"$trust_mode\"," \
  "  \"signingIdentity\": \"$signing_identity\"," \
  "  \"certificateSha256\": \"$certificate_sha256\"," \
  "  \"notAfter\": \"$certificate_not_after\"" \
  '}' > "$identity_path"

if [[ "$mode" == macos ]]; then
  python3 "$bundle_generator" \
    "$output_directory" \
    --platform macos \
    --distribution-trust "$trust_mode" \
    --identity-file "$identity_path" \
    --variable "APPLE_SIGNING_CERTIFICATE_SHA256=$certificate_sha256" \
    --variable "APPLE_SIGNING_IDENTITY=$signing_identity" \
    --variable "APPLE_SIGNING_TRUST_MODE=$trust_mode" \
    --secret-base64 "APPLE_CERTIFICATE=$p12_path" \
    --secret "APPLE_CERTIFICATE_PASSWORD=$password_path"
else
  printf '%s\n' \
    '{' \
    '  "schemaVersion": 1,' \
    '  "platform": "ios",' \
    '  "distributionTrust": "platform-key",' \
    "  \"signingIdentity\": \"$signing_identity\"," \
    "  \"certificateSha256\": \"$certificate_sha256\"," \
    "  \"notAfter\": \"$certificate_not_after\"," \
    "  \"teamId\": \"$team_id\"," \
    "  \"exportMethod\": \"$export_method\"" \
    '}' > "$identity_path"
  python3 "$bundle_generator" \
    "$output_directory" \
    --platform ios \
    --distribution-trust platform-key \
    --identity-file "$identity_path" \
    --variable "IOS_SIGNING_CERTIFICATE_SHA256=$certificate_sha256" \
    --variable "IOS_SIGNING_IDENTITY=$signing_identity" \
    --variable "IOS_TEAM_ID=$team_id" \
    --variable "IOS_EXPORT_METHOD=$export_method" \
    --secret-base64 "IOS_CERTIFICATE_BASE64=$p12_path" \
    --secret "IOS_CERTIFICATE_PASSWORD=$password_path" \
    --secret-base64 "IOS_PROVISIONING_PROFILE_BASE64=$profile_path"
fi

chmod 700 "$output_directory" "$output_directory/github-actions"
chmod 644 "$identity_path"

echo "Prepared $mode GitHub Actions signing configuration in: $output_directory"
echo "Certificate SHA-256: $certificate_sha256"
echo "Public identity metadata: $identity_path"
echo "GitHub Actions configuration bundle: $output_directory/github-actions"
if [[ "$mode" == ios ]]; then
  echo 'The Remote Client release workflow performs the final profile, Team ID, bundle ID, and certificate authorization checks on macOS.'
else
  echo 'The Remote Client release workflow performs the final macOS keychain identity check before signing.'
fi
