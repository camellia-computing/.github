#!/usr/bin/env python3
"""Create a protected GitHub Actions signing-configuration bundle.

The bundle deliberately separates non-secret GitHub Actions variables from
secret payload files.  It contains upload helpers for Bash and PowerShell 7,
but never contacts GitHub while material is being generated.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any


GITHUB_NAME = re.compile(r"^[A-Z][A-Z0-9_]*$")
PLATFORMS = {"windows", "macos", "linux", "android", "ios"}
TRUST_MODES = {"public-trust", "private-trust", "platform-key"}
FORBIDDEN_PUBLIC_FIELDS = {
    "password",
    "passphrase",
    "private_key",
    "private_key_pem",
    "pfx_base64",
    "p12_base64",
    "keystore_base64",
    "provisioning_profile_base64",
    "secret_value",
}
FORBIDDEN_PUBLIC_FIELD_NORMALIZED = {
    re.sub(r"[^a-z0-9]", "", field) for field in FORBIDDEN_PUBLIC_FIELDS
}
PRIVATE_MARKERS = (
    "-----BEGIN " + "PRIVATE KEY-----",
    "-----BEGIN " + "ENCRYPTED PRIVATE KEY-----",
    "-----BEGIN " + "EC PRIVATE KEY-----",
    "-----BEGIN " + "OPENSSH PRIVATE KEY-----",
    "-----BEGIN PGP " + "PRIVATE KEY BLOCK-----",
)
SENSITIVE_VARIABLE_SUFFIXES = (
    "password",
    "passphrase",
    "privatekey",
    "pfxbase64",
    "p12base64",
    "keystorebase64",
    "provisioningprofilebase64",
)


class BundleError(ValueError):
    """Raised when a bundle input would be unsafe or ambiguous."""


def require_regular_file(path: Path, description: str) -> None:
    if path.is_symlink() or not path.is_file():
        raise BundleError(f"{description} must be a regular, non-symbolic-link file")


def parse_name_assignment(value: str, description: str) -> tuple[str, Path]:
    name, separator, source = value.partition("=")
    if not separator or not GITHUB_NAME.fullmatch(name) or not source:
        raise BundleError(f"{description} must use NAME=PATH with a valid GitHub name")
    return name, Path(source)


def parse_variable_assignment(value: str) -> tuple[str, str]:
    name, separator, variable_value = value.partition("=")
    if not separator or not GITHUB_NAME.fullmatch(name):
        raise BundleError("--variable must use NAME=VALUE with a valid GitHub name")
    if not variable_value or "\r" in variable_value or "\n" in variable_value:
        raise BundleError(f"GitHub variable {name} must be a non-empty single line")
    normalized_name = re.sub(r"[^a-z0-9]", "", name.lower())
    if normalized_name.endswith(SENSITIVE_VARIABLE_SUFFIXES):
        raise BundleError(f"GitHub variable {name} appears to be a Secret payload")
    return name, variable_value


def reject_private_public_metadata(value: Any, location: str = "$") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str):
                raise BundleError(f"public identity key at {location} must be a string")
            normalized_key = re.sub(r"[^a-z0-9]", "", key.lower())
            if normalized_key in FORBIDDEN_PUBLIC_FIELD_NORMALIZED:
                raise BundleError(f"private field is forbidden in public identity: {location}.{key}")
            reject_private_public_metadata(child, f"{location}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            reject_private_public_metadata(child, f"{location}[{index}]")
    elif not isinstance(value, (str, int, float, bool, type(None))):
        raise BundleError(f"public identity contains an unsupported value at {location}")


def load_public_identity(path: Path) -> Any:
    require_regular_file(path, "--identity-file")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BundleError(f"--identity-file is not valid UTF-8 JSON: {error}") from error
    reject_private_public_metadata(value)
    rendered = json.dumps(value, sort_keys=True)
    if any(marker in rendered for marker in PRIVATE_MARKERS):
        raise BundleError("--identity-file appears to contain private key material")
    return value


def write_file(path: Path, payload: bytes, mode: int) -> None:
    with path.open("xb") as handle:
        handle.write(payload)
    os.chmod(path, mode)


def shell_uploader() -> str:
    return """#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'USAGE'
usage:
  upload.sh --apply --repo OWNER/REPOSITORY
  upload.sh --apply --org ORGANIZATION --repos repository-one,repository-two

Without --apply this helper only prints the names it would update.
USAGE
}

apply=false
scope=\"\"
repository=\"\"
organization=\"\"
repositories=\"\"

while (($# > 0)); do
  case \"$1\" in
    --apply)
      apply=true
      ;;
    --repo)
      [[ $# -ge 2 ]] || { usage; exit 2; }
      scope=repository
      repository=$2
      shift
      ;;
    --org)
      [[ $# -ge 2 ]] || { usage; exit 2; }
      scope=organization
      organization=$2
      shift
      ;;
    --repos)
      [[ $# -ge 2 ]] || { usage; exit 2; }
      repositories=$2
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      usage
      exit 2
      ;;
  esac
  shift
done

if [[ \"$scope\" == repository ]]; then
  [[ -n \"$repository\" && -z \"$organization\" && -z \"$repositories\" ]] || {
    usage
    exit 2
  }
elif [[ \"$scope\" == organization ]]; then
  [[ -n \"$organization\" && -n \"$repositories\" && -z \"$repository\" ]] || {
    usage
    exit 2
  }
else
  usage
  exit 2
fi

command -v gh >/dev/null 2>&1 || {
  echo 'GitHub CLI (gh) is required' >&2
  exit 127
}

bundle_directory="$(
  CDPATH=
  cd -- \"$(dirname -- \"${BASH_SOURCE[0]}\")\"
  pwd -P
)"
variables_file=\"$bundle_directory/variables.env\"
secrets_directory=\"$bundle_directory/secrets\"
[[ -f \"$variables_file\" && ! -L \"$variables_file\" && -d \"$secrets_directory\" && ! -L \"$secrets_directory\" ]] || {
  echo 'The signing bundle is incomplete or contains an unsafe symbolic link' >&2
  exit 1
}

scope_label=\"$repository\"
scope_args=()
if [[ \"$scope\" == organization ]]; then
  scope_label=\"$organization selected repositories: $repositories\"
  scope_args=(--org \"$organization\" --repos \"$repositories\" --visibility selected)
else
  scope_args=(--repo \"$repository\")
fi

variable_names=()
while IFS='=' read -r name value || [[ -n \"${name:-}\" ]]; do
  [[ \"$name\" =~ ^[A-Z][A-Z0-9_]*$ && -n \"${value:-}\" ]] || {
    echo 'variables.env contains an invalid value' >&2
    exit 1
  }
  variable_names+=(\"$name\")
done < \"$variables_file\"
(( ${#variable_names[@]} > 0 )) || {
  echo 'variables.env must contain at least one variable' >&2
  exit 1
}

shopt -s nullglob
secret_files=(\"$secrets_directory\"/*)
(( ${#secret_files[@]} > 0 )) || {
  echo 'secrets must contain at least one Secret payload file' >&2
  exit 1
}
secret_names=()
for secret_file in \"${secret_files[@]}\"; do
  secret_name=$(basename -- \"$secret_file\")
  [[ -f \"$secret_file\" && \"$secret_name\" =~ ^[A-Z][A-Z0-9_]*$ && ! -L \"$secret_file\" ]] || {
    echo 'secrets contains an invalid file or symbolic link' >&2
    exit 1
  }
  secret_names+=(\"$secret_name\")
done

printf 'Signing bundle target: %s\\n' \"$scope_label\"
printf 'GitHub variables: %s\\n' \"${variable_names[*]:-none}\"
printf 'GitHub secrets: %s\\n' \"${secret_names[*]:-none}\"
if [[ \"$apply\" != true ]]; then
  echo 'Dry run only. Re-run with --apply after reviewing metadata.json and variables.env.'
  exit 0
fi

while IFS='=' read -r name value || [[ -n \"${name:-}\" ]]; do
  gh variable set \"$name\" \"${scope_args[@]}\" --body \"$value\"
done < \"$variables_file\"
for secret_file in \"${secret_files[@]}\"; do
  secret_name=$(basename -- \"$secret_file\")
  gh secret set \"$secret_name\" \"${scope_args[@]}\" < \"$secret_file\"
done

echo 'GitHub Actions signing configuration updated. Run the non-publishing release candidate before promotion.'
"""


def powershell_uploader() -> str:
    return r"""#requires -Version 7.6

[CmdletBinding(DefaultParameterSetName = 'Repository')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Repository')]
    [string] $Repository,

    [Parameter(Mandatory, ParameterSetName = 'Organization')]
    [string] $Organization,

    [Parameter(Mandatory, ParameterSetName = 'Organization')]
    [string] $Repositories,

    [Parameter()]
    [switch] $Apply
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-GhSecretSet {
    param(
        [Parameter(Mandatory)]
        [string] $Name,

        [Parameter(Mandatory)]
        [string] $SecretPath,

        [Parameter(Mandatory)]
        [string[]] $ScopeArguments
    )

    $processInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $processInfo.FileName = 'gh'
    $processInfo.UseShellExecute = $false
    $processInfo.RedirectStandardInput = $true
    $null = $processInfo.ArgumentList.Add('secret')
    $null = $processInfo.ArgumentList.Add('set')
    $null = $processInfo.ArgumentList.Add($Name)
    foreach ($argument in $ScopeArguments) {
        $null = $processInfo.ArgumentList.Add($argument)
    }
    $process = [System.Diagnostics.Process]::Start($processInfo)
    if ($null -eq $process) {
        throw "Could not start gh to set secret $Name"
    }
    try {
        $payload = [System.IO.File]::ReadAllBytes($SecretPath)
        $process.StandardInput.BaseStream.Write($payload, 0, $payload.Length)
    }
    finally {
        $process.StandardInput.Close()
    }
    $process.WaitForExit()
    if ($process.ExitCode -ne 0) {
        throw "gh secret set failed for $Name"
    }
}

if ($null -eq (Get-Command gh -ErrorAction SilentlyContinue)) {
    throw 'GitHub CLI (gh) is required.'
}

$variablesPath = Join-Path $PSScriptRoot 'variables.env'
$secretsPath = Join-Path $PSScriptRoot 'secrets'
foreach ($path in @($variablesPath, $secretsPath)) {
    $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
    if ($item.LinkType) {
        throw "Signing bundle path must not be a symbolic link: $path"
    }
}
if (-not (Test-Path -LiteralPath $variablesPath -PathType Leaf) -or
    -not (Test-Path -LiteralPath $secretsPath -PathType Container)) {
    throw 'The signing bundle is incomplete.'
}

$variables = @()
foreach ($line in [System.IO.File]::ReadAllLines($variablesPath)) {
    $separator = $line.IndexOf('=')
    if ($separator -le 0) {
        throw 'variables.env contains an invalid value.'
    }
    $name = $line.Substring(0, $separator)
    $value = $line.Substring($separator + 1)
    if ($name -notmatch '^[A-Z][A-Z0-9_]*$' -or [string]::IsNullOrEmpty($value)) {
        throw 'variables.env contains an invalid value.'
    }
    $variables += [PSCustomObject]@{ Name = $name; Value = $value }
}

$secrets = @(
    Get-ChildItem -LiteralPath $secretsPath -File |
        Sort-Object Name |
        ForEach-Object {
            if ($_.LinkType -or $_.Name -notmatch '^[A-Z][A-Z0-9_]*$') {
                throw "secrets contains an invalid file or symbolic link: $($_.FullName)"
            }
            $_
        }
)
if ($variables.Count -eq 0 -or $secrets.Count -eq 0) {
    throw 'The signing bundle must contain at least one variable and one Secret payload.'
}

if ($PSCmdlet.ParameterSetName -eq 'Organization') {
    if ([string]::IsNullOrWhiteSpace($Organization) -or [string]::IsNullOrWhiteSpace($Repositories)) {
        throw 'Organization and Repositories must both be non-empty.'
    }
    $scopeArguments = @('--org', $Organization, '--repos', $Repositories, '--visibility', 'selected')
    $scopeLabel = "$Organization selected repositories: $Repositories"
}
else {
    if ([string]::IsNullOrWhiteSpace($Repository)) {
        throw 'Repository must be non-empty.'
    }
    $scopeArguments = @('--repo', $Repository)
    $scopeLabel = $Repository
}

Write-Host "Signing bundle target: $scopeLabel"
Write-Host "GitHub variables: $($variables.Name -join ' ')"
Write-Host "GitHub secrets: $($secrets.Name -join ' ')"
if (-not $Apply) {
    Write-Host 'Dry run only. Re-run with -Apply after reviewing metadata.json and variables.env.'
    return
}

foreach ($variable in $variables) {
    & gh variable set $variable.Name @scopeArguments --body $variable.Value
    if ($LASTEXITCODE -ne 0) {
        throw "gh variable set failed for $($variable.Name)"
    }
}
foreach ($secret in $secrets) {
    Invoke-GhSecretSet -Name $secret.Name -SecretPath $secret.FullName -ScopeArguments $scopeArguments
}

Write-Host 'GitHub Actions signing configuration updated. Run the non-publishing release candidate before promotion.'
"""


def render_readme(
    platform: str,
    distribution_trust: str,
    variables: dict[str, str],
    secrets: list[str],
) -> str:
    variable_lines = "\n".join(f"{name}={value}" for name, value in variables.items())
    secret_lines = "\n".join(f"- `{name}`" for name in secrets)
    return f"""# GitHub Actions signing configuration bundle

This protected local directory was generated for **{platform}** with
`{distribution_trust}` distribution trust. It contains the exact GitHub Actions
configuration group expected by the reviewed release workflows.

Generation does not contact GitHub. Review `metadata.json` and the public
values below before uploading. Do not commit this directory, copy its secret
files into chat, or print their contents in a terminal.

## GitHub variables

`variables.env` is directly copyable and contains only non-secret values:

```text
{variable_lines}
```

## GitHub secrets

The following values are stored as protected files under `secrets/` and are
never echoed by the upload helpers:

{secret_lines}

## Upload deliberately

The helpers first dry-run and list names only. After review, choose exactly one
scope and add the explicit apply switch:

```bash
./upload.sh --apply --repo OWNER/CLIENT_REPOSITORY
./upload.sh --apply --org OWNER --repos CLIENT_ONE,CLIENT_TWO
```

```powershell
pwsh -NoProfile -File .\\Upload.ps1 -Apply -Repository OWNER/CLIENT_REPOSITORY
pwsh -NoProfile -File .\\Upload.ps1 -Apply -Organization OWNER -Repositories CLIENT_ONE,CLIENT_TWO
```

For a shared desktop identity, use the organization scope with only its approved
consumer repositories. Android and iOS identities belong only to
`remote-client`. Setting this bundle does not register, approve, or activate an
identity: update the public signing registry through a reviewed change, then run
a non-publishing release candidate before any promotion.
"""


def create_bundle(
    output_directory: Path,
    platform: str,
    distribution_trust: str,
    public_identity: Any,
    variables: dict[str, str],
    secret_sources: dict[str, tuple[Path, bool]],
) -> Path:
    if output_directory.is_symlink() or not output_directory.is_dir():
        raise BundleError("OUTPUT_DIRECTORY must be an existing, non-symbolic-link directory")
    bundle_directory = output_directory / "github-actions"
    if bundle_directory.exists() or bundle_directory.is_symlink():
        raise BundleError(f"refusing to overwrite existing bundle: {bundle_directory}")

    temporary_directory = Path(
        tempfile.mkdtemp(prefix=".github-actions-", dir=output_directory)
    )
    try:
        os.chmod(temporary_directory, 0o700)
        secrets_directory = temporary_directory / "secrets"
        secrets_directory.mkdir(mode=0o700)
        os.chmod(secrets_directory, 0o700)

        for name, (source, encode_base64) in secret_sources.items():
            require_regular_file(source, f"secret source for {name}")
            payload = source.read_bytes()
            if not payload:
                raise BundleError(f"secret source for {name} must not be empty")
            if encode_base64:
                payload = base64.b64encode(payload)
            write_file(secrets_directory / name, payload, 0o600)

        metadata = {
            "schema_version": 1,
            "platform": platform,
            "distribution_trust": distribution_trust,
            "public_identity": public_identity,
            "github_actions": {
                "variables": [
                    {"name": name, "value": value} for name, value in variables.items()
                ],
                "secrets": list(secret_sources),
            },
        }
        write_file(
            temporary_directory / "metadata.json",
            (json.dumps(metadata, indent=2, sort_keys=True) + "\n").encode("utf-8"),
            0o600,
        )
        write_file(
            temporary_directory / "variables.env",
            "".join(f"{name}={value}\n" for name, value in variables.items()).encode(
                "utf-8"
            ),
            0o600,
        )
        write_file(
            temporary_directory / "README.md",
            render_readme(
                platform,
                distribution_trust,
                variables,
                list(secret_sources),
            ).encode("utf-8"),
            0o600,
        )
        write_file(
            temporary_directory / "upload.sh", shell_uploader().encode("utf-8"), 0o700
        )
        write_file(
            temporary_directory / "Upload.ps1",
            powershell_uploader().encode("utf-8"),
            0o700,
        )
        os.replace(temporary_directory, bundle_directory)
    except Exception:
        shutil.rmtree(temporary_directory, ignore_errors=True)
        raise
    return bundle_directory


def parse_arguments(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create a protected GitHub Actions signing-configuration bundle."
    )
    parser.add_argument("output_directory", type=Path)
    parser.add_argument("--platform", required=True, choices=sorted(PLATFORMS))
    parser.add_argument(
        "--distribution-trust", required=True, choices=sorted(TRUST_MODES)
    )
    parser.add_argument("--identity-file", required=True, type=Path)
    parser.add_argument("--variable", action="append", default=[], metavar="NAME=VALUE")
    parser.add_argument("--secret", action="append", default=[], metavar="NAME=PATH")
    parser.add_argument(
        "--secret-base64", action="append", default=[], metavar="NAME=PATH"
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> Path:
    args = parse_arguments(argv)
    variables = dict(sorted(parse_variable_assignment(value) for value in args.variable))
    if len(variables) != len(args.variable):
        raise BundleError("GitHub variable names must be unique")

    secret_sources: dict[str, tuple[Path, bool]] = {}
    for assignment, encode_base64 in (
        *((value, False) for value in args.secret),
        *((value, True) for value in args.secret_base64),
    ):
        name, source = parse_name_assignment(assignment, "secret input")
        if name in secret_sources:
            raise BundleError("GitHub secret names must be unique")
        secret_sources[name] = (source, encode_base64)
    if not variables or not secret_sources:
        raise BundleError("at least one --variable and one secret input are required")
    if set(variables).intersection(secret_sources):
        raise BundleError("a GitHub name cannot be both a variable and a secret")

    sorted_secrets = dict(sorted(secret_sources.items()))
    bundle = create_bundle(
        args.output_directory,
        args.platform,
        args.distribution_trust,
        load_public_identity(args.identity_file),
        variables,
        sorted_secrets,
    )
    print(f"Created protected GitHub Actions signing bundle: {bundle}")
    return bundle


if __name__ == "__main__":
    try:
        main()
    except BundleError as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(2) from error
