#!/usr/bin/env python3
"""Fail-closed validation for the public signing identity registry."""

from __future__ import annotations

import argparse
import json
import re
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any


STATES = {
    "not-configured",
    "configured-unregistered",
    "active",
    "retiring",
    "revoked",
}
TRUST_MODES = {"public-trust", "private-trust", "platform-key", "unresolved"}
IDENTITY_PATTERNS = {
    "x509-sha256": re.compile(r"^[0-9A-F]{64}$"),
    "openpgp-fingerprint": re.compile(r"^(?:[0-9A-F]{40}|[0-9A-F]{64})$"),
}
NATIVE_IDENTITY_PATTERNS = {
    "x509-sha1-thumbprint": re.compile(r"^[0-9A-F]{40}$"),
}
PLATFORMS = {"windows", "macos", "linux", "android", "ios"}
CONSUMERS = {"nexus", "remote-client"}
FORBIDDEN_KEYS = {
    "private_key",
    "private_key_pem",
    "password",
    "passphrase",
    "pfx_base64",
    "p12_base64",
    "keystore_base64",
    "provisioning_profile_base64",
    "secret_value",
}
SENSITIVE_SUFFIXES = {
    ".jks",
    ".keystore",
    ".mobileprovision",
    ".p12",
    ".pfx",
}
PRIVATE_MARKERS = (
    ("-----BEGIN " + "PRIVATE KEY-----").encode(),
    ("-----BEGIN " + "ENCRYPTED PRIVATE KEY-----").encode(),
    ("-----BEGIN " + "EC PRIVATE KEY-----").encode(),
    ("-----BEGIN " + "OPENSSH PRIVATE KEY-----").encode(),
    ("-----BEGIN PGP " + "PRIVATE KEY BLOCK-----").encode(),
)
REGISTRY_KEYS = {
    "$schema",
    "schema_version",
    "registry_revision",
    "organization",
    "last_reviewed_on",
    "identities",
}
IDENTITY_KEYS = {
    "id",
    "platform",
    "consumers",
    "state",
    "distribution_trust",
    "secret_names",
    "variable_names",
    "public_identity",
    "note",
}
PUBLIC_IDENTITY_KEYS = {"kind", "value", "not_after", "native_reference"}
NATIVE_REFERENCE_KEYS = {"kind", "value"}


def require_string(mapping: dict[str, Any], name: str) -> str:
    value = mapping.get(name)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be a non-empty string")
    return value


def reject_forbidden_keys(value: Any, location: str = "$") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if key.lower() in FORBIDDEN_KEYS:
                raise ValueError(f"private material field is forbidden at {location}.{key}")
            reject_forbidden_keys(child, f"{location}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            reject_forbidden_keys(child, f"{location}[{index}]")


def validate_names(values: Any, field: str) -> None:
    if (
        not isinstance(values, list)
        or len(values) != len(set(values))
        or values != sorted(values)
    ):
        raise ValueError(f"{field} must be a sorted unique array")
    for value in values:
        if not isinstance(value, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]*", value):
            raise ValueError(f"{field} contains an invalid GitHub name: {value!r}")


def validate_registry(registry: dict[str, Any]) -> None:
    reject_forbidden_keys(registry)
    if set(registry) != REGISTRY_KEYS:
        raise ValueError(
            f"registry fields differ: expected {sorted(REGISTRY_KEYS)}, "
            f"found {sorted(registry)}"
        )
    if registry.get("schema_version") != 1:
        raise ValueError("schema_version must be 1")
    if registry.get("organization") != "camellia-computing":
        raise ValueError("organization must be camellia-computing")
    revision = require_string(registry, "registry_revision")
    if not re.fullmatch(r"20\d{2}-\d{2}-\d{2}\.[1-9]\d*", revision):
        raise ValueError("registry_revision must use YYYY-MM-DD.N")
    reviewed = date.fromisoformat(require_string(registry, "last_reviewed_on"))
    if reviewed > date.today():
        raise ValueError("last_reviewed_on cannot be in the future")
    if revision.split(".", 1)[0] != reviewed.isoformat():
        raise ValueError("registry_revision date must equal last_reviewed_on")

    identities = registry.get("identities")
    if not isinstance(identities, list) or not identities:
        raise ValueError("identities must be a non-empty array")
    seen_ids: set[str] = set()
    seen_platforms: set[str] = set()
    seen_public_identities: set[tuple[str, str]] = set()
    for identity in identities:
        if not isinstance(identity, dict):
            raise ValueError("each identity must be an object")
        if set(identity) != IDENTITY_KEYS:
            raise ValueError(
                f"identity fields differ: expected {sorted(IDENTITY_KEYS)}, "
                f"found {sorted(identity)}"
            )
        identity_id = require_string(identity, "id")
        if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", identity_id):
            raise ValueError(f"invalid identity id: {identity_id}")
        if identity_id in seen_ids:
            raise ValueError(f"duplicate identity id: {identity_id}")
        seen_ids.add(identity_id)

        platform = require_string(identity, "platform")
        if platform not in PLATFORMS:
            raise ValueError(f"unsupported platform: {platform}")
        seen_platforms.add(platform)

        consumers = identity.get("consumers")
        if (
            not isinstance(consumers, list)
            or not consumers
            or consumers != sorted(set(consumers))
            or not set(consumers).issubset(CONSUMERS)
        ):
            raise ValueError(f"{identity_id} has invalid or unsorted consumers")
        state = require_string(identity, "state")
        trust = require_string(identity, "distribution_trust")
        if state not in STATES:
            raise ValueError(f"{identity_id} has invalid state: {state}")
        if trust not in TRUST_MODES:
            raise ValueError(f"{identity_id} has invalid distribution trust: {trust}")
        if state in {"active", "retiring"} and trust == "unresolved":
            raise ValueError(f"{identity_id} cannot sign while trust is unresolved")
        validate_names(identity.get("secret_names"), f"{identity_id}.secret_names")
        validate_names(identity.get("variable_names"), f"{identity_id}.variable_names")
        require_string(identity, "note")

        public_identity = identity.get("public_identity")
        if not isinstance(public_identity, dict):
            raise ValueError(f"{identity_id}.public_identity must be an object")
        if set(public_identity) != PUBLIC_IDENTITY_KEYS:
            raise ValueError(f"{identity_id}.public_identity has unexpected fields")
        kind = require_string(public_identity, "kind")
        if kind not in IDENTITY_PATTERNS:
            raise ValueError(f"{identity_id} has unsupported public identity kind")
        value = public_identity.get("value")
        not_after = public_identity.get("not_after")
        native_reference = public_identity.get("native_reference")
        if state in {"active", "retiring", "revoked"}:
            if not isinstance(value, str) or not IDENTITY_PATTERNS[kind].fullmatch(value):
                raise ValueError(f"{identity_id} requires a canonical public identity")
            identity_key = (kind, value)
            if identity_key in seen_public_identities:
                raise ValueError(f"duplicate canonical public identity: {identity_id}")
            seen_public_identities.add(identity_key)
        elif value is not None:
            raise ValueError(f"{identity_id} cannot publish an identity before registration")
        if value is None and not_after is not None:
            raise ValueError(f"{identity_id} cannot publish expiry without an identity")
        if not_after is not None:
            if not isinstance(not_after, str) or not_after.endswith("Z"):
                raise ValueError(f"{identity_id}.not_after must be a UTC RFC 3339 value")
            try:
                expiry = datetime.fromisoformat(not_after.removesuffix("Z") + "+00:00")
            except ValueError as error:
                raise ValueError(
                    f"{identity_id}.not_after must be a UTC RFC 3339 value"
                ) from error
            if expiry.tzinfo != timezone.utc:
                raise ValueError(f"{identity_id}.not_after must use UTC")
            if state in {"active", "retiring"} and expiry <= datetime.now(timezone.utc):
                raise ValueError(f"{identity_id} has an expired signing certificate")
        elif kind == "x509-sha256" and state in {"active", "retiring"}:
            raise ValueError(f"{identity_id} requires certificate expiry")

        if platform == "windows":
            if not isinstance(native_reference, dict):
                raise ValueError(f"{identity_id} requires a Windows native reference")
            if set(native_reference) != NATIVE_REFERENCE_KEYS:
                raise ValueError(f"{identity_id}.native_reference has unexpected fields")
            native_kind = require_string(native_reference, "kind")
            if native_kind != "x509-sha1-thumbprint":
                raise ValueError(f"{identity_id} has an invalid Windows reference kind")
            native_value = native_reference.get("value")
            if state in {"active", "retiring", "revoked"}:
                if (
                    not isinstance(native_value, str)
                    or not NATIVE_IDENTITY_PATTERNS[native_kind].fullmatch(native_value)
                ):
                    raise ValueError(
                        f"{identity_id} requires a canonical Windows thumbprint"
                    )
            elif native_value is not None:
                raise ValueError(
                    f"{identity_id} cannot publish a Windows reference before registration"
                )
        elif native_reference is not None:
            raise ValueError(
                f"{identity_id} may not define a platform-native identity reference"
            )

    if seen_platforms != PLATFORMS:
        raise ValueError(
            f"registry platforms differ: expected {sorted(PLATFORMS)}, "
            f"found {sorted(seen_platforms)}"
        )


def reject_tracked_sensitive_files(repository: Path) -> None:
    git_index = repository / ".git"
    if not git_index.exists():
        return
    import subprocess

    output = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=repository,
        check=True,
        capture_output=True,
    ).stdout
    for raw_path in output.split(b"\0"):
        if not raw_path:
            continue
        path = Path(raw_path.decode("utf-8"))
        if path.suffix.lower() in SENSITIVE_SUFFIXES:
            raise ValueError(f"tracked private signing container is forbidden: {path}")
        content = (repository / path).read_bytes()
        if any(marker in content for marker in PRIVATE_MARKERS):
            raise ValueError(f"tracked private key material is forbidden: {path}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "registry",
        nargs="?",
        default="config/signing-identities.json",
    )
    args = parser.parse_args()
    path = Path(args.registry)
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("registry root must be an object")
    validate_registry(value)
    reject_tracked_sensitive_files(Path.cwd())
    print(
        f"Validated signing identity registry {value['registry_revision']} "
        f"with {len(value['identities'])} platform identities"
    )


if __name__ == "__main__":
    main()
