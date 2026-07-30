#!/usr/bin/env python3
"""Fail-closed validation for the non-secret artifact-signing policy."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

TRUST_PRIORITY = (
    "public-trust",
    "private-trust",
    "platform-key",
    "ad-hoc",
    "unsigned",
)
PLATFORM_ADAPTERS = {
    "android": "android-apksigner",
    "ios": "apple-mobile-codesign",
    "linux": "openpgp",
    "macos": "apple-codesign",
    "windows": "authenticode",
}
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
    "trust_priority",
    "identities",
}
IDENTITY_KEYS = {
    "id",
    "platform",
    "consumers",
    "allowed_outcomes",
    "formal_unsigned_allowed",
    "credential_groups",
    "verification_adapter",
    "rotation_max_days",
    "note",
}
CREDENTIAL_GROUP_KEYS = {"id", "secret_names", "variable_names"}


def require_string(mapping: dict[str, Any], name: str) -> str:
    value = mapping.get(name)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be a non-empty string")
    return value


def reject_forbidden_keys(value: Any, location: str = "$") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if key.lower() in FORBIDDEN_KEYS:
                raise ValueError(
                    f"private material field is forbidden at {location}.{key}"
                )
            reject_forbidden_keys(child, f"{location}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            reject_forbidden_keys(child, f"{location}[{index}]")


def validate_names(values: Any, field: str, *, allow_empty: bool = False) -> list[str]:
    if (
        not isinstance(values, list)
        or (not values and not allow_empty)
        or any(not isinstance(value, str) for value in values)
        or values != sorted(set(values))
    ):
        qualifier = "possibly empty " if allow_empty else "non-empty "
        raise ValueError(f"{field} must be a sorted, {qualifier}unique array")
    for value in values:
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", value):
            raise ValueError(f"{field} contains an invalid GitHub name: {value!r}")
    return values


def validate_registry(registry: dict[str, Any]) -> None:
    reject_forbidden_keys(registry)
    if set(registry) != REGISTRY_KEYS:
        raise ValueError(
            f"registry fields differ: expected {sorted(REGISTRY_KEYS)}, "
            f"found {sorted(registry)}"
        )
    if registry.get("schema_version") != 2:
        raise ValueError("schema_version must be 2")
    organization = require_string(registry, "organization")
    if not re.fullmatch(
        r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?",
        organization,
    ):
        raise ValueError("organization must be a valid GitHub owner")
    revision = require_string(registry, "registry_revision")
    if not re.fullmatch(r"20\d{2}-\d{2}-\d{2}\.[1-9]\d*", revision):
        raise ValueError("registry_revision must use YYYY-MM-DD.N")
    reviewed = date.fromisoformat(require_string(registry, "last_reviewed_on"))
    if reviewed > datetime.now(timezone.utc).date():
        raise ValueError("last_reviewed_on cannot be in the future")
    if revision.split(".", 1)[0] != reviewed.isoformat():
        raise ValueError("registry_revision date must equal last_reviewed_on")
    if registry.get("trust_priority") != list(TRUST_PRIORITY):
        raise ValueError("trust_priority must use the reviewed strongest-first order")

    identities = registry.get("identities")
    if not isinstance(identities, list) or not identities:
        raise ValueError("identities must be a non-empty array")
    seen_ids: list[str] = []
    seen_platforms: set[str] = set()
    for identity in identities:
        if not isinstance(identity, dict) or set(identity) != IDENTITY_KEYS:
            raise ValueError("identity has unexpected fields")
        identity_id = require_string(identity, "id")
        if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", identity_id):
            raise ValueError(f"invalid identity id: {identity_id}")
        seen_ids.append(identity_id)

        platform = require_string(identity, "platform")
        if platform not in PLATFORM_ADAPTERS:
            raise ValueError(f"unsupported platform: {platform}")
        seen_platforms.add(platform)
        if identity.get("verification_adapter") != PLATFORM_ADAPTERS[platform]:
            raise ValueError(f"{identity_id} has an invalid verification adapter")

        consumers = identity.get("consumers")
        if (
            not isinstance(consumers, list)
            or not consumers
            or any(
                not isinstance(consumer, str)
                or not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", consumer)
                for consumer in consumers
            )
            or consumers != sorted(set(consumers))
        ):
            raise ValueError(f"{identity_id} has invalid or unsorted consumers")

        outcomes = identity.get("allowed_outcomes")
        if (
            not isinstance(outcomes, list)
            or not outcomes
            or any(outcome not in TRUST_PRIORITY for outcome in outcomes)
            or outcomes
            != sorted(set(outcomes), key=lambda outcome: TRUST_PRIORITY.index(outcome))
        ):
            raise ValueError(
                f"{identity_id}.allowed_outcomes must follow trust priority"
            )
        formal_unsigned = identity.get("formal_unsigned_allowed")
        if not isinstance(formal_unsigned, bool):
            raise TypeError(f"{identity_id}.formal_unsigned_allowed must be boolean")
        if formal_unsigned and "unsigned" not in outcomes:
            raise ValueError(
                f"{identity_id} allows unsigned without an unsigned outcome"
            )

        rotation_days = identity.get("rotation_max_days")
        if (
            not isinstance(rotation_days, int)
            or isinstance(rotation_days, bool)
            or not 0 <= rotation_days <= 90
        ):
            raise ValueError(
                f"{identity_id}.rotation_max_days must be between 0 and 90"
            )

        credential_groups = identity.get("credential_groups")
        if not isinstance(credential_groups, list) or not credential_groups:
            raise ValueError(f"{identity_id} requires credential groups")
        group_ids: list[str] = []
        all_names: set[str] = set()
        for group in credential_groups:
            if not isinstance(group, dict) or set(group) != CREDENTIAL_GROUP_KEYS:
                raise ValueError(f"{identity_id} has an invalid credential group")
            group_id = require_string(group, "id")
            if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", group_id):
                raise ValueError(f"{identity_id} has an invalid credential group id")
            group_ids.append(group_id)
            names = validate_names(
                group.get("secret_names"),
                f"{identity_id}.{group_id}.secret_names",
            )
            names += validate_names(
                group.get("variable_names"),
                f"{identity_id}.{group_id}.variable_names",
                allow_empty=True,
            )
            overlap = all_names.intersection(names)
            if overlap:
                raise ValueError(
                    f"{identity_id} reuses credential names: {sorted(overlap)}"
                )
            all_names.update(names)
        if group_ids != sorted(set(group_ids)):
            raise ValueError(
                f"{identity_id} credential groups must be sorted and unique"
            )
        require_string(identity, "note")

    if seen_ids != sorted(set(seen_ids)):
        raise ValueError("identity ids must be sorted and unique")
    if seen_platforms != set(PLATFORM_ADAPTERS):
        raise ValueError(
            f"registry platforms differ: expected {sorted(PLATFORM_ADAPTERS)}, "
            f"found {sorted(seen_platforms)}"
        )


def reject_tracked_sensitive_files(repository: Path) -> None:
    if not (repository / ".git").exists():
        return
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
    if path.is_symlink() or not path.is_file():
        raise ValueError("registry must be a regular, non-symbolic-link file")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise TypeError("registry root must be an object")
    validate_registry(value)
    reject_tracked_sensitive_files(Path.cwd())
    print(
        f"Validated signing policy {value['registry_revision']} "
        f"with {len(value['identities'])} platform identities"
    )


if __name__ == "__main__":
    main()
