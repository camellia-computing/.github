#!/usr/bin/env python3
"""Fail closed when mutable GitHub coordinates escape reviewed identity surfaces."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

from audit_repository_policies import REPOSITORY_ROOT, load_config, validate_config

OWNER_LITERAL_ALLOWLIST = {
    ".github/CODEOWNERS",
    ".github/ISSUE_TEMPLATE/config.yml",
    "config/repository-policies.json",
    "config/signing-identities.json",
    "profile/README.md",
}
PHYSICAL_NAME_ALLOWLIST = {
    ".github/CODEOWNERS",
    ".github/ISSUE_TEMPLATE/config.yml",
    "config/repository-policies.json",
    "profile/README.md",
}
MACHINE_PATH_PATTERNS = (
    re.compile(r"(?<![$\w])/(?:home|Users)/[A-Za-z0-9._-]+/"),
    re.compile(r"(?i)\b[A-Z]:[\\/]+Users[\\/]+[^\\/\s]+[\\/]"),
    re.compile(r"(?i)(?<![$\w])/mnt/[A-Z]/Users/[^/\s]+/"),
)


def tracked_text(root: Path) -> dict[str, str]:
    result = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=root,
        check=True,
        capture_output=True,
    )
    files: dict[str, str] = {}
    for raw_path in result.stdout.split(b"\0"):
        if not raw_path:
            continue
        relative = raw_path.decode("utf-8")
        try:
            files[relative] = (root / relative).read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
    return files


def load_object(path: Path, label: str) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise TypeError(f"{label} must be a JSON object")
    return value


def validate_rename_fixture(
    config: dict[str, Any],
    fixture: dict[str, Any],
) -> list[str]:
    errors: list[str] = []
    if set(fixture) != {"organization", "repository_names"}:
        return ["rename fixture has unexpected fields"]
    organization = fixture.get("organization")
    repository_names = fixture.get("repository_names")
    if not isinstance(organization, str) or not isinstance(repository_names, dict):
        return ["rename fixture organization and repository_names are required"]

    renamed = json.loads(json.dumps(config))
    renamed["organization"] = organization
    original_security_identity = (
        renamed["code_security_configuration"]["logical_id"],
        renamed["code_security_configuration"]["configuration_id"],
    )
    original_identity = {
        policy["logical_id"]: (
            policy["repository_id"],
            tuple(policy["artifact_ids"]),
        )
        for policy in renamed["repositories"]
    }
    if set(repository_names) != set(original_identity):
        errors.append(
            "rename fixture must map every repository logical_id exactly once"
        )
        return errors
    for policy in renamed["repositories"]:
        policy["name"] = repository_names[policy["logical_id"]]
    try:
        validate_config(renamed)
    except (TypeError, ValueError) as error:
        errors.append(f"rename fixture is not a valid policy migration: {error}")
        return errors
    renamed_identity = {
        policy["logical_id"]: (
            policy["repository_id"],
            tuple(policy["artifact_ids"]),
        )
        for policy in renamed["repositories"]
    }
    if renamed_identity != original_identity:
        errors.append(
            "rename fixture changed immutable repository or artifact identities"
        )
    renamed_security_identity = (
        renamed["code_security_configuration"]["logical_id"],
        renamed["code_security_configuration"]["configuration_id"],
    )
    if renamed_security_identity != original_security_identity:
        errors.append("rename fixture changed the code-security configuration identity")
    return errors


def validate_identity_surfaces(
    root: Path,
    config: dict[str, Any],
    files: dict[str, str],
) -> list[str]:
    errors: list[str] = []
    organization = config["organization"]
    repositories = config["repositories"]
    governance = next(
        policy for policy in repositories if policy["logical_id"] == "governance"
    )

    signing = load_object(root / "config/signing-identities.json", "signing registry")
    if signing.get("organization") != organization:
        errors.append("signing registry organization differs from repository policy")
    repositories_by_logical_id = {
        policy["logical_id"]: policy for policy in repositories
    }
    signing_consumers = {
        consumer
        for identity in signing.get("identities", [])
        if isinstance(identity, dict)
        for consumer in identity.get("consumers", [])
        if isinstance(consumer, str)
    }
    invalid_consumers = sorted(
        consumer
        for consumer in signing_consumers
        if consumer not in repositories_by_logical_id
        or repositories_by_logical_id[consumer]["profile"] != "release-client"
        or not repositories_by_logical_id[consumer]["artifact_ids"]
    )
    if invalid_consumers:
        errors.append(
            "signing consumers are not artifact-producing client logical IDs: "
            f"{invalid_consumers}"
        )

    team_slugs = sorted(
        {team["slug"] for policy in repositories for team in policy["access_teams"]}
    )
    expected_codeowners = (
        "* " + " ".join(f"@{organization}/{slug}" for slug in team_slugs) + "\n"
    )
    if files.get(".github/CODEOWNERS") != expected_codeowners:
        errors.append("CODEOWNERS is not the deterministic policy-derived team surface")

    issue_config = files.get(".github/ISSUE_TEMPLATE/config.yml", "")
    governance_root = (
        f"https://github.com/{organization}/{governance['name']}/blob/main"
    )
    for document in ("SECURITY.md", "SUPPORT.md"):
        expected_url = f"{governance_root}/{document}"
        if expected_url not in issue_config:
            errors.append(
                f"issue template is missing policy-derived URL: {expected_url}"
            )

    expected_profile_urls = {
        f"https://github.com/{organization}/{policy['name']}"
        for policy in repositories
        if policy["logical_id"] != "governance"
    }
    actual_profile_urls = set(
        re.findall(
            r"https://github\.com/[A-Za-z0-9-]+/[A-Za-z0-9._-]+",
            files.get("profile/README.md", ""),
        )
    )
    if actual_profile_urls != expected_profile_urls:
        errors.append(
            "profile repository links differ from the logical-to-physical policy map"
        )
    return errors


def audit_portability(
    root: Path,
    config_path: Path,
    rename_fixture_path: Path,
) -> list[str]:
    config = load_config(config_path)
    fixture = load_object(rename_fixture_path, "rename fixture")
    files = tracked_text(root)
    errors = validate_rename_fixture(config, fixture)
    errors.extend(validate_identity_surfaces(root, config, files))

    organization = config["organization"]
    for relative, content in files.items():
        if organization.casefold() in content.casefold() and (
            relative not in OWNER_LITERAL_ALLOWLIST
        ):
            errors.append(
                f"{relative}: mutable organization login escaped its reviewed surfaces"
            )
        for pattern in MACHINE_PATH_PATTERNS:
            if pattern.search(content):
                errors.append(f"{relative}: contains a machine-specific absolute path")
                break

    for policy in config["repositories"]:
        physical_name = policy["name"]
        if physical_name.casefold() == policy["logical_id"].casefold():
            continue
        token = f"`{physical_name}`"
        for relative, content in files.items():
            if relative not in PHYSICAL_NAME_ALLOWLIST and token in content:
                errors.append(
                    f"{relative}: use logical_id {policy['logical_id']!r} "
                    f"instead of mutable repository name {physical_name!r}"
                )
    return sorted(set(errors))


def main() -> int:
    root = REPOSITORY_ROOT
    config_path = root / "config/repository-policies.json"
    fixture_path = root / "scripts/fixtures/repository-rename.json"
    errors = audit_portability(root, config_path, fixture_path)
    if errors:
        for error in errors:
            print(f"portability: {error}", file=sys.stderr)
        return 1
    print("Portability audit: compliant")
    return 0


if __name__ == "__main__":
    sys.exit(main())
