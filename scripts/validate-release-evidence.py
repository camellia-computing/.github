#!/usr/bin/env python3
"""Validate release evidence and fail on contradictory signing claims."""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

CATEGORIES = {
    "public-trust",
    "private-trust",
    "platform-key",
    "ad-hoc",
    "unsigned",
}
PLATFORMS = {"android", "ios", "linux", "macos", "source", "windows"}
DISTRIBUTIONS = {"public", "private", "restricted", "source-only"}
ROOT_KEYS = {
    "schema_version",
    "repository",
    "version",
    "source",
    "release_kind",
    "generated_at",
    "artifacts",
}
SOURCE_KEYS = {"commit", "ref"}
ARTIFACT_KEYS = {
    "name",
    "sha256",
    "size_bytes",
    "platform",
    "architecture",
    "sbom",
    "provenance",
    "signing",
}
EVIDENCE_FILE_KEYS = {"name", "sha256"}
SIGNING_KEYS = {
    "category",
    "verification",
    "verifier",
    "timestamp",
    "distribution",
    "evidence",
}


def require_string(mapping: dict[str, Any], name: str) -> str:
    value = mapping.get(name)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be a non-empty string")
    return value


def validate_evidence_file(value: Any, location: str) -> None:
    if not isinstance(value, dict) or set(value) != EVIDENCE_FILE_KEYS:
        raise ValueError(f"{location} has unexpected fields")
    require_string(value, "name")
    if not re.fullmatch(r"[0-9a-f]{64}", require_string(value, "sha256")):
        raise ValueError(f"{location}.sha256 must be lowercase SHA-256")


def validate_signing(value: Any, location: str) -> None:
    if not isinstance(value, dict) or set(value) != SIGNING_KEYS:
        raise ValueError(f"{location} has unexpected fields")
    category = require_string(value, "category")
    verification = require_string(value, "verification")
    verifier = require_string(value, "verifier")
    timestamp = require_string(value, "timestamp")
    distribution = require_string(value, "distribution")
    evidence = value.get("evidence")
    if category not in CATEGORIES:
        raise ValueError(f"{location}.category is invalid")
    if timestamp not in {"verified", "missing", "not-applicable"}:
        raise ValueError(f"{location}.timestamp is invalid")
    if distribution not in DISTRIBUTIONS:
        raise ValueError(f"{location}.distribution is invalid")
    if (
        not isinstance(evidence, list)
        or any(not isinstance(item, str) or not item for item in evidence)
        or evidence != sorted(set(evidence))
    ):
        raise ValueError(f"{location}.evidence must be a sorted unique string array")
    if category == "unsigned":
        if verification != "not-present" or verifier != "none":
            raise ValueError(f"{location} contradicts its unsigned category")
        if timestamp != "not-applicable" or evidence:
            raise ValueError(f"{location} unsigned evidence must be empty")
    else:
        if verification != "verified" or verifier == "none" or not evidence:
            raise ValueError(f"{location} signed evidence must be verified")
    if category == "ad-hoc" and distribution == "public":
        raise ValueError(
            f"{location} ad-hoc artifacts cannot claim public distribution"
        )


def validate_release_evidence(value: dict[str, Any]) -> None:
    if set(value) != ROOT_KEYS:
        raise ValueError("release evidence has unexpected fields")
    if value.get("schema_version") != 1:
        raise ValueError("schema_version must be 1")
    if not re.fullmatch(
        r"[a-z0-9]+(?:-[a-z0-9]+)*",
        require_string(value, "repository"),
    ):
        raise ValueError("repository must be a logical repository id")
    if not re.fullmatch(
        r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z]+(?:\.[0-9A-Za-z]+)*)?",
        require_string(value, "version"),
    ):
        raise ValueError("version must be SemVer without a v prefix or build metadata")
    source = value.get("source")
    if not isinstance(source, dict) or set(source) != SOURCE_KEYS:
        raise ValueError("source has unexpected fields")
    if not re.fullmatch(r"[0-9a-f]{40}", require_string(source, "commit")):
        raise ValueError("source.commit must be a full lowercase commit SHA")
    require_string(source, "ref")
    if value.get("release_kind") not in {"candidate", "formal"}:
        raise ValueError("release_kind must be candidate or formal")
    generated_at = require_string(value, "generated_at")
    if not generated_at.endswith("Z"):
        raise ValueError("generated_at must use UTC")
    try:
        timestamp = datetime.fromisoformat(generated_at.removesuffix("Z") + "+00:00")
    except ValueError as error:
        raise ValueError("generated_at must be RFC 3339") from error
    if timestamp.tzinfo != timezone.utc:
        raise ValueError("generated_at must use UTC")

    artifacts = value.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise ValueError("artifacts must be a non-empty array")
    names: list[str] = []
    for index, artifact in enumerate(artifacts):
        location = f"artifacts[{index}]"
        if not isinstance(artifact, dict) or set(artifact) != ARTIFACT_KEYS:
            raise ValueError(f"{location} has unexpected fields")
        name = require_string(artifact, "name")
        names.append(name)
        if not re.fullmatch(r"[0-9a-f]{64}", require_string(artifact, "sha256")):
            raise ValueError(f"{location}.sha256 must be lowercase SHA-256")
        size = artifact.get("size_bytes")
        if not isinstance(size, int) or isinstance(size, bool) or size < 1:
            raise ValueError(f"{location}.size_bytes must be positive")
        if artifact.get("platform") not in PLATFORMS:
            raise ValueError(f"{location}.platform is invalid")
        if not re.fullmatch(
            r"[a-z0-9]+(?:-[a-z0-9]+)*",
            require_string(artifact, "architecture"),
        ):
            raise ValueError(f"{location}.architecture is invalid")
        validate_evidence_file(artifact.get("sbom"), f"{location}.sbom")
        validate_evidence_file(artifact.get("provenance"), f"{location}.provenance")
        validate_signing(artifact.get("signing"), f"{location}.signing")
    if names != sorted(set(names)):
        raise ValueError("artifacts must be sorted and unique by name")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("evidence", type=Path)
    args = parser.parse_args()
    value = json.loads(args.evidence.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise TypeError("release evidence root must be an object")
    validate_release_evidence(value)
    print(f"Validated release evidence for {len(value['artifacts'])} artifacts")


if __name__ == "__main__":
    main()
