#!/usr/bin/env python3
"""Validate the immutable four-repository Remote system evidence contract.

This parser is deliberately independent of candidate repository code. A system
run may only be accepted when the governance checkout validates the complete
manifest, all source/image/artifact relationships, and the fixed scenario set.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

COMMIT = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
HASH = re.compile(r"^[0-9a-f]{64}$")
NAME = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
REPOSITORY = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,98}[A-Za-z0-9])?$")
REF = re.compile(
    r"^(?:refs/(?:heads|tags)/[A-Za-z0-9._/-]{1,200}|refs/commits/[0-9a-f]{40})$"
)
VERSION = re.compile(r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$")
ISO_UTC = re.compile(r"^20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
PORT_RANGE = re.compile(r"^([1-9][0-9]{3,4})-([1-9][0-9]{3,4})$")
CANARY = re.compile(
    r"(?i)(?:bearer\s+|basic\s+|password\s*=|secret\s*=|token\s*=|-----begin\s+|"
    r"-----end\s+)"
)

LOGICAL_REPOSITORIES = (
    "remote-client",
    "remote-management",
    "remote-protocol",
    "remote-server",
)
SERVICE_REPOSITORIES = {"remote-management", "remote-server"}
SCENARIOS = (
    "auth-device-verification",
    "direct-session",
    "forced-relay-session",
    "first-frame-input",
    "file-clipboard-audit",
    "reconnect-shutdown",
)
REQUIRED_ARTIFACTS = {
    "remote-client-web": ("remote-client", "web"),
    "remote-client-controller": ("remote-client", "controller"),
    "remote-server-image": ("remote-server", "image"),
    "remote-management-image": ("remote-management", "image"),
}
FORBIDDEN_FIELD_TOKENS = (
    "password",
    "secret",
    "token",
    "private_key",
    "credential",
    "cookie",
    "authorization",
    "raw_log",
    "pii",
)
ROOT_KEYS = {
    "schema_version",
    "contract_revision",
    "organization",
    "run",
    "candidates",
    "compatibility",
    "scenarios",
    "isolation",
    "evidence",
}
CANDIDATE_KEYS = {
    "logical_id",
    "repository",
    "commit",
    "ref",
    "version",
    "image",
    "artifacts",
    "protocol_commit",
    "web_client_commit",
}
IMAGE_KEYS = {"repository", "digest", "platforms", "source_commit"}
ARTIFACT_KEYS = {"name", "kind", "sha256", "size_bytes", "source_commit"}
RUN_KEYS = {
    "id",
    "mode",
    "started_at",
    "finished_at",
    "workflow_ref",
    "runner",
    "harness_commit",
}
COMPATIBILITY_KEYS = {
    "protocol_commit",
    "client_protocol_commit",
    "server_protocol_commit",
    "client_web_commit",
}
SCENARIO_KEYS = {"name", "status", "attempt_id", "duration_ms", "evidence_sha256"}
ISOLATION_KEYS = {
    "compose_project",
    "network",
    "volume_prefix",
    "credential_namespace",
    "port_range",
}
EVIDENCE_KEYS = {"files", "retention_days"}


class ManifestError(ValueError):
    """Raised for any untrusted or incompatible manifest input."""


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ManifestError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def parse_json(data: bytes, label: str) -> Any:
    if len(data) > 262_144:
        raise ManifestError(f"{label} exceeds 262144 bytes")
    try:
        return json.loads(
            data.decode("utf-8"),
            object_pairs_hook=unique_object,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ManifestError(f"{label} contains non-finite number {value}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ManifestError(f"{label} is not valid UTF-8 JSON") from error


def exact_keys(value: Any, expected: set[str], location: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise ManifestError(f"{location} has unexpected fields")
    return value


def string(value: Any, location: str, pattern: re.Pattern[str] | None = None) -> str:
    if not isinstance(value, str) or not value:
        raise ManifestError(f"{location} must be a non-empty string")
    if pattern is not None and not pattern.fullmatch(value):
        raise ManifestError(f"{location} has an invalid format")
    return value


def integer(
    value: Any,
    location: str,
    *,
    minimum: int = 0,
    maximum: int | None = None,
) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise ManifestError(f"{location} must be an integer >= {minimum}")
    if maximum is not None and value > maximum:
        raise ManifestError(f"{location} exceeds maximum {maximum}")
    return value


def sha(value: Any, location: str) -> str:
    return string(value, location, HASH)


def commit(value: Any, location: str) -> str:
    return string(value, location, COMMIT)


def scan_for_secrets(value: Any, location: str = "manifest") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ManifestError(f"{location} contains a non-string field name")
            lowered = key.casefold()
            if lowered != "credential_namespace" and any(
                token in lowered for token in FORBIDDEN_FIELD_TOKENS
            ):
                raise ManifestError(
                    f"{location}.{key} is not an allowed evidence field"
                )
            scan_for_secrets(item, f"{location}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            scan_for_secrets(item, f"{location}[{index}]")
    elif isinstance(value, str) and CANARY.search(value):
        raise ManifestError(f"{location} contains a credential canary")


def iso_utc(value: Any, location: str) -> str:
    result = string(value, location, ISO_UTC)
    try:
        parsed = datetime.fromisoformat(result.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError("UTC offset is missing")
    except ValueError as error:
        raise ManifestError(f"{location} is not a real UTC timestamp") from error
    return result


def load_contract(path: Path) -> dict[str, Any]:
    value = parse_json(path.read_bytes(), "contract")
    if not isinstance(value, dict):
        raise ManifestError("contract must be an object")
    if (
        value.get("schema_version") != 1
        or value.get("organization") != "camellia-computing"
    ):
        raise ManifestError("unsupported Remote system contract")
    if value.get("logical_repositories") != list(LOGICAL_REPOSITORIES):
        raise ManifestError("contract logical repository order is invalid")
    if value.get("service_repositories") != sorted(SERVICE_REPOSITORIES):
        raise ManifestError("contract service repository set is invalid")
    if value.get("scenarios") != list(SCENARIOS):
        raise ManifestError("contract scenario set is invalid")
    if value.get("required_images") != ["remote-management", "remote-server"]:
        raise ManifestError("contract image set is invalid")
    if value.get("required_artifacts") != [
        "remote-client-web",
        "remote-client-controller",
        "remote-server-image",
        "remote-management-image",
    ]:
        raise ManifestError("contract artifact set is invalid")
    modes = value.get("modes")
    if not isinstance(modes, dict) or set(modes) != {"smoke", "exhaustive"}:
        raise ManifestError("contract modes are invalid")
    smoke = modes["smoke"]
    exhaustive = modes["exhaustive"]
    if (
        not isinstance(smoke, dict)
        or smoke.get("max_duration_seconds") != 900
        or smoke.get("required_scenarios")
        != [
            "auth-device-verification",
            "direct-session",
            "forced-relay-session",
            "first-frame-input",
            "reconnect-shutdown",
        ]
        or not isinstance(exhaustive, dict)
        or exhaustive.get("max_duration_seconds") != 7200
        or exhaustive.get("required_scenarios") != list(SCENARIOS)
    ):
        raise ManifestError("contract mode budgets or scenarios are invalid")
    policy = value.get("artifact_policy")
    if (
        not isinstance(policy, dict)
        or policy.get("retention_days") != 7
        or policy.get("max_manifest_bytes") != 262144
        or policy.get("max_evidence_bytes") != 4194304
        or policy.get("forbidden_field_tokens") != list(FORBIDDEN_FIELD_TOKENS)
    ):
        raise ManifestError("contract artifact retention must be seven days")
    isolation = value.get("isolation")
    if not isinstance(isolation, dict) or isolation != {
        "required": [
            "compose_project",
            "network",
            "volume_prefix",
            "credential_namespace",
            "port_range",
        ],
        "max_name_length": 63,
    }:
        raise ManifestError("contract isolation requirements are invalid")
    return value


def repository_map(value: str) -> dict[str, str]:
    parsed = parse_json(value.encode(), "REMOTE_REPOSITORY_MAP")
    if not isinstance(parsed, dict) or tuple(sorted(parsed)) != LOGICAL_REPOSITORIES:
        raise ManifestError("REMOTE_REPOSITORY_MAP must contain all four logical IDs")
    result: dict[str, str] = {}
    for logical_id in LOGICAL_REPOSITORIES:
        result[logical_id] = string(
            parsed[logical_id],
            f"REMOTE_REPOSITORY_MAP.{logical_id}",
            REPOSITORY,
        )
    if len({item.casefold() for item in result.values()}) != len(result):
        raise ManifestError("REMOTE_REPOSITORY_MAP contains duplicate physical names")
    return result


def validate_image(value: Any, location: str, candidate_commit: str) -> dict[str, Any]:
    image = exact_keys(value, IMAGE_KEYS, location)
    string(
        image["repository"],
        f"{location}.repository",
        re.compile(r"^[a-z0-9./_-]{3,250}$"),
    )
    string(image["digest"], f"{location}.digest", DIGEST)
    platforms = image["platforms"]
    if (
        not isinstance(platforms, list)
        or not platforms
        or any(
            not isinstance(item, str) or item not in {"linux/amd64", "linux/arm64"}
            for item in platforms
        )
        or platforms != sorted(set(platforms))
    ):
        raise ManifestError(f"{location}.platforms must be sorted and unique")
    if image["source_commit"] != candidate_commit:
        raise ManifestError(f"{location}.source_commit does not match candidate")
    return image


def validate_artifact(
    value: Any, location: str, candidate_commit: str
) -> dict[str, Any]:
    artifact = exact_keys(value, ARTIFACT_KEYS, location)
    string(
        artifact["name"],
        f"{location}.name",
        re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$"),
    )
    string(
        artifact["kind"],
        f"{location}.kind",
        re.compile(r"^(?:web|controller|image|source)$"),
    )
    sha(artifact["sha256"], f"{location}.sha256")
    integer(
        artifact["size_bytes"],
        f"{location}.size_bytes",
        minimum=1,
        maximum=4_194_304,
    )
    if artifact["source_commit"] != candidate_commit:
        raise ManifestError(f"{location}.source_commit does not match candidate")
    return artifact


def validate_candidate(
    value: Any, logical_id: str, names: dict[str, str]
) -> dict[str, Any]:
    candidate = exact_keys(value, CANDIDATE_KEYS, f"candidate[{logical_id}]")
    if candidate["logical_id"] != logical_id:
        raise ManifestError(f"candidate[{logical_id}] logical ID mismatch")
    if candidate["repository"] != names[logical_id]:
        raise ManifestError(
            f"candidate[{logical_id}] repository does not match reviewed map"
        )
    candidate_commit = commit(candidate["commit"], f"candidate[{logical_id}].commit")
    string(candidate["ref"], f"candidate[{logical_id}].ref", REF)
    if candidate["version"] is not None:
        string(candidate["version"], f"candidate[{logical_id}].version", VERSION)
    if candidate["protocol_commit"] is not None:
        commit(candidate["protocol_commit"], f"candidate[{logical_id}].protocol_commit")
    if candidate["web_client_commit"] is not None:
        commit(
            candidate["web_client_commit"], f"candidate[{logical_id}].web_client_commit"
        )
    image = candidate["image"]
    if logical_id in SERVICE_REPOSITORIES:
        validate_image(image, f"candidate[{logical_id}].image", candidate_commit)
    elif image is not None:
        raise ManifestError(f"candidate[{logical_id}] cannot publish an image")
    artifacts = candidate["artifacts"]
    if not isinstance(artifacts, list) or not artifacts:
        raise ManifestError(f"candidate[{logical_id}].artifacts must be non-empty")
    validated = [
        validate_artifact(
            item,
            f"candidate[{logical_id}].artifacts[{index}]",
            candidate_commit,
        )
        for index, item in enumerate(artifacts)
    ]
    names_seen = [item["name"] for item in validated]
    if names_seen != sorted(set(names_seen)):
        raise ManifestError(
            f"candidate[{logical_id}].artifacts must be sorted and unique"
        )
    return candidate


def validate_manifest(
    value: Any,
    contract: dict[str, Any],
    names: dict[str, str],
) -> dict[str, Any]:
    manifest = exact_keys(value, ROOT_KEYS, "manifest")
    if (
        manifest["schema_version"] != 1
        or manifest["organization"] != "camellia-computing"
    ):
        raise ManifestError("manifest schema or organization is invalid")
    if manifest["contract_revision"] != contract["contract_revision"]:
        raise ManifestError("manifest contract revision is not the reviewed revision")
    run = exact_keys(manifest["run"], RUN_KEYS, "run")
    run_id = string(run["id"], "run.id", NAME)
    mode = string(run["mode"], "run.mode", re.compile(r"^(?:smoke|exhaustive)$"))
    started = iso_utc(run["started_at"], "run.started_at")
    finished = iso_utc(run["finished_at"], "run.finished_at")
    if finished < started:
        raise ManifestError("run.finished_at precedes run.started_at")
    workflow_ref = string(run["workflow_ref"], "run.workflow_ref")
    if workflow_ref != (
        "camellia-computing/.github/.github/workflows/"
        "remote-system-e2e.yml@refs/heads/main"
    ):
        raise ManifestError(
            "manifest was not produced by the protected organization harness"
        )
    if run["runner"] != "camellia-remote-system-harness":
        raise ManifestError("manifest runner identity is invalid")
    harness_commit = commit(run["harness_commit"], "run.harness_commit")

    candidates = manifest["candidates"]
    candidate_ids = (
        [
            item.get("logical_id") if isinstance(item, dict) else None
            for item in candidates
        ]
        if isinstance(candidates, list)
        else []
    )
    if candidate_ids != list(LOGICAL_REPOSITORIES):
        raise ManifestError(
            "manifest candidates must contain the four logical IDs in order"
        )
    validated = {
        logical_id: validate_candidate(item, logical_id, names)
        for logical_id, item in zip(LOGICAL_REPOSITORIES, candidates)
    }
    protocol_commit = validated["remote-protocol"]["commit"]
    for logical_id in ("remote-client", "remote-server"):
        if validated[logical_id]["protocol_commit"] != protocol_commit:
            raise ManifestError(
                f"{logical_id} does not pin the selected Protocol commit"
            )
    if (
        validated["remote-management"]["web_client_commit"]
        != validated["remote-client"]["commit"]
    ):
        raise ManifestError(
            "Management Web artifact is not sourced from the selected Client commit"
        )

    compatibility = exact_keys(
        manifest["compatibility"], COMPATIBILITY_KEYS, "compatibility"
    )
    if (
        compatibility["protocol_commit"] != protocol_commit
        or compatibility["client_protocol_commit"] != protocol_commit
        or compatibility["server_protocol_commit"] != protocol_commit
    ):
        raise ManifestError("compatibility Protocol pins do not agree")
    if compatibility["client_web_commit"] != validated["remote-client"]["commit"]:
        raise ManifestError("compatibility Web commit does not agree")
    for key in COMPATIBILITY_KEYS:
        commit(compatibility[key], f"compatibility.{key}")

    artifacts: dict[str, tuple[str, str]] = {}
    for logical_id, candidate in validated.items():
        for artifact in candidate["artifacts"]:
            name = artifact["name"]
            if name in artifacts:
                raise ManifestError(f"duplicate artifact name: {name}")
            artifacts[name] = (logical_id, artifact["kind"])
    for name, (logical_id, kind) in REQUIRED_ARTIFACTS.items():
        if artifacts.get(name) != (logical_id, kind):
            raise ManifestError(
                f"required artifact {name} is missing or owned by the wrong candidate"
            )

    scenarios = manifest["scenarios"]
    if not isinstance(scenarios, list):
        raise ManifestError("manifest.scenarios must be an array")
    required = contract["modes"][mode]["required_scenarios"]
    scenario_ids = [
        item.get("name") if isinstance(item, dict) else None for item in scenarios
    ]
    if scenario_ids != required:
        raise ManifestError("manifest scenarios do not match the selected mode")
    for index, scenario_value in enumerate(scenarios):
        scenario = exact_keys(scenario_value, SCENARIO_KEYS, f"scenarios[{index}]")
        string(scenario["name"], f"scenarios[{index}].name")
        if scenario["status"] != "passed":
            raise ManifestError(f"scenario {scenario['name']} did not pass")
        string(scenario["attempt_id"], f"scenarios[{index}].attempt_id", NAME)
        integer(
            scenario["duration_ms"],
            f"scenarios[{index}].duration_ms",
            minimum=1,
            maximum=7_200_000,
        )
        sha(scenario["evidence_sha256"], f"scenarios[{index}].evidence_sha256")

    isolation = exact_keys(manifest["isolation"], ISOLATION_KEYS, "isolation")
    prefix = f"camellia-remote-e2e-{run_id}"
    for key in ("compose_project", "network", "volume_prefix", "credential_namespace"):
        value = string(isolation[key], f"isolation.{key}", NAME)
        if not value.startswith(prefix) or len(value) > 63:
            raise ManifestError(f"isolation.{key} must be a unique run-scoped name")
    match = PORT_RANGE.fullmatch(
        string(isolation["port_range"], "isolation.port_range")
    )
    if match is None or int(match.group(2)) - int(match.group(1)) < 15:
        raise ManifestError("isolation.port_range must provide at least 16 ports")

    evidence = exact_keys(manifest["evidence"], EVIDENCE_KEYS, "evidence")
    if evidence["retention_days"] != 7:
        raise ManifestError("evidence retention must be exactly seven days")
    files = evidence["files"]
    if not isinstance(files, list) or not files:
        raise ManifestError("evidence.files must be non-empty")
    names_seen: set[str] = set()
    total_bytes = 0
    for index, item in enumerate(files):
        file_value = exact_keys(
            item,
            {"name", "sha256", "size_bytes"},
            f"evidence.files[{index}]",
        )
        file_name = string(
            file_value["name"],
            f"evidence.files[{index}].name",
            re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$"),
        )
        if file_name in names_seen:
            raise ManifestError(f"duplicate evidence file: {file_name}")
        names_seen.add(file_name)
        sha(file_value["sha256"], f"evidence.files[{index}].sha256")
        total_bytes += integer(
            file_value["size_bytes"],
            f"evidence.files[{index}].size_bytes",
            minimum=1,
            maximum=4_194_304,
        )
    if total_bytes > 4_194_304:
        raise ManifestError("evidence exceeds the four MiB bounded artifact budget")
    if harness_commit in {candidate["commit"] for candidate in validated.values()}:
        raise ManifestError("harness commit must be distinct from candidate commits")
    return manifest


def canonical_bytes(value: dict[str, Any]) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode()


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--manifest", type=Path, required=True)
    result.add_argument(
        "--contract",
        type=Path,
        default=Path(__file__).parents[1] / "config/remote-system-contract.json",
    )
    result.add_argument("--repository-map", required=True)
    result.add_argument("--canonical-output", type=Path)
    result.add_argument("--github-output", action="store_true")
    return result


def main(arguments: list[str] | None = None) -> int:
    args = parser().parse_args(arguments)
    try:
        contract = load_contract(args.contract)
        names = repository_map(args.repository_map)
        value = parse_json(args.manifest.read_bytes(), "manifest")
        scan_for_secrets(value)
        manifest = validate_manifest(value, contract, names)
        canonical = canonical_bytes(manifest)
        digest = hashlib.sha256(canonical).hexdigest()
        if args.canonical_output is not None:
            args.canonical_output.write_bytes(canonical)
        if args.github_output:
            import os

            output = Path(os.environ["GITHUB_OUTPUT"])
            with output.open("a", encoding="utf-8") as stream:
                stream.write(f"manifest_sha256={digest}\n")
        print(f"validated Remote system manifest: {digest}")
        return 0
    except (OSError, ManifestError) as error:
        print(f"remote system manifest rejected: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
