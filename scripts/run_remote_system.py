#!/usr/bin/env python3
"""Run the base-owned Remote system smoke/exhaustive harness.

The runner owns process arguments, timeouts, isolation names and cleanup. A
candidate repository supplies only immutable source/image/artifact metadata and
is never allowed to replace this executable or its scenario list.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import validate_remote_system_manifest as contract
except ModuleNotFoundError:  # unittest imports this file as scripts.run_remote_system.
    from scripts import validate_remote_system_manifest as contract


TEMPLATE_KEYS = {
    "schema_version",
    "contract_revision",
    "organization",
    "candidates",
    "compatibility",
}
DRIVER_KEYS = {"status", "attempt_id", "evidence_file"}
DRIVER_STATUS = re.compile(r"^(?:passed|failed)$")
POSTGRES_IMAGE = (
    "postgres:18-alpine@sha256:"
    "9a8afca54e7861fd90fab5fdf4c42477a6b1cb7d293595148e674e0a3181de15"
)


class HarnessError(RuntimeError):
    """Raised when the trusted harness cannot prove a complete run."""


def parse_object(path: Path, label: str, limit: int) -> dict[str, Any]:
    try:
        data = path.read_bytes()
    except OSError as error:
        raise HarnessError(f"cannot read {label}") from error
    if len(data) > limit:
        raise HarnessError(f"{label} exceeds {limit} bytes")
    value = contract.parse_json(data, label)
    if not isinstance(value, dict):
        raise HarnessError(f"{label} must be an object")
    return value


def utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def run_command(
    arguments: list[str],
    *,
    cwd: Path,
    timeout: float,
    environment: dict[str, str] | None = None,
    label: str,
) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(
            arguments,
            cwd=cwd,
            env=environment,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise HarnessError(f"{label} did not complete within its deadline") from error


def docker_compose(
    compose: Path,
    project: str,
    arguments: list[str],
    *,
    cwd: Path,
    timeout: float,
    environment: dict[str, str],
    label: str,
) -> subprocess.CompletedProcess[bytes]:
    return run_command(
        ["docker", "compose", "-p", project, "-f", str(compose), *arguments],
        cwd=cwd,
        timeout=timeout,
        environment=environment,
        label=label,
    )


def check_compose_images(
    compose: Path,
    project: str,
    expected: dict[str, str],
    *,
    cwd: Path,
    environment: dict[str, str],
) -> None:
    result = docker_compose(
        compose,
        project,
        ["config", "--format", "json"],
        cwd=cwd,
        timeout=60,
        environment=environment,
        label="Compose config",
    )
    if result.returncode != 0 or len(result.stdout) > 262_144:
        raise HarnessError("Compose model could not be rendered")
    try:
        model = contract.parse_json(result.stdout, "Compose model")
    except contract.ManifestError as error:
        raise HarnessError(str(error)) from error
    services = model.get("services") if isinstance(model, dict) else None
    if not isinstance(services, dict):
        raise HarnessError("Compose model has no services")
    required = {
        "postgres": POSTGRES_IMAGE,
        "migrate": expected["remote-management"],
        "management": expected["remote-management"],
        "identity": expected["remote-server"],
        "relay": expected["remote-server"],
    }
    if set(services) != set(required):
        raise HarnessError("Compose model has an unexpected service set")
    for service, image in required.items():
        actual = services.get(service, {}).get("image")
        if actual != image:
            raise HarnessError(
                f"Compose service {service} is not pinned to its manifest image"
            )
        if services[service].get("network_mode") == "host" or services[service].get(
            "privileged", False
        ):
            raise HarnessError(
                f"Compose service {service} crosses the host security boundary"
            )


def verify_driver(path: Path, trusted_root: Path) -> Path:
    try:
        resolved = path.resolve(strict=True)
        root = trusted_root.resolve(strict=True)
    except OSError as error:
        raise HarnessError("scenario driver is not available") from error
    if resolved == root or root not in resolved.parents:
        raise HarnessError("scenario driver is outside the trusted harness root")
    if (
        resolved.is_symlink()
        or not resolved.is_file()
        or not os.access(resolved, os.X_OK)
    ):
        raise HarnessError("scenario driver must be an executable regular file")
    return resolved


def collect_scenario(
    driver: Path,
    scenario: str,
    attempt_id: str,
    *,
    workdir: Path,
    timeout: float,
    environment: dict[str, str],
) -> tuple[int, str, Path]:
    result_path = workdir / f"{attempt_id}-result.json"
    process = run_command(
        [
            str(driver),
            "--scenario",
            scenario,
            "--attempt-id",
            attempt_id,
            "--output",
            str(result_path),
        ],
        cwd=workdir,
        timeout=timeout,
        environment=environment,
        label=f"scenario {scenario}",
    )
    if process.returncode != 0:
        raise HarnessError(f"scenario {scenario} driver failed")
    result = parse_object(result_path, f"scenario {scenario} result", 16_384)
    if set(result) != DRIVER_KEYS:
        raise HarnessError(f"scenario {scenario} result has unexpected fields")
    if not isinstance(result["status"], str) or not DRIVER_STATUS.fullmatch(
        result["status"]
    ):
        raise HarnessError(f"scenario {scenario} result status is invalid")
    if result["status"] != "passed":
        raise HarnessError(f"scenario {scenario} did not pass")
    if result["attempt_id"] != attempt_id:
        raise HarnessError(f"scenario {scenario} attempt identity mismatch")
    evidence_path = Path(result["evidence_file"])
    if not evidence_path.is_absolute():
        evidence_path = (workdir / evidence_path).resolve()
    try:
        evidence_path.relative_to(workdir.resolve())
    except ValueError as error:
        raise HarnessError(
            f"scenario {scenario} evidence escapes the run directory"
        ) from error
    if evidence_path.is_symlink() or not evidence_path.is_file():
        raise HarnessError(f"scenario {scenario} evidence is not a regular file")
    size = evidence_path.stat().st_size
    if size < 1 or size > 4_194_304:
        raise HarnessError(f"scenario {scenario} evidence is outside the size bound")
    evidence = contract.parse_json(
        evidence_path.read_bytes(), f"scenario {scenario} evidence"
    )
    contract.scan_for_secrets(evidence, f"scenario {scenario} evidence")
    safe_path = workdir / f"{attempt_id}-evidence.json"
    safe_path.write_bytes(
        contract.canonical_bytes(evidence)
        if isinstance(evidence, dict)
        else json.dumps(evidence, sort_keys=True).encode()
    )
    digest = hashlib.sha256(safe_path.read_bytes()).hexdigest()
    return size, digest, safe_path


def load_template(path: Path) -> dict[str, Any]:
    value = parse_object(path, "candidate manifest template", 262_144)
    if set(value) != TEMPLATE_KEYS:
        raise HarnessError("candidate manifest template has unexpected fields")
    if (
        value.get("schema_version") != 1
        or value.get("organization") != "camellia-computing"
    ):
        raise HarnessError("candidate manifest template schema is invalid")
    return value


def build_skeleton(
    template: dict[str, Any],
    *,
    run_id: str,
    mode: str,
    harness_commit: str,
    compose_project: str,
    network: str,
    volume_prefix: str,
    credential_namespace: str,
    port_range: str,
) -> dict[str, Any]:
    required = (
        contract.SCENARIOS
        if mode == "exhaustive"
        else (
            "auth-device-verification",
            "direct-session",
            "forced-relay-session",
            "first-frame-input",
            "reconnect-shutdown",
        )
    )
    return {
        **template,
        "run": {
            "id": run_id,
            "mode": mode,
            "started_at": utc_now(),
            "finished_at": utc_now(),
            "workflow_ref": (
                "camellia-computing/.github/.github/workflows/"
                "remote-system-e2e.yml@refs/heads/main"
            ),
            "runner": "camellia-remote-system-harness",
            "harness_commit": harness_commit,
        },
        "scenarios": [
            {
                "name": name,
                "status": "passed",
                "attempt_id": f"{run_id}-{index:02d}",
                "duration_ms": 1,
                "evidence_sha256": "0" * 64,
            }
            for index, name in enumerate(required, start=1)
        ],
        "isolation": {
            "compose_project": compose_project,
            "network": network,
            "volume_prefix": volume_prefix,
            "credential_namespace": credential_namespace,
            "port_range": port_range,
        },
        "evidence": {
            "files": [
                {"name": "placeholder.json", "sha256": "0" * 64, "size_bytes": 1}
            ],
            "retention_days": 7,
        },
    }


def main(arguments: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-template", type=Path, required=True)
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--repository-map", required=True)
    parser.add_argument("--compose-file", type=Path, required=True)
    parser.add_argument("--scenario-driver", type=Path, required=True)
    parser.add_argument("--trusted-driver-root", type=Path, required=True)
    parser.add_argument("--output-manifest", type=Path, required=True)
    parser.add_argument("--workdir", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--harness-commit", required=True)
    parser.add_argument("--mode", choices=("smoke", "exhaustive"), default="smoke")
    parser.add_argument("--port-range", default="31000-31031")
    args = parser.parse_args(arguments)
    compose_project = f"camellia-remote-e2e-{args.run_id}"
    network = f"{compose_project}-net"
    volume_prefix = f"{compose_project}-vol"
    credential_namespace = f"{compose_project}-cred"
    environment = {
        "PATH": os.environ.get("PATH", ""),
        "COMPOSE_PROJECT_NAME": compose_project,
        "CAMELLIA_REMOTE_E2E_RUN_ID": args.run_id,
    }
    started = time.monotonic()
    compose_started = False
    try:
        args.workdir.mkdir(parents=True, exist_ok=True)
        contract_value = contract.load_contract(args.contract)
        names = contract.repository_map(args.repository_map)
        template = load_template(args.candidate_template)
        driver = verify_driver(args.scenario_driver, args.trusted_driver_root)
        skeleton = build_skeleton(
            template,
            run_id=args.run_id,
            mode=args.mode,
            harness_commit=args.harness_commit,
            compose_project=compose_project,
            network=network,
            volume_prefix=volume_prefix,
            credential_namespace=credential_namespace,
            port_range=args.port_range,
        )
        contract.scan_for_secrets(skeleton)
        # This validates all four candidates and all dependency pins before any
        # service is started. Placeholder evidence is replaced after scenarios.
        contract.validate_manifest(skeleton, contract_value, names)
        expected_images = {
            logical_id: skeleton["candidates"][
                contract.LOGICAL_REPOSITORIES.index(logical_id)
            ]["image"]["repository"]
            + "@"
            + skeleton["candidates"][contract.LOGICAL_REPOSITORIES.index(logical_id)][
                "image"
            ]["digest"]
            for logical_id in contract.SERVICE_REPOSITORIES
        }
        check_compose_images(
            args.compose_file,
            compose_project,
            expected_images,
            cwd=args.workdir,
            environment=environment,
        )
        up = docker_compose(
            args.compose_file,
            compose_project,
            ["up", "-d", "--wait"],
            cwd=args.workdir,
            timeout=300,
            environment=environment,
            label="Compose startup",
        )
        if up.returncode != 0:
            raise HarnessError("Remote system Compose startup failed")
        compose_started = True
        scenario_results: list[dict[str, Any]] = []
        evidence_files: list[dict[str, Any]] = []
        for index, scenario in enumerate(skeleton["scenarios"], start=1):
            remaining = contract_value["modes"][args.mode]["max_duration_seconds"] - (
                time.monotonic() - started
            )
            if remaining <= 1:
                raise HarnessError("Remote system run exceeded its total deadline")
            attempt_id = f"{args.run_id}-{index:02d}"
            started_scenario = time.monotonic()
            size, digest, evidence_path = collect_scenario(
                driver,
                scenario["name"],
                attempt_id,
                workdir=args.workdir,
                timeout=min(300, remaining),
                environment=environment,
            )
            scenario_results.append(
                {
                    "name": scenario["name"],
                    "status": "passed",
                    "attempt_id": attempt_id,
                    "duration_ms": max(
                        1, int((time.monotonic() - started_scenario) * 1000)
                    ),
                    "evidence_sha256": digest,
                }
            )
            evidence_files.append(
                {
                    "name": evidence_path.name,
                    "sha256": digest,
                    "size_bytes": size,
                }
            )
        skeleton["run"]["finished_at"] = utc_now()
        skeleton["scenarios"] = scenario_results
        skeleton["evidence"]["files"] = evidence_files
        contract.scan_for_secrets(skeleton)
        final = contract.validate_manifest(skeleton, contract_value, names)
        args.output_manifest.parent.mkdir(parents=True, exist_ok=True)
        args.output_manifest.write_bytes(contract.canonical_bytes(final))
        print(f"Remote system harness passed {args.mode} mode for run {args.run_id}")
        return 0
    except (
        OSError,
        KeyError,
        TypeError,
        ValueError,
        HarnessError,
        contract.ManifestError,
    ) as error:
        print(f"Remote system harness failed: {error}", file=sys.stderr)
        return 2
    finally:
        # Cleanup is deterministic and bounded. The caller's workflow also
        # invokes the same command in an always() job as a second barrier.
        if compose_started:
            result = docker_compose(
                args.compose_file,
                compose_project,
                ["down", "--volumes", "--remove-orphans", "--timeout", "30"],
                cwd=args.workdir,
                timeout=90,
                environment=environment,
                label="Compose cleanup",
            )
            if result.returncode != 0:
                raise HarnessError("Remote system Compose cleanup failed")
        try:
            shutil.rmtree(args.workdir)
        except OSError as error:
            raise HarnessError(
                "Remote system harness workspace cleanup failed"
            ) from error


if __name__ == "__main__":
    raise SystemExit(main())
