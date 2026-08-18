#!/usr/bin/env python3
"""Build the base-owned candidate metadata package for a Remote system run."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

try:
    import validate_remote_system_manifest as contract
except (
    ModuleNotFoundError
):  # unittest imports this file as scripts.build_remote_candidate_template.
    from scripts import validate_remote_system_manifest as contract


IMAGE = re.compile(
    r"^(?P<repository>[a-z0-9./_-]{3,250})@(?P<digest>sha256:[0-9a-f]{64})$"
)


def git_output(directory: Path, *arguments: str) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(directory), *arguments],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise ValueError(f"git query failed for {directory}") from error
    return result.stdout.decode("ascii").strip()


def exact_head(directory: Path, expected: str, logical_id: str) -> None:
    actual = git_output(directory, "rev-parse", "--verify", "HEAD")
    if actual != expected:
        raise ValueError(f"{logical_id} checkout is not the requested exact SHA")


def submodule_commit(directory: Path) -> str:
    line = git_output(directory, "ls-tree", "HEAD", "libs/camellia_remote_protocol")
    fields = line.split()
    if len(fields) != 4 or fields[0] != "160000" or fields[1] != "commit":
        raise ValueError("consumer Protocol submodule is not an exact gitlink")
    return contract.commit(fields[2], "consumer Protocol pin")


def sha256_file(path: Path, label: str) -> tuple[str, int]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} must be a regular file")
    size = path.stat().st_size
    if size < 1 or size > 4_194_304:
        raise ValueError(f"{label} must be between 1 and 4 MiB")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest(), size


def image(value: str, logical_id: str, source_commit: str) -> dict[str, Any]:
    match = IMAGE.fullmatch(value)
    if match is None:
        raise ValueError(f"{logical_id} image must be a repository@sha256 digest")
    return {
        "repository": match.group("repository"),
        "digest": match.group("digest"),
        "platforms": ["linux/amd64", "linux/arm64"],
        "source_commit": source_commit,
    }


def artifact(name: str, kind: str, path: Path, source_commit: str) -> dict[str, Any]:
    digest, size = sha256_file(path, name)
    return {
        "name": name,
        "kind": kind,
        "sha256": digest,
        "size_bytes": size,
        "source_commit": source_commit,
    }


def candidate(
    logical_id: str,
    repository: str,
    source_commit: str,
    *,
    artifacts: list[dict[str, Any]],
    image_value: dict[str, Any] | None = None,
    protocol_commit: str | None = None,
    web_client_commit: str | None = None,
) -> dict[str, Any]:
    return {
        "logical_id": logical_id,
        "repository": repository,
        "commit": source_commit,
        "ref": f"refs/commits/{source_commit}",
        "version": None,
        "image": image_value,
        "artifacts": sorted(artifacts, key=lambda item: item["name"]),
        "protocol_commit": protocol_commit,
        "web_client_commit": web_client_commit,
    }


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--repository-map", required=True)
    result.add_argument("--protocol-dir", type=Path, required=True)
    result.add_argument("--server-dir", type=Path, required=True)
    result.add_argument("--client-dir", type=Path, required=True)
    result.add_argument("--management-dir", type=Path, required=True)
    result.add_argument("--protocol-commit", required=True)
    result.add_argument("--server-commit", required=True)
    result.add_argument("--client-commit", required=True)
    result.add_argument("--management-commit", required=True)
    result.add_argument("--server-image", required=True)
    result.add_argument("--management-image", required=True)
    result.add_argument("--client-web-artifact", type=Path, required=True)
    result.add_argument("--client-controller-artifact", type=Path, required=True)
    result.add_argument("--server-image-evidence", type=Path, required=True)
    result.add_argument("--management-image-evidence", type=Path, required=True)
    result.add_argument("--protocol-evidence", type=Path, required=True)
    result.add_argument("--output", type=Path, required=True)
    return result


def main(arguments: list[str] | None = None) -> int:
    args = parser().parse_args(arguments)
    try:
        names = contract.repository_map(args.repository_map)
        commits = {
            "remote-protocol": contract.commit(args.protocol_commit, "protocol commit"),
            "remote-server": contract.commit(args.server_commit, "server commit"),
            "remote-client": contract.commit(args.client_commit, "client commit"),
            "remote-management": contract.commit(
                args.management_commit, "management commit"
            ),
        }
        directories = {
            "remote-protocol": args.protocol_dir,
            "remote-server": args.server_dir,
            "remote-client": args.client_dir,
            "remote-management": args.management_dir,
        }
        for logical_id, directory in directories.items():
            exact_head(directory, commits[logical_id], logical_id)
        client_protocol = submodule_commit(args.client_dir)
        server_protocol = submodule_commit(args.server_dir)
        if (
            client_protocol != commits["remote-protocol"]
            or server_protocol != commits["remote-protocol"]
        ):
            raise ValueError(
                "Client and Server Protocol gitlinks do not match the selected Protocol SHA"
            )
        lock_path = args.management_dir / "web-client.lock"
        locked_web = lock_path.read_text(encoding="ascii").strip()
        if locked_web != commits["remote-client"]:
            raise ValueError(
                "Management web-client.lock does not match the selected Client SHA"
            )
        template = {
            "schema_version": 1,
            "contract_revision": "2026-08-18.1",
            "organization": "camellia-computing",
            "candidates": [
                candidate(
                    "remote-client",
                    names["remote-client"],
                    commits["remote-client"],
                    artifacts=[
                        artifact(
                            "remote-client-controller",
                            "controller",
                            args.client_controller_artifact,
                            commits["remote-client"],
                        ),
                        artifact(
                            "remote-client-web",
                            "web",
                            args.client_web_artifact,
                            commits["remote-client"],
                        ),
                    ],
                    protocol_commit=commits["remote-protocol"],
                ),
                candidate(
                    "remote-management",
                    names["remote-management"],
                    commits["remote-management"],
                    artifacts=[
                        artifact(
                            "remote-management-image",
                            "image",
                            args.management_image_evidence,
                            commits["remote-management"],
                        )
                    ],
                    image_value=image(
                        args.management_image,
                        "remote-management",
                        commits["remote-management"],
                    ),
                    web_client_commit=commits["remote-client"],
                ),
                candidate(
                    "remote-protocol",
                    names["remote-protocol"],
                    commits["remote-protocol"],
                    artifacts=[
                        artifact(
                            "remote-protocol-source",
                            "source",
                            args.protocol_evidence,
                            commits["remote-protocol"],
                        )
                    ],
                ),
                candidate(
                    "remote-server",
                    names["remote-server"],
                    commits["remote-server"],
                    artifacts=[
                        artifact(
                            "remote-server-image",
                            "image",
                            args.server_image_evidence,
                            commits["remote-server"],
                        )
                    ],
                    image_value=image(
                        args.server_image,
                        "remote-server",
                        commits["remote-server"],
                    ),
                    protocol_commit=commits["remote-protocol"],
                ),
            ],
            "compatibility": {
                "protocol_commit": commits["remote-protocol"],
                "client_protocol_commit": client_protocol,
                "server_protocol_commit": server_protocol,
                "client_web_commit": commits["remote-client"],
            },
        }
        contract.parse_json(
            json.dumps(template, ensure_ascii=True, sort_keys=True).encode(),
            "candidate template",
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(
            (
                json.dumps(
                    template, ensure_ascii=True, sort_keys=True, separators=(",", ":")
                )
                + "\n"
            ).encode()
        )
        print(f"wrote exact Remote candidate template: {args.output}")
        return 0
    except (OSError, ValueError, contract.ManifestError) as error:
        print(f"candidate template rejected: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
