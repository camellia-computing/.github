"""Contract tests for the organization-owned Remote system manifest."""

from __future__ import annotations

import copy
import importlib.util
import json
import unittest
from pathlib import Path

SCRIPT = Path(__file__).with_name("validate_remote_system_manifest.py")
SPEC = importlib.util.spec_from_file_location("remote_manifest", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("unable to load manifest validator")
validator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validator)


NAMES = {
    "remote-client": "remote-client",
    "remote-management": "remote-management-server",
    "remote-protocol": "remote-protocol",
    "remote-server": "remote-server",
}
COMMITS = {
    "remote-client": "b" * 40,
    "remote-management": "c" * 40,
    "remote-protocol": "a" * 40,
    "remote-server": "d" * 40,
}
HARNESS_COMMIT = "e" * 40


def artifact(name: str, kind: str, source_commit: str) -> dict:
    return {
        "name": name,
        "kind": kind,
        "sha256": ("f" if kind == "web" else "1") * 64,
        "size_bytes": 128,
        "source_commit": source_commit,
    }


def candidate(logical_id: str) -> dict:
    source_commit = COMMITS[logical_id]
    if logical_id == "remote-client":
        artifacts = [
            artifact("remote-client-controller", "controller", source_commit),
            artifact("remote-client-web", "web", source_commit),
        ]
        image = None
        protocol_commit = COMMITS["remote-protocol"]
        web_commit = None
    elif logical_id == "remote-management":
        artifacts = [artifact("remote-management-image", "image", source_commit)]
        image = {
            "repository": "ghcr.io/camellia-computing/remote-management-server",
            "digest": "sha256:" + "2" * 64,
            "platforms": ["linux/amd64", "linux/arm64"],
            "source_commit": source_commit,
        }
        protocol_commit = None
        web_commit = COMMITS["remote-client"]
    elif logical_id == "remote-server":
        artifacts = [artifact("remote-server-image", "image", source_commit)]
        image = {
            "repository": "ghcr.io/camellia-computing/remote-server",
            "digest": "sha256:" + "3" * 64,
            "platforms": ["linux/amd64", "linux/arm64"],
            "source_commit": source_commit,
        }
        protocol_commit = COMMITS["remote-protocol"]
        web_commit = None
    else:
        artifacts = [artifact("remote-protocol-source", "source", source_commit)]
        image = None
        protocol_commit = None
        web_commit = None
    return {
        "logical_id": logical_id,
        "repository": NAMES[logical_id],
        "commit": source_commit,
        "ref": "refs/heads/main",
        "version": None,
        "image": image,
        "artifacts": artifacts,
        "protocol_commit": protocol_commit,
        "web_client_commit": web_commit,
    }


def manifest(mode: str = "smoke") -> dict:
    required = (
        [
            "auth-device-verification",
            "direct-session",
            "forced-relay-session",
            "first-frame-input",
            "reconnect-shutdown",
        ]
        if mode == "smoke"
        else list(validator.SCENARIOS)
    )
    return {
        "schema_version": 1,
        "contract_revision": "2026-08-18.1",
        "organization": "camellia-computing",
        "run": {
            "id": "abc12345",
            "mode": mode,
            "started_at": "2026-08-18T01:00:00Z",
            "finished_at": "2026-08-18T01:01:00Z",
            "workflow_ref": (
                "camellia-computing/.github/.github/workflows/"
                "remote-system-e2e.yml@refs/heads/main"
            ),
            "runner": "camellia-remote-system-harness",
            "harness_commit": HARNESS_COMMIT,
        },
        "candidates": [candidate(item) for item in validator.LOGICAL_REPOSITORIES],
        "compatibility": {
            "protocol_commit": COMMITS["remote-protocol"],
            "client_protocol_commit": COMMITS["remote-protocol"],
            "server_protocol_commit": COMMITS["remote-protocol"],
            "client_web_commit": COMMITS["remote-client"],
        },
        "scenarios": [
            {
                "name": name,
                "status": "passed",
                "attempt_id": f"attempt-{index:02d}",
                "duration_ms": 100,
                "evidence_sha256": "4" * 64,
            }
            for index, name in enumerate(required, start=1)
        ],
        "isolation": {
            "compose_project": "camellia-remote-e2e-abc12345",
            "network": "camellia-remote-e2e-abc12345-net",
            "volume_prefix": "camellia-remote-e2e-abc12345-vol",
            "credential_namespace": "camellia-remote-e2e-abc12345-cred",
            "port_range": "31000-31031",
        },
        "evidence": {
            "files": [
                {"name": "scenario-summary.json", "sha256": "5" * 64, "size_bytes": 256}
            ],
            "retention_days": 7,
        },
    }


class RemoteManifestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = validator.load_contract(
            SCRIPT.parents[1] / "config/remote-system-contract.json"
        )
        cls.names = validator.repository_map(json.dumps(NAMES))

    def test_accepts_complete_smoke_manifest(self) -> None:
        value = manifest()
        validated = validator.validate_manifest(value, self.contract, self.names)
        self.assertEqual(validated["run"]["mode"], "smoke")
        self.assertEqual(
            len(validator.canonical_bytes(validated)),
            len(validator.canonical_bytes(value)),
        )

    def test_accepts_exhaustive_scenario_set(self) -> None:
        validator.validate_manifest(manifest("exhaustive"), self.contract, self.names)

    def test_rejects_protocol_pin_mismatch(self) -> None:
        value = manifest()
        value["candidates"][0]["protocol_commit"] = "9" * 40
        with self.assertRaisesRegex(validator.ManifestError, "Protocol commit"):
            validator.validate_manifest(value, self.contract, self.names)

    def test_rejects_image_source_mismatch(self) -> None:
        value = manifest()
        value["candidates"][1]["image"]["source_commit"] = "9" * 40
        with self.assertRaisesRegex(validator.ManifestError, "source_commit"):
            validator.validate_manifest(value, self.contract, self.names)

    def test_rejects_non_passed_scenario(self) -> None:
        value = manifest()
        value["scenarios"][0]["status"] = "skipped"
        with self.assertRaisesRegex(validator.ManifestError, "did not pass"):
            validator.validate_manifest(value, self.contract, self.names)

    def test_rejects_unknown_manifest_field(self) -> None:
        value = manifest()
        value["unexpected"] = True
        with self.assertRaisesRegex(validator.ManifestError, "unexpected fields"):
            validator.validate_manifest(value, self.contract, self.names)

    def test_rejects_duplicate_json_key(self) -> None:
        raw = json.dumps(manifest()).replace(
            '"schema_version": 1,', '"schema_version": 1, "schema_version": 1,', 1
        )
        with self.assertRaisesRegex(validator.ManifestError, "duplicate JSON key"):
            validator.parse_json(raw.encode(), "manifest")

    def test_rejects_secret_field_and_canary(self) -> None:
        value = manifest()
        value["evidence"]["private_key"] = "do-not-collect"
        with self.assertRaisesRegex(validator.ManifestError, "not an allowed"):
            validator.scan_for_secrets(value)
        value = manifest()
        value["evidence"]["files"][0]["name"] = "token=leaked"
        with self.assertRaisesRegex(validator.ManifestError, "canary"):
            validator.scan_for_secrets(value)

    def test_rejects_repository_map_collision(self) -> None:
        with self.assertRaisesRegex(validator.ManifestError, "duplicate"):
            validator.repository_map(
                json.dumps({item: "same" for item in validator.LOGICAL_REPOSITORIES})
            )

    def test_rejects_cross_run_isolation(self) -> None:
        value = manifest()
        value["isolation"]["network"] = "camellia-remote-e2e-other-net"
        with self.assertRaisesRegex(validator.ManifestError, "unique run-scoped"):
            validator.validate_manifest(value, self.contract, self.names)

    def test_rejects_candidate_workflow_identity(self) -> None:
        value = manifest()
        value["run"]["workflow_ref"] = (
            "candidate/.github/workflows/e2e.yml@refs/heads/main"
        )
        with self.assertRaisesRegex(validator.ManifestError, "protected"):
            validator.validate_manifest(value, self.contract, self.names)

    def test_canonical_output_is_stable(self) -> None:
        first = validator.canonical_bytes(manifest())
        shuffled = json.loads(json.dumps(manifest()))
        shuffled["evidence"] = copy.deepcopy(shuffled["evidence"])
        self.assertEqual(first, validator.canonical_bytes(shuffled))
        self.assertEqual(len(validator.hashlib.sha256(first).hexdigest()), 64)


if __name__ == "__main__":
    unittest.main()
