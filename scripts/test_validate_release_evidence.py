"""Regression tests for immutable release evidence validation."""

from __future__ import annotations

import copy
import importlib.util
import unittest
from pathlib import Path
from types import ModuleType


def load_validator() -> ModuleType:
    path = Path("scripts/validate-release-evidence.py")
    spec = importlib.util.spec_from_file_location("release_evidence_validator", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load release evidence validator")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def policy() -> dict:
    return {
        "repository_policy_revision": "2026-07-31.1",
        "signing_registry_revision": "2026-07-31.1",
        "exceptions": [],
    }


def file_fixture() -> dict:
    digest = "a" * 64
    return {
        "schema_version": 1,
        "repository": "example-client",
        "version": "1.0.0-rc.1",
        "source": {
            "commit": "b" * 40,
            "ref": "refs/heads/main",
            "validation_run_id": 42,
        },
        "release_kind": "candidate",
        "generated_at": "2026-07-29T12:00:00Z",
        "policy": policy(),
        "dependencies": [],
        "files": [
            {
                "name": "example-client-1.0.0-rc.1-windows-x86-64.zip",
                "sha256": digest,
                "size_bytes": 1024,
                "platform": "windows",
                "architecture": "x86-64",
                "sbom": {"name": "artifact.spdx.json", "sha256": digest},
                "provenance": {
                    "name": "artifact.intoto.jsonl",
                    "sha256": digest,
                },
                "signing": {
                    "category": "private-trust",
                    "verification": "verified",
                    "verifier": "authenticode",
                    "timestamp": "verified",
                    "distribution": "restricted",
                    "evidence": ["authenticode-verification.json"],
                },
            }
        ],
        "images": [],
    }


def image_fixture() -> dict:
    digest = f"sha256:{'c' * 64}"
    evidence_digest = "d" * 64
    commit = "e" * 40
    return {
        "schema_version": 1,
        "repository": "example-service",
        "version": "1.0.0",
        "source": {
            "commit": commit,
            "ref": "refs/tags/v1.0.0",
            "validation_run_id": 43,
        },
        "release_kind": "formal",
        "generated_at": "2026-07-29T12:00:00Z",
        "policy": policy(),
        "dependencies": [
            {
                "repository": "example-client",
                "commit": "b" * 40,
                "version": "1.0.0",
                "relation": "compatible-with",
                "evidence": "client-version-policy.json",
            }
        ],
        "files": [],
        "images": [
            {
                "name": "example-service",
                "digest": digest,
                "platforms": [
                    {
                        "platform": "linux",
                        "architecture": "amd64",
                        "digest": f"sha256:{'f' * 64}",
                    },
                    {
                        "platform": "linux",
                        "architecture": "arm64",
                        "digest": f"sha256:{'1' * 64}",
                    },
                ],
                "sbom": {
                    "name": "example-service.spdx.json",
                    "sha256": evidence_digest,
                },
                "provenance": {
                    "name": "example-service.intoto.jsonl",
                    "sha256": evidence_digest,
                },
                "registries": [
                    {
                        "name": "dockerhub",
                        "status": "skipped",
                        "reason": "not-configured",
                    },
                    {
                        "name": "ghcr",
                        "status": "published",
                        "repository": "ghcr.io/example/example-service",
                        "digest": digest,
                        "aliases": ["1.0.0", f"sha-{commit}"],
                        "signature": {
                            "mechanism": "keyless-cosign",
                            "verification": "verified",
                            "identity": (
                                "https://github.com/example/example-service/"
                                ".github/workflows/publish-release.yml@refs/tags/v1.0.0"
                            ),
                            "issuer": "https://token.actions.githubusercontent.com",
                            "evidence": ["ghcr-cosign-verification.json"],
                        },
                        "readback": "verified",
                    },
                ],
            }
        ],
    }


class ReleaseEvidenceValidatorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.validator = load_validator()

    def test_signed_file_fixture_is_valid(self) -> None:
        self.validator.validate_release_evidence(file_fixture())

    def test_unsigned_desktop_fixture_is_valid_when_explicit(self) -> None:
        value = file_fixture()
        value["files"][0]["signing"] = {
            "category": "unsigned",
            "verification": "not-present",
            "verifier": "none",
            "timestamp": "not-applicable",
            "distribution": "restricted",
            "evidence": [],
        }
        self.validator.validate_release_evidence(value)

    def test_unsigned_mobile_output_requires_resigning_classification(self) -> None:
        value = file_fixture()
        artifact = value["files"][0]
        artifact["platform"] = "android"
        artifact["signing"] = {
            "category": "unsigned",
            "verification": "not-present",
            "verifier": "none",
            "timestamp": "not-applicable",
            "distribution": "installable",
            "evidence": [],
        }
        with self.assertRaisesRegex(ValueError, "re-signing input"):
            self.validator.validate_release_evidence(value)

    def test_web_file_uses_not_applicable_native_signing(self) -> None:
        value = file_fixture()
        artifact = value["files"][0]
        artifact["platform"] = "web"
        artifact["architecture"] = "all"
        artifact["signing"] = {
            "category": "not-applicable",
            "verification": "not-applicable",
            "verifier": "none",
            "timestamp": "not-applicable",
            "distribution": "not-applicable",
            "evidence": [],
        }
        self.validator.validate_release_evidence(value)

    def test_failed_signature_cannot_be_downgraded_to_unsigned(self) -> None:
        value = file_fixture()
        value["files"][0]["signing"]["verification"] = "not-present"
        with self.assertRaisesRegex(ValueError, "signed evidence must be verified"):
            self.validator.validate_release_evidence(value)

    def test_ad_hoc_artifact_cannot_claim_installable_distribution(self) -> None:
        value = file_fixture()
        signing = value["files"][0]["signing"]
        signing["category"] = "ad-hoc"
        signing["distribution"] = "installable"
        with self.assertRaisesRegex(ValueError, "cannot claim installable"):
            self.validator.validate_release_evidence(value)

    def test_file_order_is_stable(self) -> None:
        value = file_fixture()
        duplicate = copy.deepcopy(value["files"][0])
        duplicate["name"] = "another.zip"
        value["files"].append(duplicate)
        with self.assertRaisesRegex(ValueError, "sorted and unique"):
            self.validator.validate_release_evidence(value)

    def test_formal_image_fixture_is_valid_with_conditional_registry(self) -> None:
        self.validator.validate_release_evidence(image_fixture())

    def test_formal_image_requires_at_least_one_configured_registry(self) -> None:
        value = image_fixture()
        value["images"][0]["registries"][1] = {
            "name": "ghcr",
            "status": "skipped",
            "reason": "not-configured",
        }
        with self.assertRaisesRegex(ValueError, "no configured registry"):
            self.validator.validate_release_evidence(value)

    def test_candidate_cannot_publish_a_registry_image(self) -> None:
        value = image_fixture()
        value["release_kind"] = "candidate"
        value["source"]["ref"] = "refs/heads/main"
        value["images"][0]["registries"][0]["reason"] = "candidate-only"
        with self.assertRaisesRegex(ValueError, "candidates cannot publish"):
            self.validator.validate_release_evidence(value)

    def test_formal_tag_must_match_version(self) -> None:
        value = image_fixture()
        value["source"]["ref"] = "refs/tags/v1.0.1"
        with self.assertRaisesRegex(ValueError, "exact stable version tag"):
            self.validator.validate_release_evidence(value)

    def test_expired_exception_is_rejected(self) -> None:
        value = file_fixture()
        value["policy"]["exceptions"] = [
            {
                "id": "temporary-platform-exception",
                "owner": "release-team",
                "expires_on": "2026-07-28",
                "reason": "Temporary platform limitation.",
                "compensating_control": "Independent readback verification.",
                "evidence": ["exception-review"],
            }
        ]
        with self.assertRaisesRegex(ValueError, "was expired"):
            self.validator.validate_release_evidence(value)


if __name__ == "__main__":
    unittest.main()
