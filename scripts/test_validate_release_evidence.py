#!/usr/bin/env python3
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


def fixture() -> dict:
    digest = "a" * 64
    return {
        "schema_version": 1,
        "repository": "example-client",
        "version": "1.0.0-rc.1",
        "source": {
            "commit": "b" * 40,
            "ref": "refs/tags/v1.0.0-rc.1",
        },
        "release_kind": "candidate",
        "generated_at": "2026-07-29T12:00:00Z",
        "artifacts": [
            {
                "name": "example-client-1.0.0-rc.1-windows-x86-64.zip",
                "sha256": digest,
                "size_bytes": 1024,
                "platform": "windows",
                "architecture": "x86-64",
                "sbom": {"name": "artifact.spdx.json", "sha256": digest},
                "provenance": {"name": "artifact.intoto.jsonl", "sha256": digest},
                "signing": {
                    "category": "private-trust",
                    "verification": "verified",
                    "verifier": "authenticode",
                    "timestamp": "verified",
                    "distribution": "private",
                    "evidence": ["authenticode-verification.json"],
                },
            }
        ],
    }


class ReleaseEvidenceValidatorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.validator = load_validator()

    def test_signed_fixture_is_valid(self) -> None:
        self.validator.validate_release_evidence(fixture())

    def test_unsigned_fixture_is_valid_when_explicit(self) -> None:
        value = fixture()
        value["artifacts"][0]["signing"] = {
            "category": "unsigned",
            "verification": "not-present",
            "verifier": "none",
            "timestamp": "not-applicable",
            "distribution": "source-only",
            "evidence": [],
        }
        self.validator.validate_release_evidence(value)

    def test_failed_signature_cannot_be_downgraded_to_unsigned(self) -> None:
        value = fixture()
        value["artifacts"][0]["signing"]["verification"] = "not-present"
        with self.assertRaisesRegex(ValueError, "signed evidence must be verified"):
            self.validator.validate_release_evidence(value)

    def test_ad_hoc_artifact_cannot_claim_public_distribution(self) -> None:
        value = fixture()
        signing = value["artifacts"][0]["signing"]
        signing["category"] = "ad-hoc"
        signing["distribution"] = "public"
        with self.assertRaisesRegex(ValueError, "cannot claim public"):
            self.validator.validate_release_evidence(value)

    def test_artifact_order_is_stable(self) -> None:
        value = fixture()
        duplicate = copy.deepcopy(value["artifacts"][0])
        duplicate["name"] = "another.zip"
        value["artifacts"].append(duplicate)
        with self.assertRaisesRegex(ValueError, "sorted and unique"):
            self.validator.validate_release_evidence(value)


if __name__ == "__main__":
    unittest.main()
