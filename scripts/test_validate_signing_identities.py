#!/usr/bin/env python3
"""Regression tests for the non-secret signing policy validator."""

from __future__ import annotations

import copy
import importlib.util
import json
import unittest
from pathlib import Path
from types import ModuleType


def load_validator() -> ModuleType:
    path = Path("scripts/validate-signing-identities.py")
    spec = importlib.util.spec_from_file_location("signing_policy_validator", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load signing policy validator")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class SigningPolicyValidatorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.validator = load_validator()
        cls.registry = json.loads(
            Path("config/signing-identities.json").read_text(encoding="utf-8")
        )

    def test_reviewed_policy_is_valid_and_contains_no_identity_value(self) -> None:
        self.validator.validate_registry(self.registry)
        serialized = json.dumps(self.registry)
        self.assertNotIn("public_identity", serialized)
        self.assertNotIn("not_after", serialized)

    def test_priority_reordering_is_rejected(self) -> None:
        registry = copy.deepcopy(self.registry)
        registry["trust_priority"][0:2] = reversed(registry["trust_priority"][0:2])
        with self.assertRaisesRegex(ValueError, "strongest-first"):
            self.validator.validate_registry(registry)

    def test_partial_unsigned_policy_is_rejected(self) -> None:
        registry = copy.deepcopy(self.registry)
        registry["identities"][0]["allowed_outcomes"].remove("unsigned")
        with self.assertRaisesRegex(ValueError, "allows unsigned"):
            self.validator.validate_registry(registry)

    def test_private_material_field_is_rejected(self) -> None:
        registry = copy.deepcopy(self.registry)
        registry["identities"][0]["private_key"] = "not-a-key"
        with self.assertRaisesRegex(ValueError, "private material field"):
            self.validator.validate_registry(registry)

    def test_duplicate_credential_name_is_rejected(self) -> None:
        registry = copy.deepcopy(self.registry)
        identity = next(
            item for item in registry["identities"] if item["platform"] == "windows"
        )
        duplicate = identity["credential_groups"][0]["secret_names"][0]
        identity["credential_groups"][1]["secret_names"][0] = duplicate
        identity["credential_groups"][1]["secret_names"].sort()
        with self.assertRaisesRegex(ValueError, "reuses credential names"):
            self.validator.validate_registry(registry)

    def test_consumer_is_a_portable_logical_id_not_a_fixed_allowlist(self) -> None:
        registry = copy.deepcopy(self.registry)
        registry["identities"][0]["consumers"] = ["future-client"]
        self.validator.validate_registry(registry)

        registry["identities"][0]["consumers"] = ["Invalid Consumer"]
        with self.assertRaisesRegex(ValueError, "invalid or unsorted consumers"):
            self.validator.validate_registry(registry)


if __name__ == "__main__":
    unittest.main()
