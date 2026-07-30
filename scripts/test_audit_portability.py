"""Regression tests for the static repository portability audit."""

from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path

import audit_portability
from audit_repository_policies import load_config


class PortabilityAuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.root = Path(__file__).resolve().parents[1]
        cls.config = load_config(cls.root / "config/repository-policies.json")
        cls.fixture = audit_portability.load_object(
            cls.root / "scripts/fixtures/repository-rename.json",
            "rename fixture",
        )

    def test_reviewed_tree_has_no_uncontrolled_coordinates(self) -> None:
        self.assertEqual(
            audit_portability.audit_portability(
                self.root,
                self.root / "config/repository-policies.json",
                self.root / "scripts/fixtures/repository-rename.json",
            ),
            [],
        )

    def test_rename_fixture_preserves_immutable_identities(self) -> None:
        self.assertEqual(
            audit_portability.validate_rename_fixture(self.config, self.fixture),
            [],
        )

    def test_case_insensitive_repository_collision_fails_closed(self) -> None:
        fixture = copy.deepcopy(self.fixture)
        fixture["repository_names"]["remote-server"] = "remote.client"
        errors = audit_portability.validate_rename_fixture(self.config, fixture)
        self.assertEqual(len(errors), 1)
        self.assertIn("unique ignoring case", errors[0])

    def test_machine_specific_path_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "portable.txt").write_text(
                "Do not use /" + "home/private-user/workspace here.\n",
                encoding="utf-8",
            )
            content = (root / "portable.txt").read_text(encoding="utf-8")
            self.assertTrue(
                any(
                    pattern.search(content)
                    for pattern in audit_portability.MACHINE_PATH_PATTERNS
                )
            )


if __name__ == "__main__":
    unittest.main()
