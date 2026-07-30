"""Tests for logical-to-physical repository scope resolution."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from resolve_repository_scope import repository_names


class ResolveRepositoryScopeTests(unittest.TestCase):
    def test_reviewed_scope_is_sorted_and_complete(self) -> None:
        names = repository_names(Path("config/repository-policies.json"))
        self.assertEqual(len(names), 7)
        self.assertEqual(names, sorted(set(names)))

    def test_invalid_duplicate_scope_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "policy.json"
            config.write_text(
                json.dumps(
                    {
                        "repositories": [
                            {"logical_id": "first", "name": "same"},
                            {"logical_id": "second", "name": "SAME"},
                        ]
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "unique names"):
                repository_names(config)

    def test_physical_names_need_not_follow_logical_order(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "policy.json"
            config.write_text(
                json.dumps(
                    {
                        "repositories": [
                            {"logical_id": "client", "name": "z.Client"},
                            {"logical_id": "server", "name": "a_server"},
                        ]
                    }
                ),
                encoding="utf-8",
            )
            self.assertEqual(repository_names(config), ["a_server", "z.Client"])


if __name__ == "__main__":
    unittest.main()
