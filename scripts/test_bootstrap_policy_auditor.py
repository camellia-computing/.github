"""Regression tests for the Policy Auditor GitHub App manifest."""

from __future__ import annotations

import copy
import unittest
from pathlib import Path

import bootstrap_policy_auditor as bootstrap
from audit_repository_policies import (
    EXPECTED_POLICY_AUDITOR_PERMISSIONS,
    load_config,
)


class PolicyAuditorBootstrapTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.config = load_config(Path("config/repository-policies.json"))

    def test_manifest_is_policy_derived_read_only_and_webhook_free(self) -> None:
        manifest = bootstrap.policy_auditor_manifest(
            self.config,
            "http://127.0.0.1:12345/callback",
        )
        governance = next(
            policy
            for policy in self.config["repositories"]
            if policy["logical_id"] == "governance"
        )
        self.assertEqual(
            manifest["url"],
            f"https://github.com/{self.config['organization']}/{governance['name']}",
        )
        self.assertEqual(
            manifest["default_permissions"],
            EXPECTED_POLICY_AUDITOR_PERMISSIONS,
        )
        self.assertFalse(manifest["hook_attributes"]["active"])
        self.assertEqual(manifest["default_events"], [])
        self.assertFalse(manifest["public"])
        self.assertNotIn("write", manifest["default_permissions"].values())

    def test_installation_verifier_rejects_scope_or_permission_drift(self) -> None:
        slug = "portable-policy-auditor"
        installation = {
            "app_slug": slug,
            "events": [],
            "permissions": copy.deepcopy(EXPECTED_POLICY_AUDITOR_PERMISSIONS),
            "repository_selection": "all",
            "suspended_at": None,
            "target_id": self.config["organization_id"],
            "target_type": "Organization",
        }
        bootstrap.verify_installation(self.config, slug, installation)

        installation["permissions"]["issues"] = "write"
        with self.assertRaisesRegex(RuntimeError, "differs"):
            bootstrap.verify_installation(self.config, slug, installation)


if __name__ == "__main__":
    unittest.main()
