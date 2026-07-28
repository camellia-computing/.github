#!/usr/bin/env python3
"""Regression tests for the organization repository policy auditor."""

from __future__ import annotations

import copy
import unittest
from pathlib import Path
from typing import Any

import audit_repository_policies as audit


class FakeAPI:
    def __init__(self, responses: dict[str, Any]) -> None:
        self.responses = responses

    def get(self, endpoint: str) -> Any:
        if endpoint not in self.responses:
            raise RuntimeError(f"missing fixture: {endpoint}")
        return copy.deepcopy(self.responses[endpoint])


def fixture_for(policy: dict[str, Any]) -> dict[str, Any]:
    organization = "camellia-computing"
    repository = policy["name"]
    root = f"repos/{organization}/{repository}"
    responses: dict[str, Any] = {
        root: {
            "allow_auto_merge": False,
            "allow_merge_commit": False,
            "allow_rebase_merge": False,
            "allow_squash_merge": True,
            "archived": False,
            "default_branch": "main",
            "delete_branch_on_merge": True,
            "squash_merge_commit_message": "BLANK",
            "squash_merge_commit_title": "PR_TITLE",
            "visibility": policy["visibility"],
            "security_and_analysis": {
                "dependabot_security_updates": {"status": "enabled"},
                "secret_scanning": {"status": "enabled"},
                "secret_scanning_push_protection": {"status": "enabled"},
            },
        },
        f"{root}/immutable-releases": {"enabled": True},
        f"{root}/actions/permissions": {
            "enabled": True,
            "allowed_actions": "all",
            "sha_pinning_required": True,
        },
        f"{root}/actions/permissions/workflow": {
            "default_workflow_permissions": "read",
            "can_approve_pull_request_reviews": False,
        },
        f"{root}/rulesets?includes_parents=true&per_page=100": [
            {
                "id": 1,
                "name": "Protect default branch",
                "target": "branch",
            },
            {
                "id": 2,
                "name": "Protect release tags",
                "target": "tag",
            },
        ],
        f"{root}/rulesets/1": {
            "name": "Protect default branch",
            "target": "branch",
            "enforcement": "active",
            "bypass_actors": [],
            "conditions": {
                "ref_name": {
                    "exclude": [],
                    "include": ["~DEFAULT_BRANCH"],
                }
            },
            "rules": [
                {"type": "deletion"},
                {"type": "non_fast_forward"},
                {"type": "required_linear_history"},
                {
                    "type": "pull_request",
                    "parameters": {
                        "allowed_merge_methods": ["squash"],
                        "dismiss_stale_reviews_on_push": True,
                        "require_code_owner_review": True,
                        "require_last_push_approval": True,
                        "required_approving_review_count": 1,
                        "required_review_thread_resolution": True,
                    },
                },
                {
                    "type": "required_status_checks",
                    "parameters": {
                        "do_not_enforce_on_create": True,
                        "required_status_checks": [
                            {"context": context}
                            for context in policy["required_status_checks"]
                        ],
                        "strict_required_status_checks_policy": True,
                    },
                },
                {
                    "type": "code_scanning",
                    "parameters": {
                        "code_scanning_tools": [
                            {
                                "alerts_threshold": "errors",
                                "security_alerts_threshold": "high_or_higher",
                                "tool": "CodeQL",
                            }
                        ]
                    },
                },
            ],
        },
        f"{root}/rulesets/2": {
            "name": "Protect release tags",
            "target": "tag",
            "enforcement": "active",
            "bypass_actors": [],
            "conditions": {
                "ref_name": {
                    "exclude": [],
                    "include": ["refs/tags/v*"],
                }
            },
            "rules": [
                {"type": "deletion"},
                {"type": "non_fast_forward"},
            ],
        },
        f"{root}/environments/release": {
            "deployment_branch_policy": {
                "custom_branch_policies": True,
                "protected_branches": False,
            },
            "protection_rules": [
                {
                    "type": "required_reviewers",
                    "prevent_self_review": True,
                    "reviewers": [
                        {
                            "type": "Team",
                            "reviewer": {
                                "slug": policy["release_review_team"],
                            },
                        }
                    ],
                },
                {"type": "branch_policy"},
            ],
        },
        f"{root}/environments/release/deployment-branch-policies": {
            "total_count": len(policy["release_deployment_policies"]),
            "branch_policies": [
                {
                    "name": item["name"],
                    "type": item["type"],
                }
                for item in policy["release_deployment_policies"]
            ],
        },
    }
    for path in policy["required_paths"]:
        responses[f"{root}/contents/{path}?ref=main"] = {
            "type": "file",
            "path": path,
        }
    return responses


class RepositoryPolicyAuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.config = audit.load_config(Path("config/repository-policies.json"))
        cls.policy = cls.config["repositories"][0]

    def run_fixture(self, responses: dict[str, Any]) -> dict[str, Any]:
        config = {
            "policy_revision": self.config["policy_revision"],
            "organization": self.config["organization"],
            "repositories": [self.policy],
        }
        return audit.audit_repositories(FakeAPI(responses), config)

    def test_reviewed_config_is_valid(self) -> None:
        self.assertEqual(
            {item["name"] for item in self.config["repositories"]},
            audit.TARGET_REPOSITORIES,
        )

    def test_compliant_fixture_has_no_drift(self) -> None:
        report = self.run_fixture(fixture_for(self.policy))
        self.assertEqual(report["status"], "compliant")
        self.assertEqual(report["drift_count"], 0)
        self.assertIn("match the reviewed baseline", audit.render_markdown(report))

    def test_security_and_review_drift_is_reported(self) -> None:
        responses = fixture_for(self.policy)
        root = f"repos/camellia-computing/{self.policy['name']}"
        responses[f"{root}/immutable-releases"]["enabled"] = False
        branch_rules = responses[f"{root}/rulesets/1"]["rules"]
        pull_request = next(
            rule for rule in branch_rules if rule["type"] == "pull_request"
        )
        pull_request["parameters"]["require_last_push_approval"] = False
        report = self.run_fixture(responses)
        controls = {item["control"] for item in report["drifts"]}
        self.assertEqual(report["status"], "drift")
        self.assertIn("release.immutable", controls)
        self.assertIn(
            "ruleset.default_branch.pull_request.require_last_push_approval",
            controls,
        )
        self.assertIn("| Repository | Control |", audit.render_markdown(report))

    def test_missing_api_fixture_is_isolated_to_repository(self) -> None:
        responses = fixture_for(self.policy)
        root = f"repos/camellia-computing/{self.policy['name']}"
        del responses[f"{root}/actions/permissions"]
        report = self.run_fixture(responses)
        self.assertEqual(report["drift_count"], 1)
        self.assertEqual(report["drifts"][0]["control"], "audit.api")


if __name__ == "__main__":
    unittest.main()
