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


def fixture_for(
    policy: dict[str, Any],
    controls: dict[str, Any],
    organization: str,
) -> dict[str, Any]:
    repository = policy["name"]
    root = f"repos/{organization}/{repository}"
    release_capable = policy["release"] is not None
    rulesets: list[dict[str, Any]] = [
        {
            "id": 1,
            "name": "Protect default branch",
            "target": "branch",
        }
    ]
    if release_capable:
        rulesets.append(
            {
                "id": 2,
                "name": "Protect release tags",
                "target": "tag",
            }
        )
    responses: dict[str, Any] = {
        f"orgs/{organization}": {
            field: controls[field]
            for field in (
                "default_repository_permission",
                "members_can_change_repo_visibility",
                "members_can_create_private_pages",
                "members_can_create_public_pages",
                "members_can_create_repositories",
                "members_can_delete_repositories",
                "two_factor_requirement_enabled",
            )
        },
        f"orgs/{organization}/members?role=admin&per_page=100": [
            {"login": "owner-one"},
            {"login": "owner-two"},
        ],
        f"orgs/{organization}/outside_collaborators?per_page=100": [],
        f"orgs/{organization}/invitations?per_page=100": [],
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
        f"{root}/immutable-releases": {"enabled": release_capable},
        f"{root}/actions/permissions": {
            "enabled": True,
            "allowed_actions": "all",
            "sha_pinning_required": True,
        },
        f"{root}/actions/permissions/workflow": {
            "default_workflow_permissions": "read",
            "can_approve_pull_request_reviews": False,
        },
        f"{root}/teams?per_page=100": [
            {
                "permission": team["permission"],
                "slug": team["slug"],
            }
            for team in policy["access_teams"]
        ],
        f"{root}/rulesets?includes_parents=true&per_page=100": rulesets,
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
    }
    for path in policy["required_paths"]:
        responses[f"{root}/contents/{path}?ref=main"] = {
            "type": "file",
            "path": path,
        }
    if release_capable:
        responses.update(
            {
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
                                        "slug": policy["release"]["review_team"],
                                    },
                                }
                            ],
                        },
                        {"type": "branch_policy"},
                    ],
                },
                f"{root}/environments/release/deployment-branch-policies": {
                    "total_count": len(policy["release"]["deployment_policies"]),
                    "branch_policies": [
                        {
                            "name": item["name"],
                            "type": item["type"],
                        }
                        for item in policy["release"]["deployment_policies"]
                    ],
                },
            }
        )
    return responses


class RepositoryPolicyAuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.config = audit.load_config(Path("config/repository-policies.json"))
        cls.release_policy = next(
            item for item in cls.config["repositories"] if item["name"] == "nexus"
        )
        cls.library_policy = next(
            item
            for item in cls.config["repositories"]
            if item["profile"] == "library"
        )

    def run_fixture(
        self,
        policy: dict[str, Any],
        responses: dict[str, Any],
    ) -> dict[str, Any]:
        config = {
            "policy_revision": self.config["policy_revision"],
            "organization": self.config["organization"],
            "organization_controls": self.config["organization_controls"],
            "repositories": [policy],
        }
        return audit.audit_repositories(FakeAPI(responses), config)

    def fixture(self, policy: dict[str, Any]) -> dict[str, Any]:
        return fixture_for(
            policy,
            self.config["organization_controls"],
            self.config["organization"],
        )

    def test_reviewed_config_covers_every_profile_and_has_portable_ids(self) -> None:
        self.assertEqual(len(self.config["repositories"]), 7)
        self.assertEqual(
            {item["profile"] for item in self.config["repositories"]},
            audit.PROFILES,
        )
        self.assertEqual(
            len({item["logical_id"] for item in self.config["repositories"]}),
            7,
        )
        renamed = copy.deepcopy(self.config)
        renamed["organization"] = "example-owner"
        audit.validate_config(renamed)

    def test_compliant_release_fixture_has_no_drift(self) -> None:
        report = self.run_fixture(
            self.release_policy,
            self.fixture(self.release_policy),
        )
        self.assertEqual(report["status"], "compliant")
        self.assertEqual(report["drift_count"], 0)
        self.assertIn("all repositories match", audit.render_markdown(report))

    def test_compliant_library_does_not_require_release_controls(self) -> None:
        report = self.run_fixture(
            self.library_policy,
            self.fixture(self.library_policy),
        )
        self.assertEqual(report["status"], "compliant")
        self.assertEqual(report["drift_count"], 0)

    def test_security_and_review_drift_is_reported(self) -> None:
        responses = self.fixture(self.release_policy)
        root = (
            f"repos/{self.config['organization']}/{self.release_policy['name']}"
        )
        responses[f"{root}/immutable-releases"]["enabled"] = False
        branch_rules = responses[f"{root}/rulesets/1"]["rules"]
        pull_request = next(
            rule for rule in branch_rules if rule["type"] == "pull_request"
        )
        pull_request["parameters"]["require_last_push_approval"] = False
        report = self.run_fixture(self.release_policy, responses)
        controls = {item["control"] for item in report["drifts"]}
        self.assertEqual(report["status"], "drift")
        self.assertIn("release.immutable", controls)
        self.assertIn(
            "ruleset.default_branch.pull_request.require_last_push_approval",
            controls,
        )

    def test_organization_and_team_drift_is_reported(self) -> None:
        responses = self.fixture(self.release_policy)
        organization = self.config["organization"]
        root = f"repos/{organization}/{self.release_policy['name']}"
        responses[f"orgs/{organization}"]["two_factor_requirement_enabled"] = False
        responses[f"{root}/teams?per_page=100"][0]["permission"] = "push"
        report = self.run_fixture(self.release_policy, responses)
        controls = {item["control"] for item in report["drifts"]}
        self.assertIn("organization.two_factor_requirement_enabled", controls)
        self.assertIn("repository.access_teams", controls)

    def test_missing_api_fixture_is_isolated_to_repository(self) -> None:
        responses = self.fixture(self.release_policy)
        root = (
            f"repos/{self.config['organization']}/{self.release_policy['name']}"
        )
        del responses[f"{root}/actions/permissions"]
        report = self.run_fixture(self.release_policy, responses)
        self.assertEqual(report["drift_count"], 1)
        self.assertEqual(report["drifts"][0]["control"], "audit.api")


if __name__ == "__main__":
    unittest.main()
