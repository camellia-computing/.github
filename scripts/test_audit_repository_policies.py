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
    security_configuration: dict[str, Any],
    organization: str,
    organization_id: int,
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
            "id": organization_id,
            "login": organization,
            **{
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
        },
        f"orgs/{organization}/members?role=admin&per_page=100": [
            {"login": "owner-one"},
            {"login": "owner-two"},
        ],
        f"orgs/{organization}/outside_collaborators?per_page=100": [],
        f"orgs/{organization}/invitations?per_page=100": [],
        f"orgs/{organization}/repos?type=all&per_page=100": [
            {
                "id": policy["repository_id"],
                "name": repository,
            }
        ],
        f"orgs/{organization}/actions/permissions": {
            "allowed_actions": controls["actions_allowed_actions"],
            "enabled_repositories": controls["actions_enabled_repositories"],
            "sha_pinning_required": controls["actions_sha_pinning_required"],
        },
        f"orgs/{organization}/actions/permissions/workflow": {
            "can_approve_pull_request_reviews": controls[
                "actions_can_approve_pull_request_reviews"
            ],
            "default_workflow_permissions": controls[
                "actions_default_workflow_permissions"
            ],
        },
        f"orgs/{organization}/actions/permissions/artifact-and-log-retention": {
            "days": controls["actions_artifact_and_log_retention_days"],
            "maximum_allowed_days": 400,
        },
        f"orgs/{organization}/settings/immutable-releases": {
            "enforced_repositories": "selected" if release_capable else "none",
        },
        (
            f"orgs/{organization}/code-security/configurations/"
            f"{security_configuration['configuration_id']}"
        ): {
            "id": security_configuration["configuration_id"],
            "target_type": "organization",
            "name": security_configuration["name"],
            "description": security_configuration["description"],
            "enforcement": security_configuration["enforcement"],
            **copy.deepcopy(security_configuration["settings"]),
        },
        f"orgs/{organization}/code-security/configurations/defaults": [
            {
                "default_for_new_repos": security_configuration[
                    "default_for_new_repos"
                ],
                "configuration": {
                    "id": security_configuration["configuration_id"],
                },
            }
        ],
        root: {
            "id": policy["repository_id"],
            "name": repository,
            "full_name": f"{organization}/{repository}",
            "owner": {
                "id": organization_id,
                "login": organization,
            },
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
        f"{root}/code-scanning/default-setup": {
            "languages": ["actions"],
            "query_suite": "default",
            "schedule": "weekly",
            "state": "configured",
            "threat_model": "remote_and_local",
        },
        f"{root}/code-security-configuration": {
            "status": (
                "enforced"
                if security_configuration["enforcement"] == "enforced"
                else "attached"
            ),
            "configuration": {
                "id": security_configuration["configuration_id"],
            },
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
    if release_capable:
        responses[
            f"orgs/{organization}/settings/immutable-releases/repositories?per_page=100"
        ] = {
            "total_count": 1,
            "repositories": [
                {
                    "id": policy["repository_id"],
                    "name": repository,
                }
            ],
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
                f"{root}/environments/release/deployment-branch-policies"
                "?per_page=100": {
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
            item for item in cls.config["repositories"] if item["profile"] == "library"
        )

    def run_fixture(
        self,
        policy: dict[str, Any],
        responses: dict[str, Any],
    ) -> dict[str, Any]:
        config = {
            "policy_revision": self.config["policy_revision"],
            "organization": self.config["organization"],
            "organization_id": self.config["organization_id"],
            "automation_scopes": [],
            "code_security_configuration": self.config["code_security_configuration"],
            "organization_controls": self.config["organization_controls"],
            "repositories": [policy],
        }
        return audit.audit_repositories(FakeAPI(responses), config)

    def fixture(self, policy: dict[str, Any]) -> dict[str, Any]:
        return fixture_for(
            policy,
            self.config["organization_controls"],
            self.config["code_security_configuration"],
            self.config["organization"],
            self.config["organization_id"],
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
        renamed_names = {
            "nexus-client": "Nexus.Client",
            "nexus-management": "nexus_management",
            "remote-client": "Remote.Client",
            "remote-management": "remote_management",
            "remote-protocol": "Remote.Protocol",
            "remote-server": "remote_server",
        }
        original_identities = {
            item["logical_id"]: (item["repository_id"], item["artifact_ids"])
            for item in renamed["repositories"]
        }
        for policy in renamed["repositories"]:
            policy["name"] = renamed_names.get(policy["logical_id"], policy["name"])
        audit.validate_config(renamed)
        self.assertEqual(
            {
                item["logical_id"]: (item["repository_id"], item["artifact_ids"])
                for item in renamed["repositories"]
            },
            original_identities,
        )

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
        root = f"repos/{self.config['organization']}/{self.release_policy['name']}"
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

    def test_shared_actions_release_and_security_drift_is_reported(self) -> None:
        responses = self.fixture(self.release_policy)
        organization = self.config["organization"]
        root = f"repos/{organization}/{self.release_policy['name']}"
        responses[f"orgs/{organization}/actions/permissions"][
            "sha_pinning_required"
        ] = False
        responses[
            f"orgs/{organization}/settings/immutable-releases/repositories?per_page=100"
        ]["repositories"][0]["id"] += 1
        configuration_id = self.config["code_security_configuration"][
            "configuration_id"
        ]
        responses[
            f"orgs/{organization}/code-security/configurations/{configuration_id}"
        ]["dependabot_security_updates"] = "disabled"
        responses[f"{root}/code-security-configuration"]["configuration"]["id"] += 1

        report = self.run_fixture(self.release_policy, responses)
        controls = {item["control"] for item in report["drifts"]}
        self.assertIn("actions.sha_pinning_required", controls)
        self.assertIn("release.immutable.repository_ids", controls)
        self.assertIn(
            "security.configuration.settings.dependabot_security_updates",
            controls,
        )
        self.assertIn("security.configuration.id", controls)

    def test_immutable_identity_drift_is_reported(self) -> None:
        responses = self.fixture(self.release_policy)
        organization = self.config["organization"]
        root = f"repos/{organization}/{self.release_policy['name']}"
        responses[f"orgs/{organization}"]["id"] += 1
        responses[root]["id"] += 1
        report = self.run_fixture(self.release_policy, responses)
        controls = {item["control"] for item in report["drifts"]}
        self.assertIn("organization.id", controls)
        self.assertIn("repository.id", controls)

    def test_release_automation_scope_uses_immutable_repository_ids(self) -> None:
        repositories = {
            item["logical_id"]: item for item in self.config["repositories"]
        }
        responses: dict[str, Any] = {
            f"orgs/{self.config['organization']}/actions/secrets?per_page=100": {
                "total_count": sum(
                    len(scope["organization_secrets"])
                    for scope in self.config["automation_scopes"]
                ),
                "secrets": [
                    {"name": name, "visibility": "selected"}
                    for scope in self.config["automation_scopes"]
                    for name in scope["organization_secrets"]
                ],
            },
            f"orgs/{self.config['organization']}/actions/variables?per_page=30": {
                "total_count": sum(
                    len(scope["organization_variables"])
                    for scope in self.config["automation_scopes"]
                ),
                "variables": [
                    {"name": name, "visibility": "selected", "value": "discarded"}
                    for scope in self.config["automation_scopes"]
                    for name in scope["organization_variables"]
                ],
            },
        }
        for scope in self.config["automation_scopes"]:
            selected = [
                {
                    "id": repositories[logical_id]["repository_id"],
                    "name": repositories[logical_id]["name"],
                }
                for logical_id in scope["repository_logical_ids"]
            ]
            for kind, names in (
                ("secret", scope["organization_secrets"]),
                ("variable", scope["organization_variables"]),
            ):
                for name in names:
                    responses[
                        f"orgs/{self.config['organization']}/actions/{kind}s/"
                        f"{name}/repositories?per_page=100"
                    ] = {
                        "total_count": len(selected),
                        "repositories": selected,
                    }
        auditor = audit.Auditor()
        audit.audit_automation_scopes(
            FakeAPI(responses),
            auditor,
            self.config["organization"],
            self.config,
        )
        self.assertEqual(auditor.drifts, [])

        variable_endpoint = (
            f"orgs/{self.config['organization']}/actions/variables/"
            "RELEASE_APP_CLIENT_ID/repositories?per_page=100"
        )
        responses[variable_endpoint]["repositories"].append(
            {
                "id": self.config["repositories"][0]["repository_id"],
                "name": self.config["repositories"][0]["name"],
            }
        )
        responses[variable_endpoint]["total_count"] += 1
        auditor = audit.Auditor()
        audit.audit_automation_scopes(
            FakeAPI(responses),
            auditor,
            self.config["organization"],
            self.config,
        )
        controls = {item.control for item in auditor.drifts}
        self.assertIn(
            "automation.release-manager.variable.RELEASE_APP_CLIENT_ID.repositories",
            controls,
        )

    def test_policy_auditor_installation_uses_complete_repository_ids(self) -> None:
        app_slug = "policy-auditor"
        installation_id = 42
        repositories = [
            {"id": item["repository_id"], "name": item["name"]}
            for item in self.config["repositories"]
        ]
        metadata_api = FakeAPI(
            {
                f"orgs/{self.config['organization']}/installations?per_page=100": {
                    "total_count": 1,
                    "installations": [
                        {
                            "app_slug": app_slug,
                            "events": [],
                            "id": installation_id,
                            "permissions": copy.deepcopy(
                                audit.EXPECTED_POLICY_AUDITOR_PERMISSIONS
                            ),
                            "repository_selection": "all",
                            "suspended_at": None,
                            "target_id": self.config["organization_id"],
                            "target_type": "Organization",
                        }
                    ],
                }
            }
        )
        scope_api = FakeAPI(
            {
                "installation/repositories?per_page=100": {
                    "total_count": len(repositories),
                    "repositories": copy.deepcopy(repositories),
                }
            }
        )
        auditor = audit.Auditor()
        audit.audit_policy_auditor_installation(
            metadata_api,
            scope_api,
            auditor,
            self.config["organization"],
            self.config,
            app_slug,
            installation_id,
        )
        self.assertEqual(auditor.drifts, [])

        scope_api.responses["installation/repositories?per_page=100"][
            "repositories"
        ].pop()
        scope_api.responses["installation/repositories?per_page=100"][
            "total_count"
        ] -= 1
        auditor = audit.Auditor()
        audit.audit_policy_auditor_installation(
            metadata_api,
            scope_api,
            auditor,
            self.config["organization"],
            self.config,
            app_slug,
            installation_id,
        )
        self.assertEqual(len(auditor.drifts), 1)
        self.assertEqual(
            auditor.drifts[0].control,
            "automation.policy-auditor.installation.repository_ids",
        )

        installation = metadata_api.responses[
            f"orgs/{self.config['organization']}/installations?per_page=100"
        ]["installations"][0]
        installation["permissions"]["issues"] = "write"
        auditor = audit.Auditor()
        audit.audit_policy_auditor_installation(
            metadata_api,
            FakeAPI(
                {
                    "installation/repositories?per_page=100": {
                        "total_count": len(repositories),
                        "repositories": copy.deepcopy(repositories),
                    }
                }
            ),
            auditor,
            self.config["organization"],
            self.config,
            app_slug,
            installation_id,
        )
        self.assertEqual(len(auditor.drifts), 1)
        self.assertEqual(
            auditor.drifts[0].control,
            "automation.policy-auditor.installation.permissions",
        )

    def test_pagination_consumes_every_page_and_rejects_truncation(self) -> None:
        first = [{"id": item} for item in range(100)]
        api = FakeAPI(
            {
                "items?per_page=100": first,
                "items?per_page=100&page=2": [{"id": 100}],
                "objects?per_page=100": {
                    "total_count": 101,
                    "repositories": first,
                },
                "objects?per_page=100&page=2": {
                    "total_count": 101,
                    "repositories": [{"id": 100}],
                },
            }
        )
        self.assertEqual(
            len(audit.get_all_list_pages(api, "items?per_page=100")),
            101,
        )
        self.assertEqual(
            len(
                audit.get_all_collection_pages(
                    api,
                    "objects?per_page=100",
                    "repositories",
                )["repositories"]
            ),
            101,
        )

        truncated = FakeAPI(
            {
                "objects?per_page=100": {
                    "total_count": 2,
                    "repositories": [{"id": 1}],
                },
                "objects?per_page=100&page=2": {
                    "total_count": 2,
                    "repositories": [],
                },
            }
        )
        with self.assertRaisesRegex(RuntimeError, "incomplete page"):
            audit.get_all_collection_pages(
                truncated,
                "objects?per_page=100",
                "repositories",
            )

    def test_missing_api_fixture_is_isolated_to_repository(self) -> None:
        responses = self.fixture(self.release_policy)
        root = f"repos/{self.config['organization']}/{self.release_policy['name']}"
        del responses[f"{root}/actions/permissions"]
        report = self.run_fixture(self.release_policy, responses)
        self.assertEqual(report["drift_count"], 1)
        self.assertEqual(report["drifts"][0]["control"], "audit.api")


if __name__ == "__main__":
    unittest.main()
