#!/usr/bin/env python3
"""Audit organization and repository settings against the reviewed policy."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import asdict, dataclass
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

CONFIG_KEYS = {
    "$schema",
    "schema_version",
    "policy_revision",
    "organization",
    "organization_id",
    "last_reviewed_on",
    "automation_scopes",
    "code_security_configuration",
    "organization_controls",
    "repositories",
}
AUTOMATION_SCOPE_KEYS = {
    "logical_id",
    "organization_secrets",
    "organization_variables",
    "repository_logical_ids",
}
ORGANIZATION_CONTROL_KEYS = {
    "actions_allowed_actions",
    "actions_artifact_and_log_retention_days",
    "actions_can_approve_pull_request_reviews",
    "actions_default_workflow_permissions",
    "actions_enabled_repositories",
    "actions_sha_pinning_required",
    "default_repository_permission",
    "members_can_change_repo_visibility",
    "members_can_create_private_pages",
    "members_can_create_public_pages",
    "members_can_create_repositories",
    "members_can_delete_repositories",
    "minimum_owner_count",
    "outside_collaborator_count",
    "pending_invitation_count",
    "two_factor_requirement_enabled",
}
CODE_SECURITY_CONFIGURATION_KEYS = {
    "configuration_id",
    "default_for_new_repos",
    "description",
    "enforcement",
    "logical_id",
    "name",
    "settings",
}
CODE_SECURITY_SETTING_KEYS = {
    "advanced_security",
    "code_scanning_default_setup",
    "code_scanning_default_setup_options",
    "code_scanning_delegated_alert_dismissal",
    "code_scanning_options",
    "dependabot_alerts",
    "dependabot_delegated_alert_dismissal",
    "dependabot_security_updates",
    "dependency_graph",
    "dependency_graph_autosubmit_action",
    "dependency_graph_autosubmit_action_options",
    "private_vulnerability_reporting",
    "secret_scanning",
    "secret_scanning_delegated_alert_dismissal",
    "secret_scanning_delegated_bypass",
    "secret_scanning_extended_metadata",
    "secret_scanning_generic_secrets",
    "secret_scanning_non_provider_patterns",
    "secret_scanning_push_protection",
    "secret_scanning_validity_checks",
}
REPOSITORY_POLICY_KEYS = {
    "artifact_ids",
    "logical_id",
    "name",
    "repository_id",
    "product",
    "profile",
    "visibility",
    "access_teams",
    "required_status_checks",
    "required_paths",
    "release",
}
ACCESS_TEAM_KEYS = {"permission", "slug"}
RELEASE_POLICY_KEYS = {"review_team", "deployment_policies"}
DEPLOYMENT_POLICY_KEYS = {"name", "type"}
PROFILES = {"governance", "library", "release-client", "release-service"}
PRODUCTS = {"organization", "nexus", "remote"}
RELEASE_PROFILES = {"release-client", "release-service"}
TEAM_PERMISSIONS = {"pull", "triage", "push", "maintain", "admin"}
EXPECTED_BRANCH_RULE_TYPES = {
    "code_scanning",
    "deletion",
    "non_fast_forward",
    "pull_request",
    "required_linear_history",
    "required_status_checks",
}
EXPECTED_TAG_RULE_TYPES = {"deletion", "non_fast_forward"}
API_VERSION = "2026-03-10"
EXPECTED_POLICY_AUDITOR_PERMISSIONS = {
    "administration": "read",
    "contents": "read",
    "members": "read",
    "metadata": "read",
    "organization_actions_variables": "read",
    "organization_administration": "read",
    "organization_secrets": "read",
}


class API(Protocol):
    def get(self, endpoint: str) -> Any: ...


class GitHubAPI:
    def __init__(self, token: str, base_url: str = "https://api.github.com") -> None:
        if not token:
            raise ValueError("GH_TOKEN is required")
        self._token = token
        self._base_url = base_url.rstrip("/")

    def get(self, endpoint: str) -> Any:
        request = Request(
            f"{self._base_url}/{endpoint.lstrip('/')}",
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self._token}",
                "User-Agent": "organization-repository-policy-audit",
                "X-GitHub-Api-Version": API_VERSION,
            },
            method="GET",
        )
        try:
            with urlopen(request, timeout=30) as response:
                content = response.read()
        except HTTPError as error:
            detail = error.read().decode("utf-8", errors="replace")
            raise RuntimeError(
                f"GitHub API {error.code} for {endpoint}: {detail}"
            ) from error
        except URLError as error:
            raise RuntimeError(
                f"GitHub API unavailable for {endpoint}: {error}"
            ) from error
        if not content:
            return None
        return json.loads(content)


def page_endpoint(endpoint: str, page: int) -> str:
    separator = "&" if "?" in endpoint else "?"
    return f"{endpoint}{separator}page={page}"


def get_all_list_pages(
    api: API,
    endpoint: str,
    *,
    page_size: int = 100,
) -> list[Any]:
    """Return every page from a GitHub endpoint whose response is an array."""
    items: list[Any] = []
    page = 1
    while True:
        response = api.get(endpoint if page == 1 else page_endpoint(endpoint, page))
        if not isinstance(response, list):
            raise TypeError(f"GitHub API returned a non-array page for {endpoint}")
        items.extend(response)
        if len(response) < page_size:
            return items
        page += 1


def get_all_collection_pages(
    api: API,
    endpoint: str,
    collection: str,
) -> dict[str, Any]:
    """Return a complete GitHub `{total_count, <collection>}` response."""
    first = api.get(endpoint)
    if not isinstance(first, dict):
        raise TypeError(f"GitHub API returned a non-object page for {endpoint}")
    total_count = first.get("total_count")
    first_items = first.get(collection)
    if (
        not isinstance(total_count, int)
        or isinstance(total_count, bool)
        or total_count < 0
        or not isinstance(first_items, list)
    ):
        raise RuntimeError(
            f"GitHub API returned invalid pagination data for {endpoint}"
        )

    items = list(first_items)
    page = 2
    while len(items) < total_count:
        response = api.get(page_endpoint(endpoint, page))
        if (
            not isinstance(response, dict)
            or response.get("total_count") != total_count
            or not isinstance(response.get(collection), list)
            or not response[collection]
        ):
            raise RuntimeError(f"GitHub API returned an incomplete page for {endpoint}")
        items.extend(response[collection])
        page += 1
    if len(items) != total_count:
        raise RuntimeError(
            f"GitHub API item count differs from total_count for {endpoint}"
        )
    return {**first, collection: items}


@dataclass(frozen=True)
class Drift:
    repository: str
    control: str
    expected: Any
    actual: Any


class Auditor:
    def __init__(self) -> None:
        self.drifts: list[Drift] = []

    def equal(
        self,
        repository: str,
        control: str,
        actual: Any,
        expected: Any,
    ) -> None:
        if actual != expected:
            self.drifts.append(Drift(repository, control, expected, actual))

    def true(
        self,
        repository: str,
        control: str,
        condition: bool,
        expected: Any,
        actual: Any,
    ) -> None:
        if not condition:
            self.drifts.append(Drift(repository, control, expected, actual))


def require_string(mapping: dict[str, Any], name: str) -> str:
    value = mapping.get(name)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be a non-empty string")
    return value


def require_sorted_unique_strings(
    value: Any,
    name: str,
    *,
    allow_empty: bool = False,
) -> list[str]:
    if (
        not isinstance(value, list)
        or (not value and not allow_empty)
        or any(not isinstance(item, str) or not item for item in value)
        or value != sorted(set(value))
    ):
        qualifier = "" if allow_empty else "non-empty, "
        raise ValueError(f"{name} must be a sorted, {qualifier}unique string array")
    return value


def require_positive_integer(mapping: dict[str, Any], name: str) -> int:
    value = mapping.get(name)
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise ValueError(f"{name} must be a positive integer")
    return value


def validate_config(config: dict[str, Any]) -> None:
    if set(config) != CONFIG_KEYS:
        raise ValueError(
            f"policy fields differ: expected {sorted(CONFIG_KEYS)}, "
            f"found {sorted(config)}"
        )
    if config.get("schema_version") != 3:
        raise ValueError("schema_version must be 3")
    organization = require_string(config, "organization")
    if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?", organization):
        raise ValueError("organization must be a valid GitHub owner")
    require_positive_integer(config, "organization_id")
    revision = require_string(config, "policy_revision")
    if not re.fullmatch(r"20\d{2}-\d{2}-\d{2}\.[1-9]\d*", revision):
        raise ValueError("policy_revision must use YYYY-MM-DD.N")
    reviewed = date.fromisoformat(require_string(config, "last_reviewed_on"))
    if reviewed > datetime.now(timezone.utc).date():
        raise ValueError("last_reviewed_on cannot be in the future")
    if revision.split(".", 1)[0] != reviewed.isoformat():
        raise ValueError("policy_revision date must equal last_reviewed_on")

    organization_controls = config.get("organization_controls")
    if (
        not isinstance(organization_controls, dict)
        or set(organization_controls) != ORGANIZATION_CONTROL_KEYS
    ):
        raise ValueError("organization_controls has unexpected fields")
    if organization_controls.get("default_repository_permission") not in {
        "none",
        "read",
        "write",
        "admin",
    }:
        raise ValueError(
            "organization_controls.default_repository_permission is invalid"
        )
    if organization_controls.get("actions_allowed_actions") not in {
        "all",
        "local_only",
        "selected",
    }:
        raise ValueError("organization_controls.actions_allowed_actions is invalid")
    if organization_controls.get("actions_enabled_repositories") not in {
        "all",
        "none",
        "selected",
    }:
        raise ValueError(
            "organization_controls.actions_enabled_repositories is invalid"
        )
    if organization_controls.get("actions_default_workflow_permissions") not in {
        "read",
        "write",
    }:
        raise ValueError(
            "organization_controls.actions_default_workflow_permissions is invalid"
        )
    for field in (
        "actions_can_approve_pull_request_reviews",
        "actions_sha_pinning_required",
        "members_can_change_repo_visibility",
        "members_can_create_private_pages",
        "members_can_create_public_pages",
        "members_can_create_repositories",
        "members_can_delete_repositories",
        "two_factor_requirement_enabled",
    ):
        if not isinstance(organization_controls.get(field), bool):
            raise TypeError(f"organization_controls.{field} must be boolean")
    retention_days = organization_controls.get(
        "actions_artifact_and_log_retention_days"
    )
    if (
        not isinstance(retention_days, int)
        or isinstance(retention_days, bool)
        or not 1 <= retention_days <= 400
    ):
        raise ValueError(
            "organization_controls.actions_artifact_and_log_retention_days "
            "must be between 1 and 400"
        )
    minimum_owner_count = organization_controls.get("minimum_owner_count")
    if (
        not isinstance(minimum_owner_count, int)
        or isinstance(minimum_owner_count, bool)
        or minimum_owner_count < 2
    ):
        raise ValueError("organization_controls.minimum_owner_count must be >= 2")
    for field in ("outside_collaborator_count", "pending_invitation_count"):
        value = organization_controls.get(field)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ValueError(f"organization_controls.{field} must be non-negative")

    repositories = config.get("repositories")
    if not isinstance(repositories, list) or not repositories:
        raise ValueError("repositories must be a non-empty array")
    names: list[str] = []
    logical_ids: list[str] = []
    repository_ids: list[int] = []
    artifact_ids: list[str] = []
    for policy in repositories:
        if not isinstance(policy, dict) or set(policy) != REPOSITORY_POLICY_KEYS:
            raise ValueError("repository policy has unexpected fields")
        policy_artifact_ids = require_sorted_unique_strings(
            policy.get("artifact_ids"),
            "repository.artifact_ids",
            allow_empty=True,
        )
        for artifact_id in policy_artifact_ids:
            if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", artifact_id):
                raise ValueError(f"invalid artifact logical id: {artifact_id}")
        artifact_ids.extend(policy_artifact_ids)
        logical_id = require_string(policy, "logical_id")
        if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", logical_id):
            raise ValueError(f"invalid repository logical id: {logical_id}")
        logical_ids.append(logical_id)
        name = require_string(policy, "name")
        if (
            len(name) > 100
            or name in {".", ".."}
            or not re.fullmatch(r"[A-Za-z0-9._-]+", name)
        ):
            raise ValueError(f"invalid repository name: {name}")
        names.append(name)
        repository_ids.append(require_positive_integer(policy, "repository_id"))
        product = require_string(policy, "product")
        profile = require_string(policy, "profile")
        if product not in PRODUCTS:
            raise ValueError(f"{name} has invalid product: {product}")
        if profile not in PROFILES:
            raise ValueError(f"{name} has invalid profile: {profile}")
        if (profile == "governance") != (product == "organization"):
            raise ValueError(f"{name} governance profile/product pairing is invalid")
        if (product == "organization") != (not policy_artifact_ids):
            raise ValueError(
                f"{name} must define artifact ids exactly when it is product-owned"
            )
        if policy.get("visibility") not in {"public", "private"}:
            raise ValueError(f"{name} has invalid visibility")
        access_teams = policy.get("access_teams")
        if not isinstance(access_teams, list) or not access_teams:
            raise ValueError(f"{name} requires at least one access team")
        normalized_teams: list[tuple[str, str]] = []
        for team in access_teams:
            if not isinstance(team, dict) or set(team) != ACCESS_TEAM_KEYS:
                raise ValueError(f"{name} has an invalid access team")
            slug = require_string(team, "slug")
            permission = require_string(team, "permission")
            if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", slug):
                raise ValueError(f"{name} has an invalid access team slug")
            if permission not in TEAM_PERMISSIONS:
                raise ValueError(f"{name} has an invalid team permission")
            normalized_teams.append((slug, permission))
        if normalized_teams != sorted(set(normalized_teams)):
            raise ValueError(f"{name} access teams must be sorted and unique")
        require_sorted_unique_strings(
            policy.get("required_status_checks"),
            f"{name}.required_status_checks",
        )
        require_sorted_unique_strings(
            policy.get("required_paths"),
            f"{name}.required_paths",
        )
        release = policy.get("release")
        if profile in RELEASE_PROFILES and not isinstance(release, dict):
            raise ValueError(f"{name} release profile requires release controls")
        if profile not in RELEASE_PROFILES and release is not None:
            raise ValueError(
                f"{name} non-release profile cannot define release controls"
            )
        if release is None:
            continue
        if set(release) != RELEASE_POLICY_KEYS:
            raise ValueError(f"{name} release policy has unexpected fields")
        team = require_string(release, "review_team")
        if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", team):
            raise ValueError(f"{name} has an invalid release review team")
        if team not in {item["slug"] for item in access_teams}:
            raise ValueError(f"{name} release reviewer must have repository access")
        deployment_policies = release.get("deployment_policies")
        if not isinstance(deployment_policies, list) or not deployment_policies:
            raise ValueError(f"{name} requires release deployment policies")
        normalized: list[tuple[str, str]] = []
        for deployment_policy in deployment_policies:
            if (
                not isinstance(deployment_policy, dict)
                or set(deployment_policy) != DEPLOYMENT_POLICY_KEYS
            ):
                raise ValueError(f"{name} has an invalid deployment policy")
            policy_name = require_string(deployment_policy, "name")
            policy_type = deployment_policy.get("type")
            if policy_type not in {"branch", "tag"}:
                raise ValueError(f"{name} has an invalid deployment policy type")
            normalized.append((policy_type, policy_name))
        if normalized != sorted(set(normalized)):
            raise ValueError(f"{name} deployment policies must be sorted and unique")

    if logical_ids != sorted(set(logical_ids)):
        raise ValueError("repository policies must be sorted by unique logical_id")
    if len({name.casefold() for name in names}) != len(names):
        raise ValueError("repository names must be unique ignoring case")
    if len(repository_ids) != len(set(repository_ids)):
        raise ValueError("repository ids must be unique")
    if len(artifact_ids) != len(set(artifact_ids)):
        raise ValueError("artifact logical ids must be unique")

    security_configuration = config.get("code_security_configuration")
    if (
        not isinstance(security_configuration, dict)
        or set(security_configuration) != CODE_SECURITY_CONFIGURATION_KEYS
    ):
        raise ValueError("code_security_configuration has unexpected fields")
    require_positive_integer(security_configuration, "configuration_id")
    security_logical_id = require_string(security_configuration, "logical_id")
    if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", security_logical_id):
        raise ValueError("code_security_configuration.logical_id is invalid")
    require_string(security_configuration, "name")
    require_string(security_configuration, "description")
    if security_configuration.get("default_for_new_repos") not in {
        "all",
        "none",
        "private_and_internal",
        "public",
    }:
        raise ValueError("code_security_configuration.default_for_new_repos is invalid")
    if security_configuration.get("enforcement") not in {
        "enforced",
        "unenforced",
    }:
        raise ValueError("code_security_configuration.enforcement is invalid")
    security_settings = security_configuration.get("settings")
    if (
        not isinstance(security_settings, dict)
        or set(security_settings) != CODE_SECURITY_SETTING_KEYS
    ):
        raise ValueError("code_security_configuration.settings has unexpected fields")
    feature_statuses = {"disabled", "enabled", "not_set"}
    for field in CODE_SECURITY_SETTING_KEYS - {
        "advanced_security",
        "code_scanning_default_setup_options",
        "code_scanning_options",
        "dependency_graph_autosubmit_action_options",
    }:
        if security_settings.get(field) not in feature_statuses:
            raise ValueError(f"code_security_configuration.settings.{field} is invalid")
    if security_settings.get("advanced_security") not in {"disabled", "enabled"}:
        raise ValueError(
            "code_security_configuration.settings.advanced_security is invalid"
        )
    default_setup_options = security_settings.get("code_scanning_default_setup_options")
    if (
        not isinstance(default_setup_options, dict)
        or set(default_setup_options) != {"runner_label", "runner_type"}
        or default_setup_options.get("runner_type")
        not in {"labeled", "not_set", "standard"}
        or (
            default_setup_options.get("runner_label") is not None
            and not isinstance(default_setup_options.get("runner_label"), str)
        )
    ):
        raise ValueError(
            "code_security_configuration.settings."
            "code_scanning_default_setup_options is invalid"
        )
    if (
        default_setup_options["runner_type"] == "labeled"
        and not default_setup_options["runner_label"]
    ) or (
        default_setup_options["runner_type"] != "labeled"
        and default_setup_options["runner_label"] is not None
    ):
        raise ValueError(
            "code_security_configuration labeled runner settings are inconsistent"
        )
    code_scanning_options = security_settings.get("code_scanning_options")
    if (
        not isinstance(code_scanning_options, dict)
        or set(code_scanning_options) != {"allow_advanced"}
        or not isinstance(code_scanning_options.get("allow_advanced"), bool)
    ):
        raise ValueError(
            "code_security_configuration.settings.code_scanning_options is invalid"
        )
    autosubmit_options = security_settings.get(
        "dependency_graph_autosubmit_action_options"
    )
    if (
        not isinstance(autosubmit_options, dict)
        or set(autosubmit_options) != {"labeled_runners"}
        or not isinstance(autosubmit_options.get("labeled_runners"), bool)
    ):
        raise ValueError(
            "code_security_configuration.settings."
            "dependency_graph_autosubmit_action_options is invalid"
        )

    automation_scopes = config.get("automation_scopes")
    if not isinstance(automation_scopes, list) or not automation_scopes:
        raise ValueError("automation_scopes must be a non-empty array")
    scope_ids: list[str] = []
    secret_names: list[str] = []
    variable_names: list[str] = []
    known_logical_ids = set(logical_ids)
    for scope in automation_scopes:
        if not isinstance(scope, dict) or set(scope) != AUTOMATION_SCOPE_KEYS:
            raise ValueError("automation scope has unexpected fields")
        scope_id = require_string(scope, "logical_id")
        if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", scope_id):
            raise ValueError(f"invalid automation scope logical id: {scope_id}")
        scope_ids.append(scope_id)
        scope_secrets = require_sorted_unique_strings(
            scope.get("organization_secrets"),
            f"automation.{scope_id}.organization_secrets",
            allow_empty=True,
        )
        scope_variables = require_sorted_unique_strings(
            scope.get("organization_variables"),
            f"automation.{scope_id}.organization_variables",
            allow_empty=True,
        )
        if not scope_secrets and not scope_variables:
            raise ValueError(f"automation.{scope_id} must define credentials")
        for name in [*scope_secrets, *scope_variables]:
            if not re.fullmatch(r"[A-Z][A-Z0-9_]*", name):
                raise ValueError(f"automation.{scope_id} has an invalid Actions name")
        secret_names.extend(scope_secrets)
        variable_names.extend(scope_variables)
        repository_logical_ids = require_sorted_unique_strings(
            scope.get("repository_logical_ids"),
            f"automation.{scope_id}.repository_logical_ids",
        )
        unknown = sorted(set(repository_logical_ids) - known_logical_ids)
        if unknown:
            raise ValueError(
                f"automation.{scope_id} references unknown repositories: {unknown}"
            )
    if scope_ids != sorted(set(scope_ids)):
        raise ValueError("automation scopes must be sorted by unique logical_id")
    if len(secret_names) != len(set(secret_names)):
        raise ValueError(
            "organization secret names must belong to one automation scope"
        )
    if len(variable_names) != len(set(variable_names)):
        raise ValueError(
            "organization variable names must belong to one automation scope"
        )


def load_config(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise TypeError("repository policy root must be an object")
    validate_config(value)
    return value


def rules_by_type(
    auditor: Auditor,
    repository: str,
    control: str,
    rules: Any,
    expected_types: set[str],
) -> dict[str, dict[str, Any]]:
    if not isinstance(rules, list) or any(not isinstance(rule, dict) for rule in rules):
        auditor.equal(repository, control, rules, sorted(expected_types))
        return {}
    rule_types = [rule.get("type") for rule in rules]
    auditor.equal(
        repository, f"{control}.types", sorted(rule_types), sorted(expected_types)
    )
    auditor.equal(
        repository,
        f"{control}.unique_types",
        len(rule_types),
        len(set(rule_types)),
    )
    return {
        str(rule["type"]): rule for rule in rules if isinstance(rule.get("type"), str)
    }


def find_ruleset(
    api: API,
    auditor: Auditor,
    repository: str,
    endpoint_root: str,
    rulesets: Any,
    name: str,
    target: str,
) -> dict[str, Any] | None:
    matches = (
        [
            item
            for item in rulesets
            if isinstance(item, dict)
            and item.get("name") == name
            and item.get("target") == target
        ]
        if isinstance(rulesets, list)
        else []
    )
    auditor.equal(repository, f"ruleset.{name}.count", len(matches), 1)
    if len(matches) != 1 or not isinstance(matches[0].get("id"), int):
        return None
    detail = api.get(f"{endpoint_root}/rulesets/{matches[0]['id']}")
    if not isinstance(detail, dict):
        auditor.equal(repository, f"ruleset.{name}.response", detail, "object")
        return None
    return detail


def audit_branch_ruleset(
    auditor: Auditor,
    repository: str,
    detail: dict[str, Any],
    expected_checks: list[str],
) -> None:
    prefix = "ruleset.default_branch"
    auditor.equal(
        repository, f"{prefix}.enforcement", detail.get("enforcement"), "active"
    )
    auditor.equal(repository, f"{prefix}.bypass", detail.get("bypass_actors"), [])
    auditor.equal(
        repository,
        f"{prefix}.conditions",
        detail.get("conditions"),
        {"ref_name": {"exclude": [], "include": ["~DEFAULT_BRANCH"]}},
    )
    rules = rules_by_type(
        auditor,
        repository,
        prefix,
        detail.get("rules"),
        EXPECTED_BRANCH_RULE_TYPES,
    )

    pull_request = rules.get("pull_request", {}).get("parameters")
    if not isinstance(pull_request, dict):
        auditor.equal(repository, f"{prefix}.pull_request", pull_request, "parameters")
    else:
        expected_pull_request = {
            "allowed_merge_methods": ["squash"],
            "dismiss_stale_reviews_on_push": True,
            "require_code_owner_review": True,
            "require_last_push_approval": True,
            "required_review_thread_resolution": True,
        }
        for field, expected in expected_pull_request.items():
            auditor.equal(
                repository,
                f"{prefix}.pull_request.{field}",
                pull_request.get(field),
                expected,
            )
        approvals = pull_request.get("required_approving_review_count")
        auditor.true(
            repository,
            f"{prefix}.pull_request.required_approving_review_count",
            isinstance(approvals, int)
            and not isinstance(approvals, bool)
            and approvals >= 1,
            "integer >= 1",
            approvals,
        )

    statuses = rules.get("required_status_checks", {}).get("parameters")
    if not isinstance(statuses, dict):
        auditor.equal(repository, f"{prefix}.status_checks", statuses, "parameters")
    else:
        contexts = statuses.get("required_status_checks")
        actual_checks = (
            sorted(
                item.get("context")
                for item in contexts
                if isinstance(item, dict) and isinstance(item.get("context"), str)
            )
            if isinstance(contexts, list)
            else contexts
        )
        auditor.equal(
            repository,
            f"{prefix}.status_checks.contexts",
            actual_checks,
            expected_checks,
        )
        auditor.equal(
            repository,
            f"{prefix}.status_checks.strict",
            statuses.get("strict_required_status_checks_policy"),
            True,
        )
        auditor.equal(
            repository,
            f"{prefix}.status_checks.creation",
            statuses.get("do_not_enforce_on_create"),
            True,
        )

    code_scanning = rules.get("code_scanning", {}).get("parameters")
    expected_codeql = [
        {
            "alerts_threshold": "errors",
            "security_alerts_threshold": "high_or_higher",
            "tool": "CodeQL",
        }
    ]
    auditor.equal(
        repository,
        f"{prefix}.code_scanning",
        code_scanning.get("code_scanning_tools")
        if isinstance(code_scanning, dict)
        else code_scanning,
        expected_codeql,
    )


def audit_tag_ruleset(
    auditor: Auditor,
    repository: str,
    detail: dict[str, Any],
) -> None:
    prefix = "ruleset.release_tags"
    auditor.equal(
        repository, f"{prefix}.enforcement", detail.get("enforcement"), "active"
    )
    auditor.equal(repository, f"{prefix}.bypass", detail.get("bypass_actors"), [])
    auditor.equal(
        repository,
        f"{prefix}.conditions",
        detail.get("conditions"),
        {"ref_name": {"exclude": [], "include": ["refs/tags/v*"]}},
    )
    rules_by_type(
        auditor,
        repository,
        prefix,
        detail.get("rules"),
        EXPECTED_TAG_RULE_TYPES,
    )


def audit_release_environment(
    api: API,
    auditor: Auditor,
    repository: str,
    endpoint_root: str,
    policy: dict[str, Any],
) -> None:
    environment = api.get(f"{endpoint_root}/environments/release")
    if not isinstance(environment, dict):
        auditor.equal(repository, "release_environment.response", environment, "object")
        return
    auditor.equal(
        repository,
        "release_environment.deployment_branch_policy",
        environment.get("deployment_branch_policy"),
        {"custom_branch_policies": True, "protected_branches": False},
    )
    protection_rules = environment.get("protection_rules")
    types = (
        sorted(rule.get("type") for rule in protection_rules if isinstance(rule, dict))
        if isinstance(protection_rules, list)
        else protection_rules
    )
    auditor.equal(
        repository,
        "release_environment.protection_rule_types",
        types,
        ["branch_policy", "required_reviewers"],
    )
    reviewer_rules = (
        [
            rule
            for rule in protection_rules
            if isinstance(rule, dict) and rule.get("type") == "required_reviewers"
        ]
        if isinstance(protection_rules, list)
        else []
    )
    auditor.equal(
        repository,
        "release_environment.reviewer_rule_count",
        len(reviewer_rules),
        1,
    )
    if len(reviewer_rules) == 1:
        reviewer_rule = reviewer_rules[0]
        auditor.equal(
            repository,
            "release_environment.prevent_self_review",
            reviewer_rule.get("prevent_self_review"),
            True,
        )
        reviewers = reviewer_rule.get("reviewers")
        normalized_reviewers = (
            sorted(
                (
                    reviewer.get("type"),
                    reviewer.get("reviewer", {}).get("slug"),
                )
                for reviewer in reviewers
                if isinstance(reviewer, dict)
                and isinstance(reviewer.get("reviewer"), dict)
            )
            if isinstance(reviewers, list)
            else reviewers
        )
        auditor.equal(
            repository,
            "release_environment.reviewers",
            normalized_reviewers,
            [("Team", policy["release"]["review_team"])],
        )

    policies = get_all_collection_pages(
        api,
        f"{endpoint_root}/environments/release/deployment-branch-policies?per_page=100",
        "branch_policies",
    )
    branch_policies = (
        policies.get("branch_policies") if isinstance(policies, dict) else None
    )
    normalized_policies = (
        sorted(
            (
                item.get("type"),
                item.get("name"),
            )
            for item in branch_policies
            if isinstance(item, dict)
        )
        if isinstance(branch_policies, list)
        else branch_policies
    )
    expected_policies = sorted(
        (item["type"], item["name"])
        for item in policy["release"]["deployment_policies"]
    )
    auditor.equal(
        repository,
        "release_environment.deployment_policies",
        normalized_policies,
        expected_policies,
    )


def audit_organization(
    api: API,
    auditor: Auditor,
    organization: str,
    organization_id: int,
    controls: dict[str, Any],
    security_configuration: dict[str, Any],
    repository_policies: list[dict[str, Any]],
) -> None:
    metadata = api.get(f"orgs/{organization}")
    if not isinstance(metadata, dict):
        auditor.equal("@organization", "organization.response", metadata, "object")
        return
    auditor.equal(
        "@organization",
        "organization.id",
        metadata.get("id"),
        organization_id,
    )
    login = metadata.get("login")
    auditor.equal(
        "@organization",
        "organization.login",
        login.casefold() if isinstance(login, str) else login,
        organization.casefold(),
    )
    for field in (
        "default_repository_permission",
        "members_can_change_repo_visibility",
        "members_can_create_private_pages",
        "members_can_create_public_pages",
        "members_can_create_repositories",
        "members_can_delete_repositories",
        "two_factor_requirement_enabled",
    ):
        auditor.equal(
            "@organization",
            f"organization.{field}",
            metadata.get(field),
            controls[field],
        )

    owners = get_all_list_pages(
        api,
        f"orgs/{organization}/members?role=admin&per_page=100",
    )
    owner_count = len(owners)
    auditor.true(
        "@organization",
        "organization.owner_count",
        isinstance(owner_count, int)
        and not isinstance(owner_count, bool)
        and owner_count >= controls["minimum_owner_count"],
        f">= {controls['minimum_owner_count']}",
        owner_count,
    )

    outside_collaborators = get_all_list_pages(
        api,
        f"orgs/{organization}/outside_collaborators?per_page=100",
    )
    outside_count = len(outside_collaborators)
    auditor.equal(
        "@organization",
        "organization.outside_collaborator_count",
        outside_count,
        controls["outside_collaborator_count"],
    )

    invitations = get_all_list_pages(
        api,
        f"orgs/{organization}/invitations?per_page=100",
    )
    invitation_count = len(invitations)
    auditor.equal(
        "@organization",
        "organization.pending_invitation_count",
        invitation_count,
        controls["pending_invitation_count"],
    )

    repositories = get_all_list_pages(
        api,
        f"orgs/{organization}/repos?type=all&per_page=100",
    )
    actual_repository_ids = sorted(
        item.get("id") for item in repositories if isinstance(item, dict)
    )
    expected_repository_ids = sorted(
        policy["repository_id"] for policy in repository_policies
    )
    auditor.equal(
        "@organization",
        "organization.repository_ids",
        actual_repository_ids,
        expected_repository_ids,
    )

    actions = api.get(f"orgs/{organization}/actions/permissions")
    expected_actions = {
        "allowed_actions": controls["actions_allowed_actions"],
        "enabled_repositories": controls["actions_enabled_repositories"],
        "sha_pinning_required": controls["actions_sha_pinning_required"],
    }
    for field, expected in expected_actions.items():
        auditor.equal(
            "@organization",
            f"actions.{field}",
            actions.get(field) if isinstance(actions, dict) else actions,
            expected,
        )

    workflow_permissions = api.get(f"orgs/{organization}/actions/permissions/workflow")
    expected_workflow_permissions = {
        "can_approve_pull_request_reviews": controls[
            "actions_can_approve_pull_request_reviews"
        ],
        "default_workflow_permissions": controls[
            "actions_default_workflow_permissions"
        ],
    }
    for field, expected in expected_workflow_permissions.items():
        auditor.equal(
            "@organization",
            f"actions.workflow.{field}",
            workflow_permissions.get(field)
            if isinstance(workflow_permissions, dict)
            else workflow_permissions,
            expected,
        )

    retention = api.get(
        f"orgs/{organization}/actions/permissions/artifact-and-log-retention"
    )
    auditor.equal(
        "@organization",
        "actions.artifact_and_log_retention_days",
        retention.get("days") if isinstance(retention, dict) else retention,
        controls["actions_artifact_and_log_retention_days"],
    )

    expected_release_repository_ids = sorted(
        policy["repository_id"]
        for policy in repository_policies
        if policy["release"] is not None
    )
    immutable_releases = api.get(f"orgs/{organization}/settings/immutable-releases")
    expected_enforcement = "selected" if expected_release_repository_ids else "none"
    actual_enforcement = (
        immutable_releases.get("enforced_repositories")
        if isinstance(immutable_releases, dict)
        else immutable_releases
    )
    auditor.equal(
        "@organization",
        "release.immutable.enforced_repositories",
        actual_enforcement,
        expected_enforcement,
    )
    if expected_enforcement == "selected":
        selected = get_all_collection_pages(
            api,
            f"orgs/{organization}/settings/immutable-releases/"
            "repositories?per_page=100",
            "repositories",
        )
        auditor.equal(
            "@organization",
            "release.immutable.repository_ids",
            selected_repository_ids(selected),
            expected_release_repository_ids,
        )

    configuration_id = security_configuration["configuration_id"]
    configuration = api.get(
        f"orgs/{organization}/code-security/configurations/{configuration_id}"
    )
    expected_configuration_fields = {
        "description": security_configuration["description"],
        "enforcement": security_configuration["enforcement"],
        "id": configuration_id,
        "name": security_configuration["name"],
        "target_type": "organization",
    }
    for field, expected in expected_configuration_fields.items():
        auditor.equal(
            "@organization",
            f"security.configuration.{field}",
            configuration.get(field)
            if isinstance(configuration, dict)
            else configuration,
            expected,
        )
    for field, expected in security_configuration["settings"].items():
        auditor.equal(
            "@organization",
            f"security.configuration.settings.{field}",
            configuration.get(field)
            if isinstance(configuration, dict)
            else configuration,
            expected,
        )

    defaults = api.get(f"orgs/{organization}/code-security/configurations/defaults")
    normalized_defaults = (
        sorted(
            (
                {
                    "configuration_id": (
                        item.get("configuration", {}).get("id")
                        if isinstance(item.get("configuration"), dict)
                        else None
                    ),
                    "default_for_new_repos": item.get("default_for_new_repos"),
                }
                for item in defaults
                if isinstance(item, dict)
            ),
            key=lambda item: (
                str(item["default_for_new_repos"]),
                str(item["configuration_id"]),
            ),
        )
        if isinstance(defaults, list)
        else defaults
    )
    auditor.equal(
        "@organization",
        "security.configuration.defaults",
        normalized_defaults,
        [
            {
                "configuration_id": configuration_id,
                "default_for_new_repos": security_configuration[
                    "default_for_new_repos"
                ],
            }
        ],
    )


def audit_repository(
    api: API,
    auditor: Auditor,
    organization: str,
    organization_id: int,
    security_configuration: dict[str, Any],
    policy: dict[str, Any],
) -> None:
    repository = policy["name"]
    endpoint_root = f"repos/{organization}/{repository}"
    metadata = api.get(endpoint_root)
    if not isinstance(metadata, dict):
        auditor.equal(repository, "repository.response", metadata, "object")
        return

    metadata_name = metadata.get("name")
    auditor.equal(
        repository,
        "repository.id",
        metadata.get("id"),
        policy["repository_id"],
    )
    auditor.equal(
        repository,
        "repository.name",
        metadata_name.casefold() if isinstance(metadata_name, str) else metadata_name,
        repository.casefold(),
    )
    full_name = metadata.get("full_name")
    auditor.equal(
        repository,
        "repository.full_name",
        full_name.casefold() if isinstance(full_name, str) else full_name,
        f"{organization}/{repository}".casefold(),
    )
    owner = metadata.get("owner")
    auditor.equal(
        repository,
        "repository.owner_id",
        owner.get("id") if isinstance(owner, dict) else owner,
        organization_id,
    )
    owner_login = owner.get("login") if isinstance(owner, dict) else None
    auditor.equal(
        repository,
        "repository.owner_login",
        owner_login.casefold() if isinstance(owner_login, str) else owner_login,
        organization.casefold(),
    )

    expected_repository_settings = {
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
    }
    for field, expected in expected_repository_settings.items():
        auditor.equal(
            repository,
            f"repository.{field}",
            metadata.get(field),
            expected,
        )

    security = metadata.get("security_and_analysis")
    for feature in (
        "dependabot_security_updates",
        "secret_scanning",
        "secret_scanning_push_protection",
    ):
        actual = (
            security.get(feature, {}).get("status")
            if isinstance(security, dict) and isinstance(security.get(feature), dict)
            else None
        )
        auditor.equal(repository, f"security.{feature}", actual, "enabled")

    release_capable = policy["release"] is not None
    immutable = api.get(f"{endpoint_root}/immutable-releases")
    auditor.equal(
        repository,
        "release.immutable",
        immutable.get("enabled") if isinstance(immutable, dict) else immutable,
        release_capable,
    )

    actions = api.get(f"{endpoint_root}/actions/permissions")
    expected_actions = {
        "enabled": True,
        "allowed_actions": "all",
        "sha_pinning_required": True,
    }
    for field, expected in expected_actions.items():
        auditor.equal(
            repository,
            f"actions.{field}",
            actions.get(field) if isinstance(actions, dict) else actions,
            expected,
        )

    workflow_permissions = api.get(f"{endpoint_root}/actions/permissions/workflow")
    expected_workflow_permissions = {
        "default_workflow_permissions": "read",
        "can_approve_pull_request_reviews": False,
    }
    for field, expected in expected_workflow_permissions.items():
        auditor.equal(
            repository,
            f"actions.workflow.{field}",
            workflow_permissions.get(field)
            if isinstance(workflow_permissions, dict)
            else workflow_permissions,
            expected,
        )

    codeql = api.get(f"{endpoint_root}/code-scanning/default-setup")
    expected_codeql_setup = {
        "query_suite": "default",
        "schedule": "weekly",
        "state": "configured",
        "threat_model": "remote_and_local",
    }
    for field, expected in expected_codeql_setup.items():
        auditor.equal(
            repository,
            f"security.codeql_default_setup.{field}",
            codeql.get(field) if isinstance(codeql, dict) else codeql,
            expected,
        )

    managed_security = api.get(f"{endpoint_root}/code-security-configuration")
    managed_configuration = (
        managed_security.get("configuration")
        if isinstance(managed_security, dict)
        else None
    )
    auditor.equal(
        repository,
        "security.configuration.status",
        managed_security.get("status")
        if isinstance(managed_security, dict)
        else managed_security,
        (
            "enforced"
            if security_configuration["enforcement"] == "enforced"
            else "attached"
        ),
    )
    auditor.equal(
        repository,
        "security.configuration.id",
        managed_configuration.get("id")
        if isinstance(managed_configuration, dict)
        else managed_configuration,
        security_configuration["configuration_id"],
    )

    for path in policy["required_paths"]:
        encoded_path = quote(path, safe="/")
        try:
            content = api.get(f"{endpoint_root}/contents/{encoded_path}?ref=main")
        except Exception as error:  # noqa: BLE001 - represent absence as policy drift.
            content = f"{type(error).__name__}: {error}"
        auditor.equal(
            repository,
            f"required_path.{path}",
            content.get("type") if isinstance(content, dict) else content,
            "file",
        )

    teams = get_all_list_pages(api, f"{endpoint_root}/teams?per_page=100")
    normalized_teams = (
        sorted(
            (team.get("slug"), team.get("permission"))
            for team in teams
            if isinstance(team, dict)
        )
        if isinstance(teams, list)
        else teams
    )
    expected_teams = sorted(
        (team["slug"], team["permission"]) for team in policy["access_teams"]
    )
    auditor.equal(
        repository,
        "repository.access_teams",
        normalized_teams,
        expected_teams,
    )

    rulesets = get_all_list_pages(
        api,
        f"{endpoint_root}/rulesets?includes_parents=true&per_page=100",
    )
    branch = find_ruleset(
        api,
        auditor,
        repository,
        endpoint_root,
        rulesets,
        "Protect default branch",
        "branch",
    )
    if branch is not None:
        audit_branch_ruleset(
            auditor,
            repository,
            branch,
            policy["required_status_checks"],
        )
    if release_capable:
        tags = find_ruleset(
            api,
            auditor,
            repository,
            endpoint_root,
            rulesets,
            "Protect release tags",
            "tag",
        )
        if tags is not None:
            audit_tag_ruleset(auditor, repository, tags)
        audit_release_environment(api, auditor, repository, endpoint_root, policy)
    else:
        tag_rulesets = (
            [
                item
                for item in rulesets
                if isinstance(item, dict)
                and item.get("name") == "Protect release tags"
                and item.get("target") == "tag"
            ]
            if isinstance(rulesets, list)
            else rulesets
        )
        auditor.equal(
            repository,
            "ruleset.Protect release tags.count",
            len(tag_rulesets) if isinstance(tag_rulesets, list) else tag_rulesets,
            0,
        )


def selected_repository_ids(value: Any) -> list[int] | Any:
    repositories = value.get("repositories") if isinstance(value, dict) else None
    if not isinstance(repositories, list) or any(
        not isinstance(item, dict)
        or not isinstance(item.get("id"), int)
        or isinstance(item.get("id"), bool)
        for item in repositories
    ):
        return value
    return sorted(item["id"] for item in repositories)


def audit_policy_auditor_installation(
    metadata_api: API,
    scope_api: API,
    auditor: Auditor,
    organization: str,
    config: dict[str, Any],
    app_slug: str,
    installation_id: int,
) -> None:
    installations = get_all_collection_pages(
        metadata_api,
        f"orgs/{organization}/installations?per_page=100",
        "installations",
    )["installations"]
    matches = [
        installation
        for installation in installations
        if isinstance(installation, dict) and installation.get("id") == installation_id
    ]
    auditor.equal(
        "@organization",
        "automation.policy-auditor.installation.count",
        len(matches),
        1,
    )
    if len(matches) != 1:
        return
    installation = matches[0]
    expected_metadata = {
        "app_slug": app_slug,
        "events": [],
        "permissions": EXPECTED_POLICY_AUDITOR_PERMISSIONS,
        "repository_selection": "all",
        "suspended_at": None,
        "target_id": config["organization_id"],
        "target_type": "Organization",
    }
    for field, expected in expected_metadata.items():
        auditor.equal(
            "@organization",
            f"automation.policy-auditor.installation.{field}",
            installation.get(field),
            expected,
        )

    response = get_all_collection_pages(
        scope_api,
        "installation/repositories?per_page=100",
        "repositories",
    )
    actual = selected_repository_ids(response)
    expected = sorted(policy["repository_id"] for policy in config["repositories"])
    auditor.equal(
        "@organization",
        "automation.policy-auditor.installation.repository_ids",
        actual,
        expected,
    )


def audit_automation_scopes(
    api: API,
    auditor: Auditor,
    organization: str,
    config: dict[str, Any],
) -> None:
    repositories_by_logical_id = {
        policy["logical_id"]: policy for policy in config["repositories"]
    }
    expected_names = {
        "secret": sorted(
            name
            for scope in config.get("automation_scopes", [])
            for name in scope["organization_secrets"]
        ),
        "variable": sorted(
            name
            for scope in config.get("automation_scopes", [])
            for name in scope["organization_variables"]
        ),
    }
    for kind, collection, page_size in (
        ("secret", "secrets", 100),
        ("variable", "variables", 30),
    ):
        try:
            response = get_all_collection_pages(
                api,
                f"orgs/{organization}/actions/{kind}s?per_page={page_size}",
                collection,
            )
        except Exception as error:  # noqa: BLE001 - continue with other scopes.
            auditor.drifts.append(
                Drift(
                    repository="@organization",
                    control=f"automation.organization_{kind}s.api",
                    expected="complete readable inventory",
                    actual=f"{type(error).__name__}: {error}",
                )
            )
            continue
        entries = response[collection]
        actual_names = sorted(
            item.get("name") for item in entries if isinstance(item, dict)
        )
        auditor.equal(
            "@organization",
            f"automation.organization_{kind}s.names",
            actual_names,
            expected_names[kind],
        )
        visibility = {
            item.get("name"): item.get("visibility")
            for item in entries
            if isinstance(item, dict) and item.get("name") in expected_names[kind]
        }
        auditor.equal(
            "@organization",
            f"automation.organization_{kind}s.visibility",
            visibility,
            {name: "selected" for name in expected_names[kind]},
        )

    for scope in config.get("automation_scopes", []):
        expected = sorted(
            repositories_by_logical_id[logical_id]["repository_id"]
            for logical_id in scope["repository_logical_ids"]
        )
        for kind, names in (
            ("secret", scope["organization_secrets"]),
            ("variable", scope["organization_variables"]),
        ):
            for name in names:
                control = f"automation.{scope['logical_id']}.{kind}.{name}.repositories"
                endpoint = (
                    f"orgs/{organization}/actions/{kind}s/"
                    f"{quote(name, safe='')}/repositories?per_page=100"
                )
                try:
                    response = get_all_collection_pages(
                        api,
                        endpoint,
                        "repositories",
                    )
                except Exception as error:  # noqa: BLE001 - isolate one credential scope.
                    auditor.drifts.append(
                        Drift(
                            repository="@organization",
                            control=f"{control}.api",
                            expected="readable selected-repository scope",
                            actual=f"{type(error).__name__}: {error}",
                        )
                    )
                    continue
                actual = selected_repository_ids(response)
                auditor.equal("@organization", control, actual, expected)
                if isinstance(response, dict):
                    auditor.equal(
                        "@organization",
                        f"{control}.total_count",
                        response.get("total_count"),
                        len(expected),
                    )


def audit_repositories(
    api: API,
    config: dict[str, Any],
    scope_api: API | None = None,
    policy_app_slug: str | None = None,
    policy_installation_id: int | None = None,
) -> dict[str, Any]:
    auditor = Auditor()
    organization = config["organization"]
    repositories: list[str] = []
    try:
        audit_organization(
            api,
            auditor,
            organization,
            config["organization_id"],
            config["organization_controls"],
            config["code_security_configuration"],
            config["repositories"],
        )
    except Exception as error:  # noqa: BLE001 - report organization drift and continue.
        auditor.drifts.append(
            Drift(
                repository="@organization",
                control="audit.api",
                expected="successful complete API audit",
                actual=f"{type(error).__name__}: {error}",
            )
        )
    if scope_api is not None:
        try:
            if not policy_app_slug or policy_installation_id is None:
                raise ValueError("policy auditor App identity is required")
            audit_policy_auditor_installation(
                api,
                scope_api,
                auditor,
                organization,
                config,
                policy_app_slug,
                policy_installation_id,
            )
        except Exception as error:  # noqa: BLE001 - report install drift and continue.
            auditor.drifts.append(
                Drift(
                    repository="@organization",
                    control="automation.policy-auditor.installation.api",
                    expected="successful complete installation scope audit",
                    actual=f"{type(error).__name__}: {error}",
                )
            )
        try:
            audit_automation_scopes(
                scope_api,
                auditor,
                organization,
                config,
            )
        except Exception as error:  # noqa: BLE001 - report scope drift and continue.
            auditor.drifts.append(
                Drift(
                    repository="@organization",
                    control="automation.credential_scopes.api",
                    expected="successful complete credential scope audit",
                    actual=f"{type(error).__name__}: {error}",
                )
            )
    for policy in config["repositories"]:
        repository = policy["name"]
        repositories.append(repository)
        try:
            audit_repository(
                api,
                auditor,
                organization,
                config["organization_id"],
                config["code_security_configuration"],
                policy,
            )
        except Exception as error:  # noqa: BLE001 - report one repository and continue.
            auditor.drifts.append(
                Drift(
                    repository=repository,
                    control="audit.api",
                    expected="successful complete API audit",
                    actual=f"{type(error).__name__}: {error}",
                )
            )
    return {
        "schema_version": 2,
        "policy_revision": config["policy_revision"],
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "organization": organization,
        "repositories": repositories,
        "status": "compliant" if not auditor.drifts else "drift",
        "drift_count": len(auditor.drifts),
        "drifts": [asdict(drift) for drift in auditor.drifts],
    }


def markdown_value(value: Any) -> str:
    rendered = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    return rendered.replace("|", "\\|").replace("\n", " ")


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Organization repository policy audit",
        "",
        f"- Policy revision: `{report['policy_revision']}`",
        f"- Generated: `{report['generated_at']}`",
        f"- Status: **{report['status']}**",
        f"- Drift count: `{report['drift_count']}`",
        "",
    ]
    if not report["drifts"]:
        lines.append(
            "The organization and all repositories match the reviewed baseline."
        )
        lines.append("")
        return "\n".join(lines)
    lines.extend(
        [
            "| Repository | Control | Expected | Actual |",
            "| --- | --- | --- | --- |",
        ]
    )
    for drift in report["drifts"]:
        lines.append(
            f"| `{drift['repository']}` | `{drift['control']}` | "
            f"`{markdown_value(drift['expected'])}` | "
            f"`{markdown_value(drift['actual'])}` |"
        )
    lines.append("")
    lines.append(
        "The audit is read-only. Resolve drift through a reviewed settings or "
        "configuration change; do not weaken the baseline silently."
    )
    lines.append("")
    return "\n".join(lines)


def write_report(
    report: dict[str, Any],
    json_output: Path,
    markdown_output: Path,
) -> None:
    json_output.write_text(
        json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    markdown_output.write_text(render_markdown(report), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("config/repository-policies.json"),
    )
    parser.add_argument(
        "--json-output",
        type=Path,
        default=Path("audit-report.json"),
    )
    parser.add_argument(
        "--markdown-output",
        type=Path,
        default=Path("audit-report.md"),
    )
    parser.add_argument(
        "--api-base-url",
        default=os.environ.get("GITHUB_API_URL", "https://api.github.com"),
    )
    parser.add_argument(
        "--organization",
        default=os.environ.get("POLICY_AUDIT_ORGANIZATION"),
        help="Override the configured owner for a rename or migration audit.",
    )
    args = parser.parse_args()

    report_organization = args.organization or "unavailable"
    try:
        config = load_config(args.config)
        if args.organization:
            if not re.fullmatch(
                r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?",
                args.organization,
            ):
                raise ValueError("--organization must be a valid GitHub owner")
            config = {**config, "organization": args.organization}
        report_organization = config["organization"]
        api = GitHubAPI(os.environ.get("GH_TOKEN", ""), args.api_base_url)
        scope_token = os.environ.get("GH_SCOPE_TOKEN", "")
        if not scope_token:
            raise ValueError("GH_SCOPE_TOKEN is required for credential-scope audit")
        scope_api = GitHubAPI(scope_token, args.api_base_url)
        policy_app_slug = os.environ.get("POLICY_AUDIT_APP_SLUG", "")
        if not policy_app_slug:
            raise ValueError("POLICY_AUDIT_APP_SLUG is required")
        installation_id_value = os.environ.get("POLICY_AUDIT_INSTALLATION_ID", "")
        if not installation_id_value.isdigit() or int(installation_id_value) < 1:
            raise ValueError("POLICY_AUDIT_INSTALLATION_ID must be a positive integer")
        report = audit_repositories(
            api,
            config,
            scope_api,
            policy_app_slug,
            int(installation_id_value),
        )
    except Exception as error:  # noqa: BLE001 - preserve a machine-readable failure.
        report = {
            "schema_version": 2,
            "policy_revision": "unavailable",
            "generated_at": datetime.now(timezone.utc)
            .isoformat()
            .replace("+00:00", "Z"),
            "organization": report_organization,
            "repositories": [],
            "status": "drift",
            "drift_count": 1,
            "drifts": [
                asdict(
                    Drift(
                        repository=".github",
                        control="audit.configuration",
                        expected="valid policy and authenticated API",
                        actual=f"{type(error).__name__}: {error}",
                    )
                )
            ],
        }
    write_report(report, args.json_output, args.markdown_output)
    print(
        f"Repository policy audit: {report['status']} "
        f"({report['drift_count']} drift items)"
    )
    return 0 if report["status"] == "compliant" else 1


if __name__ == "__main__":
    sys.exit(main())
