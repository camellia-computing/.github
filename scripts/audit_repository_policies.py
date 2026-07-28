#!/usr/bin/env python3
"""Audit release-capable repositories against the reviewed organization policy."""

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


TARGET_REPOSITORIES = {
    "nexus",
    "nexus-management-server",
    "remote-client",
    "remote-management-server",
    "remote-server",
}
CONFIG_KEYS = {
    "$schema",
    "schema_version",
    "policy_revision",
    "organization",
    "last_reviewed_on",
    "repositories",
}
REPOSITORY_POLICY_KEYS = {
    "name",
    "visibility",
    "required_status_checks",
    "required_paths",
    "release_review_team",
    "release_deployment_policies",
}
DEPLOYMENT_POLICY_KEYS = {"name", "type"}
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
                "User-Agent": "camellia-repository-policy-audit",
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
            raise RuntimeError(f"GitHub API unavailable for {endpoint}: {error}") from error
        if not content:
            return None
        return json.loads(content)


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


def require_sorted_unique_strings(value: Any, name: str) -> list[str]:
    if (
        not isinstance(value, list)
        or not value
        or any(not isinstance(item, str) or not item for item in value)
        or value != sorted(set(value))
    ):
        raise ValueError(f"{name} must be a sorted, non-empty, unique string array")
    return value


def validate_config(config: dict[str, Any]) -> None:
    if set(config) != CONFIG_KEYS:
        raise ValueError(
            f"policy fields differ: expected {sorted(CONFIG_KEYS)}, "
            f"found {sorted(config)}"
        )
    if config.get("schema_version") != 1:
        raise ValueError("schema_version must be 1")
    if config.get("organization") != "camellia-computing":
        raise ValueError("organization must be camellia-computing")
    revision = require_string(config, "policy_revision")
    if not re.fullmatch(r"20\d{2}-\d{2}-\d{2}\.[1-9]\d*", revision):
        raise ValueError("policy_revision must use YYYY-MM-DD.N")
    reviewed = date.fromisoformat(require_string(config, "last_reviewed_on"))
    if reviewed > date.today():
        raise ValueError("last_reviewed_on cannot be in the future")
    if revision.split(".", 1)[0] != reviewed.isoformat():
        raise ValueError("policy_revision date must equal last_reviewed_on")

    repositories = config.get("repositories")
    if not isinstance(repositories, list) or not repositories:
        raise ValueError("repositories must be a non-empty array")
    names: list[str] = []
    for policy in repositories:
        if not isinstance(policy, dict) or set(policy) != REPOSITORY_POLICY_KEYS:
            raise ValueError("repository policy has unexpected fields")
        name = require_string(policy, "name")
        if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", name):
            raise ValueError(f"invalid repository name: {name}")
        names.append(name)
        if policy.get("visibility") not in {"public", "private"}:
            raise ValueError(f"{name} has invalid visibility")
        require_sorted_unique_strings(
            policy.get("required_status_checks"),
            f"{name}.required_status_checks",
        )
        require_sorted_unique_strings(
            policy.get("required_paths"),
            f"{name}.required_paths",
        )
        team = require_string(policy, "release_review_team")
        if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", team):
            raise ValueError(f"{name} has an invalid release review team")
        deployment_policies = policy.get("release_deployment_policies")
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

    if names != sorted(set(names)):
        raise ValueError("repository policies must be sorted and unique")
    if set(names) != TARGET_REPOSITORIES:
        raise ValueError(
            f"repository policy scope differs: expected {sorted(TARGET_REPOSITORIES)}, "
            f"found {sorted(names)}"
        )


def load_config(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("repository policy root must be an object")
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
    auditor.equal(repository, f"{control}.types", sorted(rule_types), sorted(expected_types))
    auditor.equal(
        repository,
        f"{control}.unique_types",
        len(rule_types),
        len(set(rule_types)),
    )
    return {
        str(rule["type"]): rule
        for rule in rules
        if isinstance(rule.get("type"), str)
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
    auditor.equal(repository, f"{prefix}.enforcement", detail.get("enforcement"), "active")
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
            isinstance(approvals, int) and not isinstance(approvals, bool) and approvals >= 1,
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
    auditor.equal(repository, f"{prefix}.enforcement", detail.get("enforcement"), "active")
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
            [("Team", policy["release_review_team"])],
        )

    policies = api.get(
        f"{endpoint_root}/environments/release/deployment-branch-policies"
    )
    branch_policies = policies.get("branch_policies") if isinstance(policies, dict) else None
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
        for item in policy["release_deployment_policies"]
    )
    auditor.equal(
        repository,
        "release_environment.deployment_policies",
        normalized_policies,
        expected_policies,
    )


def audit_repository(
    api: API,
    auditor: Auditor,
    organization: str,
    policy: dict[str, Any],
) -> None:
    repository = policy["name"]
    endpoint_root = f"repos/{organization}/{repository}"
    metadata = api.get(endpoint_root)
    if not isinstance(metadata, dict):
        auditor.equal(repository, "repository.response", metadata, "object")
        return

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
            if isinstance(security, dict)
            and isinstance(security.get(feature), dict)
            else None
        )
        auditor.equal(repository, f"security.{feature}", actual, "enabled")

    immutable = api.get(f"{endpoint_root}/immutable-releases")
    auditor.equal(
        repository,
        "release.immutable",
        immutable.get("enabled") if isinstance(immutable, dict) else immutable,
        True,
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

    rulesets = api.get(f"{endpoint_root}/rulesets?includes_parents=true&per_page=100")
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


def audit_repositories(api: API, config: dict[str, Any]) -> dict[str, Any]:
    auditor = Auditor()
    organization = config["organization"]
    repositories: list[str] = []
    for policy in config["repositories"]:
        repository = policy["name"]
        repositories.append(repository)
        try:
            audit_repository(api, auditor, organization, policy)
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
        "schema_version": 1,
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
        "# Camellia repository policy audit",
        "",
        f"- Policy revision: `{report['policy_revision']}`",
        f"- Generated: `{report['generated_at']}`",
        f"- Status: **{report['status']}**",
        f"- Drift count: `{report['drift_count']}`",
        "",
    ]
    if not report["drifts"]:
        lines.append("All release-capable repositories match the reviewed baseline.")
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
    args = parser.parse_args()

    try:
        config = load_config(args.config)
        api = GitHubAPI(os.environ.get("GH_TOKEN", ""), args.api_base_url)
        report = audit_repositories(api, config)
    except Exception as error:  # noqa: BLE001 - preserve a machine-readable failure.
        report = {
            "schema_version": 1,
            "policy_revision": "unavailable",
            "generated_at": datetime.now(timezone.utc)
            .isoformat()
            .replace("+00:00", "Z"),
            "organization": "camellia-computing",
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
