#!/usr/bin/env python3
"""Resolve physical repository names from the logical organization policy."""

from __future__ import annotations

import json
from pathlib import Path

from audit_repository_policies import REVIEWED_CONFIG_PATH


def repository_names(config_path: Path) -> list[str]:
    config = json.loads(config_path.read_text(encoding="utf-8"))
    repositories = config.get("repositories") if isinstance(config, dict) else None
    if not isinstance(repositories, list) or not repositories:
        raise ValueError("policy config must contain repositories")
    names = [item.get("name") for item in repositories if isinstance(item, dict)]
    logical_ids = [
        item.get("logical_id") for item in repositories if isinstance(item, dict)
    ]
    if (
        len(names) != len(repositories)
        or len(logical_ids) != len(repositories)
        or any(not isinstance(name, str) or not name for name in names)
        or any(
            not isinstance(logical_id, str) or not logical_id
            for logical_id in logical_ids
        )
        or logical_ids != sorted(set(logical_ids))
        or len({name.casefold() for name in names}) != len(names)
    ):
        raise ValueError(
            "repository policies must have unique names and be sorted by logical_id"
        )
    return sorted(names, key=str.casefold)


def main() -> None:
    rendered = "\n".join(repository_names(REVIEWED_CONFIG_PATH))
    print("repositories<<POLICY_REPOSITORIES")
    print(rendered)
    print("POLICY_REPOSITORIES")


if __name__ == "__main__":
    main()
