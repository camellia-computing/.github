#!/usr/bin/env python3
"""Resolve physical repository names from the logical organization policy."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def repository_names(config_path: Path) -> list[str]:
    config = json.loads(config_path.read_text(encoding="utf-8"))
    repositories = config.get("repositories") if isinstance(config, dict) else None
    if not isinstance(repositories, list) or not repositories:
        raise ValueError("policy config must contain repositories")
    names = [item.get("name") for item in repositories if isinstance(item, dict)]
    if (
        len(names) != len(repositories)
        or any(not isinstance(name, str) or not name for name in names)
        or names != sorted(set(names))
    ):
        raise ValueError("repository names must be sorted, unique strings")
    return names


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("config/repository-policies.json"),
    )
    parser.add_argument("--github-output", type=Path)
    args = parser.parse_args()
    rendered = "\n".join(repository_names(args.config))
    if args.github_output:
        with args.github_output.open("a", encoding="utf-8") as output:
            output.write("repositories<<POLICY_REPOSITORIES\n")
            output.write(rendered)
            output.write("\nPOLICY_REPOSITORIES\n")
    else:
        print(rendered)


if __name__ == "__main__":
    main()
