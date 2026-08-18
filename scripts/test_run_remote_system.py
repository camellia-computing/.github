"""Focused runner tests using a hermetic fake Docker CLI and driver."""

from __future__ import annotations

import importlib.util
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

try:
    from scripts.test_validate_remote_system_manifest import (
        HARNESS_COMMIT,
        NAMES,
        manifest,
    )
except ModuleNotFoundError:
    from test_validate_remote_system_manifest import HARNESS_COMMIT, NAMES, manifest


SCRIPT = Path(__file__).with_name("run_remote_system.py")
SPEC = importlib.util.spec_from_file_location("remote_runner", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("unable to load Remote runner")
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


class RemoteRunnerTests(unittest.TestCase):
    def test_hermetic_smoke_run_cleans_workspace_and_writes_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bin_dir = root / "bin"
            trusted = root / "trusted"
            run_dir = root / "run"
            bin_dir.mkdir()
            trusted.mkdir()
            run_dir.mkdir()
            fake_docker = bin_dir / "docker"
            fake_docker.write_text(
                """#!/usr/bin/env python3
import json
import sys
args = sys.argv[1:]
if "config" in args:
    print(json.dumps({"services": {
      "postgres": {"image": "postgres:18-alpine@sha256:9a8afca54e7861fd90fab5fdf4c42477a6b1cb7d293595148e674e0a3181de15"},
      "migrate": {"image": "ghcr.io/camellia-computing/remote-management-server@sha256:" + "2" * 64},
      "management": {"image": "ghcr.io/camellia-computing/remote-management-server@sha256:" + "2" * 64},
      "identity": {"image": "ghcr.io/camellia-computing/remote-server@sha256:" + "3" * 64},
      "relay": {"image": "ghcr.io/camellia-computing/remote-server@sha256:" + "3" * 64}
    }}))
sys.exit(0)
"""
            )
            fake_docker.chmod(fake_docker.stat().st_mode | stat.S_IXUSR)
            driver = trusted / "scenario-driver.py"
            driver.write_text(
                """#!/usr/bin/env python3
import json
import pathlib
import sys
args = sys.argv[1:]
scenario = args[args.index("--scenario") + 1]
attempt = args[args.index("--attempt-id") + 1]
output = pathlib.Path(args[args.index("--output") + 1])
evidence = output.with_suffix(".evidence.json")
evidence.write_text(json.dumps({"events": [{"name": scenario, "observed": True}]}))
output.write_text(json.dumps({"status": "passed", "attempt_id": attempt,
                              "evidence_file": str(evidence)}))
"""
            )
            driver.chmod(driver.stat().st_mode | stat.S_IXUSR)
            candidate = manifest()
            template = {
                key: candidate[key]
                for key in (
                    "schema_version",
                    "contract_revision",
                    "organization",
                    "candidates",
                    "compatibility",
                )
            }
            template_path = root / "candidate.json"
            template_path.write_text(json.dumps(template))
            compose = root / "compose.yaml"
            compose.write_text("services: {}\n")
            output = root / "result.json"
            env_map = json.dumps(NAMES, sort_keys=True)
            old_path = os.environ.get("PATH", "")
            os.environ["PATH"] = f"{bin_dir}:{old_path}"
            try:
                status = runner.main(
                    [
                        "--candidate-template",
                        str(template_path),
                        "--contract",
                        str(SCRIPT.parents[1] / "config/remote-system-contract.json"),
                        "--repository-map",
                        env_map,
                        "--compose-file",
                        str(compose),
                        "--scenario-driver",
                        str(driver),
                        "--trusted-driver-root",
                        str(trusted),
                        "--output-manifest",
                        str(output),
                        "--workdir",
                        str(run_dir),
                        "--run-id",
                        "abc12345",
                        "--harness-commit",
                        HARNESS_COMMIT,
                    ]
                )
            finally:
                os.environ["PATH"] = old_path
            self.assertEqual(status, 0)
            self.assertTrue(output.is_file())
            self.assertFalse(run_dir.exists())
            validated = json.loads(output.read_text())
            self.assertEqual(
                [item["status"] for item in validated["scenarios"]],
                ["passed"] * 5,
            )

    def test_driver_outside_trusted_root_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            driver = root / "driver"
            (root / "trusted").mkdir()
            driver.write_text("#!/bin/sh\n")
            driver.chmod(driver.stat().st_mode | stat.S_IXUSR)
            with self.assertRaisesRegex(runner.HarnessError, "outside"):
                runner.verify_driver(driver, root / "trusted")


if __name__ == "__main__":
    unittest.main()
