"""Focused tests for exact candidate metadata construction."""

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).with_name("build_remote_candidate_template.py")
SPEC = importlib.util.spec_from_file_location("candidate_builder", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("unable to load candidate builder")
builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(builder)


class CandidateBuilderTests(unittest.TestCase):
    def test_image_requires_immutable_digest(self) -> None:
        value = builder.image(
            "ghcr.io/camellia-computing/remote-server@sha256:" + "a" * 64,
            "remote-server",
            "b" * 40,
        )
        self.assertEqual(value["digest"], "sha256:" + "a" * 64)
        with self.assertRaisesRegex(ValueError, "repository@sha256"):
            builder.image(
                "ghcr.io/example/remote-server:latest", "remote-server", "b" * 40
            )

    def test_artifact_hash_is_bounded_and_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "artifact.zip"
            path.write_bytes(b"remote-artifact")
            first = builder.artifact("remote-client-web", "web", path, "b" * 40)
            second = builder.artifact("remote-client-web", "web", path, "b" * 40)
            self.assertEqual(first, second)
            self.assertEqual(first["size_bytes"], len(b"remote-artifact"))

    def test_candidate_artifacts_are_sorted(self) -> None:
        result = builder.candidate(
            "remote-client",
            "remote-client",
            "b" * 40,
            artifacts=[
                {"name": "remote-client-web"},
                {"name": "remote-client-controller"},
            ],
        )
        self.assertEqual(
            [item["name"] for item in result["artifacts"]],
            ["remote-client-controller", "remote-client-web"],
        )


if __name__ == "__main__":
    unittest.main()
