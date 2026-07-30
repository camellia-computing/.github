#!/usr/bin/env python3
"""Regression tests for protected GitHub Actions signing bundles."""

from __future__ import annotations

import base64
import importlib.util
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT_PATH = Path(__file__).with_name("create-github-signing-bundle.py")
SPEC = importlib.util.spec_from_file_location("github_signing_bundle", SCRIPT_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load create-github-signing-bundle.py")
BUNDLE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUNDLE)


class GitHubSigningBundleTests(unittest.TestCase):
    def create_inputs(self, directory: Path) -> tuple[Path, Path, Path]:
        identity = directory / "identity.json"
        certificate = directory / "certificate.pfx"
        password = directory / "password.txt"
        identity.write_text(
            json.dumps(
                {
                    "schemaVersion": 1,
                    "platform": "windows",
                    "certificateSha256": "A" * 64,
                    "nativeSha1Thumbprint": "B" * 40,
                }
            ),
            encoding="utf-8",
        )
        certificate.write_bytes(b"test-pfx-bytes\x00\x01")
        password.write_text("test-password", encoding="utf-8")
        return identity, certificate, password

    def create_bundle(self, directory: Path) -> Path:
        identity, certificate, password = self.create_inputs(directory)
        return BUNDLE.main(
            [
                str(directory),
                "--platform",
                "windows",
                "--distribution-trust",
                "private-trust",
                "--identity-file",
                str(identity),
                "--variable",
                "WINDOWS_CODESIGN_CERTIFICATE_SHA256=" + ("A" * 64),
                "--variable",
                "WINDOWS_SIGNING_TRUST_MODE=private-trust",
                "--secret-base64",
                f"WINDOWS_CODESIGN_PFX_BASE64={certificate}",
                "--secret",
                f"WINDOWS_CODESIGN_PFX_PASSWORD={password}",
            ]
        )

    def test_bundle_contains_exact_non_secret_contract_and_protected_payloads(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            bundle = self.create_bundle(directory)

            self.assertTrue((bundle / "README.md").is_file())
            self.assertTrue((bundle / "metadata.json").is_file())
            self.assertTrue((bundle / "variables.env").is_file())
            self.assertTrue((bundle / "upload.sh").is_file())
            self.assertTrue((bundle / "Upload.ps1").is_file())
            self.assertEqual(
                (bundle / "variables.env").read_text(encoding="utf-8"),
                "WINDOWS_CODESIGN_CERTIFICATE_SHA256=" + ("A" * 64) + "\n"
                "WINDOWS_SIGNING_TRUST_MODE=private-trust\n",
            )
            self.assertEqual(
                (bundle / "secrets" / "WINDOWS_CODESIGN_PFX_BASE64").read_bytes(),
                base64.b64encode(b"test-pfx-bytes\x00\x01"),
            )
            self.assertEqual(
                (bundle / "secrets" / "WINDOWS_CODESIGN_PFX_PASSWORD").read_text(
                    encoding="utf-8"
                ),
                "test-password",
            )

            metadata = json.loads(
                (bundle / "metadata.json").read_text(encoding="utf-8")
            )
            self.assertEqual(metadata["platform"], "windows")
            self.assertEqual(metadata["distribution_trust"], "private-trust")
            self.assertEqual(
                metadata["github_actions"]["secrets"],
                ["WINDOWS_CODESIGN_PFX_BASE64", "WINDOWS_CODESIGN_PFX_PASSWORD"],
            )
            public_files = "\n".join(
                (bundle / name).read_text(encoding="utf-8")
                for name in (
                    "README.md",
                    "metadata.json",
                    "variables.env",
                    "upload.sh",
                    "Upload.ps1",
                )
            )
            self.assertNotIn("test-password", public_files)
            self.assertNotIn("test-pfx-bytes", public_files)

    def test_upload_helpers_parse_without_contacting_github(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bundle = self.create_bundle(Path(temporary))
            subprocess.run(["bash", "-n", str(bundle / "upload.sh")], check=True)
            subprocess.run(["bash", str(bundle / "upload.sh"), "--help"], check=True)
            if shutil.which("pwsh"):
                environment = os.environ.copy()
                environment["SIGNING_BUNDLE_TEST_PATH"] = str(bundle / "Upload.ps1")
                subprocess.run(
                    [
                        "pwsh",
                        "-NoProfile",
                        "-Command",
                        (
                            "$tokens = $null; $errors = $null; "
                            "[System.Management.Automation.Language.Parser]::ParseFile("
                            "$env:SIGNING_BUNDLE_TEST_PATH, [ref]$tokens, [ref]$errors) | Out-Null; "
                            "if ($errors.Count) { $errors | ForEach-Object { "
                            "[Console]::Error.WriteLine($_.Message) }; exit 1 }"
                        ),
                    ],
                    check=True,
                    env=environment,
                )

    def test_upload_helpers_stream_secrets_without_command_line_values(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            bundle = self.create_bundle(directory)
            fake_bin = directory / "bin"
            fake_bin.mkdir()
            trace = directory / "gh-trace.txt"
            fake_gh = fake_bin / "gh"
            fake_gh.write_text(
                "#!/usr/bin/env bash\n"
                "set -euo pipefail\n"
                'printf \'%s\\n\' "$*" >> "$GH_TRACE"\n'
                'if [[ "$1" == secret && "$2" == set ]]; then\n'
                "  bytes=$(wc -c < /dev/stdin)\n"
                '  printf \'secret-stdin-bytes=%s\\n\' "$bytes" >> "$GH_TRACE"\n'
                "fi\n",
                encoding="utf-8",
            )
            fake_gh.chmod(0o700)
            environment = os.environ.copy()
            environment["GH_TRACE"] = str(trace)
            environment["PATH"] = str(fake_bin) + os.pathsep + environment["PATH"]

            subprocess.run(
                [
                    "bash",
                    str(bundle / "upload.sh"),
                    "--apply",
                    "--repo",
                    "owner/repository",
                ],
                check=True,
                env=environment,
            )
            shell_trace = trace.read_text(encoding="utf-8")
            self.assertIn(
                "variable set WINDOWS_CODESIGN_CERTIFICATE_SHA256", shell_trace
            )
            self.assertIn("secret set WINDOWS_CODESIGN_PFX_BASE64", shell_trace)
            self.assertIn("secret set WINDOWS_CODESIGN_PFX_PASSWORD", shell_trace)
            self.assertNotIn("test-password", shell_trace)
            self.assertNotIn("test-pfx-bytes", shell_trace)

            if shutil.which("pwsh"):
                trace.unlink()
                subprocess.run(
                    [
                        "pwsh",
                        "-NoProfile",
                        "-File",
                        str(bundle / "Upload.ps1"),
                        "-Apply",
                        "-Organization",
                        "owner",
                        "-Repositories",
                        "nexus,remote-client",
                    ],
                    check=True,
                    env=environment,
                )
                powershell_trace = trace.read_text(encoding="utf-8")
                self.assertIn(
                    "variable set WINDOWS_CODESIGN_CERTIFICATE_SHA256", powershell_trace
                )
                self.assertIn(
                    "--org owner --repos nexus,remote-client --visibility selected",
                    powershell_trace,
                )
                self.assertIn(
                    "secret set WINDOWS_CODESIGN_PFX_BASE64", powershell_trace
                )
                self.assertNotIn("test-password", powershell_trace)
                self.assertNotIn("test-pfx-bytes", powershell_trace)

    def test_refuses_private_fields_and_overwriting_an_existing_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            identity, certificate, password = self.create_inputs(directory)
            identity.write_text('{"privateKey":"not-allowed"}', encoding="utf-8")
            with self.assertRaises(BUNDLE.BundleError):
                BUNDLE.main(
                    [
                        str(directory),
                        "--platform",
                        "windows",
                        "--distribution-trust",
                        "private-trust",
                        "--identity-file",
                        str(identity),
                        "--variable",
                        "WINDOWS_SIGNING_TRUST_MODE=private-trust",
                        "--secret",
                        f"WINDOWS_CODESIGN_PFX_PASSWORD={password}",
                    ]
                )

            identity, certificate, password = self.create_inputs(directory)
            bundle = self.create_bundle(directory)
            self.assertTrue(bundle.is_dir())
            with self.assertRaises(BUNDLE.BundleError):
                BUNDLE.main(
                    [
                        str(directory),
                        "--platform",
                        "windows",
                        "--distribution-trust",
                        "private-trust",
                        "--identity-file",
                        str(identity),
                        "--variable",
                        "WINDOWS_SIGNING_TRUST_MODE=private-trust",
                        "--secret-base64",
                        f"WINDOWS_CODESIGN_PFX_BASE64={certificate}",
                        "--secret",
                        f"WINDOWS_CODESIGN_PFX_PASSWORD={password}",
                    ]
                )

    def test_refuses_secret_like_variable_names(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            identity, _, password = self.create_inputs(directory)
            with self.assertRaises(BUNDLE.BundleError):
                BUNDLE.main(
                    [
                        str(directory),
                        "--platform",
                        "windows",
                        "--distribution-trust",
                        "private-trust",
                        "--identity-file",
                        str(identity),
                        "--variable",
                        "WINDOWS_CODESIGN_PFX_PASSWORD=not-a-variable",
                        "--secret",
                        f"TEST_SECRET={password}",
                    ]
                )


if __name__ == "__main__":
    unittest.main()
