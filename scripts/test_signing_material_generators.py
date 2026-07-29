#!/usr/bin/env python3
"""End-to-end regression tests for local signing-material generators."""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


SCRIPTS = Path(__file__).parent
P12_PASSWORD = "test-only-p12-password"
GPG_PASSPHRASE = "test-only-gpg-passphrase"
ANDROID_PASSWORD = "test-only-android-password"


class SigningMaterialGeneratorTests(unittest.TestCase):
    maxDiff = None

    def run_script(self, arguments: list[str], user_input: str) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            ["bash", *arguments],
            input=user_input,
            text=True,
            capture_output=True,
            check=False,
        )
        if result.returncode:
            self.fail(
                "generator failed with exit code "
                f"{result.returncode}:\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
            )
        return result

    def assert_bundle(
        self,
        output: Path,
        platform: str,
        trust: str,
        variables: set[str],
        secrets: set[str],
        forbidden_value: str,
    ) -> None:
        bundle = output / "github-actions"
        metadata = json.loads((bundle / "metadata.json").read_text(encoding="utf-8"))
        self.assertEqual(metadata["platform"], platform)
        self.assertEqual(metadata["distribution_trust"], trust)
        self.assertEqual(
            {item["name"] for item in metadata["github_actions"]["variables"]},
            variables,
        )
        self.assertEqual(set(metadata["github_actions"]["secrets"]), secrets)
        self.assertEqual({path.name for path in (bundle / "secrets").iterdir()}, secrets)
        for path in (bundle / "README.md", bundle / "metadata.json", bundle / "variables.env"):
            self.assertNotIn(forbidden_value, path.read_text(encoding="utf-8"))
        self.assertFalse((output / ".github-actions-input").exists())

    @unittest.skipUnless(shutil.which("openssl"), "openssl is required")
    def test_macos_private_identity_generator_creates_a_complete_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "macos"
            self.run_script(
                [str(SCRIPTS / "new-camellia-macos-private-code-signing-identity.sh"), str(output)],
                P12_PASSWORD + "\n",
            )
            self.assertTrue((output / "camellia-private-code-signing-leaf.p12").is_file())
            self.assert_bundle(
                output,
                "macos",
                "private-trust",
                {
                    "APPLE_SIGNING_CERTIFICATE_SHA256",
                    "APPLE_SIGNING_IDENTITY",
                    "APPLE_SIGNING_TRUST_MODE",
                },
                {"APPLE_CERTIFICATE", "APPLE_CERTIFICATE_PASSWORD"},
                P12_PASSWORD,
            )

    @unittest.skipUnless(shutil.which("gpg"), "gpg is required")
    def test_linux_openpgp_generator_creates_a_complete_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "linux"
            self.run_script(
                [
                    str(SCRIPTS / "new-camellia-linux-openpgp-key.sh"),
                    str(output),
                    "Camellia Test Release <release@example.invalid>",
                ],
                GPG_PASSPHRASE + "\n",
            )
            self.assertTrue((output / "camellia-linux-release-private.asc").is_file())
            self.assert_bundle(
                output,
                "linux",
                "platform-key",
                {"LINUX_GPG_FINGERPRINT"},
                {"LINUX_GPG_PRIVATE_KEY", "LINUX_GPG_PASSPHRASE"},
                GPG_PASSPHRASE,
            )

    @unittest.skipUnless(shutil.which("keytool"), "keytool is required")
    def test_android_generator_creates_a_complete_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "android"
            self.run_script(
                [str(SCRIPTS / "new-camellia-android-release-keystore.sh"), str(output)],
                ANDROID_PASSWORD + "\n" + ANDROID_PASSWORD + "\n",
            )
            self.assertTrue((output / "camellia-android-release.keystore").is_file())
            self.assert_bundle(
                output,
                "android",
                "platform-key",
                {"ANDROID_SIGNING_CERTIFICATE_SHA256"},
                {
                    "ANDROID_ALIAS",
                    "ANDROID_KEY_PASSWORD",
                    "ANDROID_KEY_STORE_PASSWORD",
                    "ANDROID_SIGNING_KEY",
                },
                ANDROID_PASSWORD,
            )

    @unittest.skipUnless(shutil.which("openssl"), "openssl is required")
    def test_apple_preparation_bundles_existing_p12_and_ios_profile(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            generated = root / "generated"
            self.run_script(
                [str(SCRIPTS / "new-camellia-macos-private-code-signing-identity.sh"), str(generated)],
                P12_PASSWORD + "\n",
            )
            p12 = generated / "camellia-private-code-signing-leaf.p12"

            macos_output = root / "prepared-macos"
            self.run_script(
                [
                    str(SCRIPTS / "prepare-camellia-apple-signing-bundle.sh"),
                    "macos",
                    str(macos_output),
                    str(p12),
                    "Camellia Computing Private Code Signing",
                    "private-trust",
                ],
                P12_PASSWORD + "\n",
            )
            self.assert_bundle(
                macos_output,
                "macos",
                "private-trust",
                {
                    "APPLE_SIGNING_CERTIFICATE_SHA256",
                    "APPLE_SIGNING_IDENTITY",
                    "APPLE_SIGNING_TRUST_MODE",
                },
                {"APPLE_CERTIFICATE", "APPLE_CERTIFICATE_PASSWORD"},
                P12_PASSWORD,
            )

            profile = root / "test.mobileprovision"
            profile.write_bytes(b"test-only-profile")
            ios_output = root / "prepared-ios"
            self.run_script(
                [
                    str(SCRIPTS / "prepare-camellia-apple-signing-bundle.sh"),
                    "ios",
                    str(ios_output),
                    str(p12),
                    str(profile),
                    "Apple Distribution: Camellia Computing (ABCDE12345)",
                    "ABCDE12345",
                    "release-testing",
                ],
                P12_PASSWORD + "\n",
            )
            self.assert_bundle(
                ios_output,
                "ios",
                "platform-key",
                {
                    "IOS_EXPORT_METHOD",
                    "IOS_SIGNING_CERTIFICATE_SHA256",
                    "IOS_SIGNING_IDENTITY",
                    "IOS_TEAM_ID",
                },
                {
                    "IOS_CERTIFICATE_BASE64",
                    "IOS_CERTIFICATE_PASSWORD",
                    "IOS_PROVISIONING_PROFILE_BASE64",
                },
                P12_PASSWORD,
            )


if __name__ == "__main__":
    unittest.main()
