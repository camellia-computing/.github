#!/usr/bin/env python3
"""Create and install the dedicated Policy Auditor App without persisting its key."""

from __future__ import annotations

import argparse
import html
import json
import secrets
import shutil
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from audit_repository_policies import (
    API_VERSION,
    EXPECTED_POLICY_AUDITOR_PERMISSIONS,
    load_config,
)


def policy_auditor_manifest(
    config: dict[str, Any],
    redirect_url: str,
    app_name: str | None = None,
) -> dict[str, Any]:
    governance = next(
        policy
        for policy in config["repositories"]
        if policy["logical_id"] == "governance"
    )
    homepage = f"https://github.com/{config['organization']}/{governance['name']}"
    return {
        "name": app_name or f"Policy Auditor {config['organization_id']}",
        "url": homepage,
        "hook_attributes": {
            "active": False,
            "url": homepage,
        },
        "redirect_url": redirect_url,
        "description": ("Read-only organization and repository policy drift auditor."),
        "public": False,
        "default_permissions": EXPECTED_POLICY_AUDITOR_PERMISSIONS,
        "default_events": [],
        "request_oauth_on_install": False,
    }


def run_checked(
    command: list[str],
    *,
    input_text: str | None = None,
    capture_output: bool = False,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        check=True,
        input=input_text,
        text=True,
        capture_output=capture_output,
    )


def open_browser(url: str) -> None:
    powershell = shutil.which("powershell.exe")
    if powershell:
        run_checked(
            [
                powershell,
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Start-Process -FilePath $args[0]",
                url,
            ]
        )
        return
    if not webbrowser.open(url, new=1):
        raise RuntimeError(f"could not open a browser; navigate to {url}")


class ManifestServer(ThreadingHTTPServer):
    manifest: dict[str, Any]
    organization: str
    registration_state: str
    result: dict[str, str] | None
    error: str | None


class ManifestHandler(BaseHTTPRequestHandler):
    server: ManifestServer

    def log_message(self, format: str, *args: object) -> None:
        return

    def send_html(self, status: int, body: str) -> None:
        content = (
            "<!doctype html><html lang='en'><meta charset='utf-8'>"
            "<title>Policy Auditor bootstrap</title>"
            "<body style='font-family:system-ui;max-width:48rem;margin:4rem auto'>"
            f"{body}</body></html>"
        ).encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(content)

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/":
            action = (
                "https://github.com/organizations/"
                f"{urllib.parse.quote(self.server.organization, safe='')}"
                "/settings/apps/new?"
                + urllib.parse.urlencode({"state": self.server.registration_state})
            )
            manifest = html.escape(
                json.dumps(self.server.manifest, separators=(",", ":")),
                quote=True,
            )
            self.send_html(
                200,
                "<h1>Register the read-only Policy Auditor</h1>"
                "<p>GitHub will show the derived permission set for owner "
                "confirmation.</p>"
                f"<form id='manifest' action='{html.escape(action, quote=True)}' "
                "method='post'>"
                f"<input type='hidden' name='manifest' value='{manifest}'>"
                "<button type='submit'>Continue to GitHub</button></form>"
                "<script>document.getElementById('manifest').submit()</script>",
            )
            return
        if parsed.path != "/callback":
            self.send_html(404, "<h1>Not found</h1>")
            return

        try:
            query = urllib.parse.parse_qs(parsed.query, strict_parsing=True)
        except ValueError:
            self.server.error = "GitHub App manifest callback query is invalid"
            self.send_html(400, "<h1>Callback validation failed</h1>")
            return
        state = query.get("state", [""])[0]
        code = query.get("code", [""])[0]
        if (
            not secrets.compare_digest(state, self.server.registration_state)
            or not code
        ):
            self.server.error = "GitHub App manifest callback validation failed"
            self.send_html(400, "<h1>Callback validation failed</h1>")
            return
        try:
            request = urllib.request.Request(
                "https://api.github.com/app-manifests/"
                f"{urllib.parse.quote(code, safe='')}/conversions",
                headers={
                    "Accept": "application/vnd.github+json",
                    "User-Agent": "policy-auditor-bootstrap",
                    "X-GitHub-Api-Version": API_VERSION,
                },
                data=b"",
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=30) as response:
                converted = json.loads(response.read())
            client_id = converted.get("client_id")
            private_key = converted.get("pem")
            slug = converted.get("slug")
            if not all(
                isinstance(value, str) and value
                for value in (client_id, private_key, slug)
            ):
                raise RuntimeError("manifest conversion omitted App credentials")
            self.server.result = {
                "client_id": client_id,
                "private_key": private_key,
                "slug": slug,
            }
            self.send_html(
                200,
                "<h1>App registered</h1>"
                "<p>The private key is being transferred directly to the "
                "repository secret. Return to the terminal to continue.</p>",
            )
        except (OSError, RuntimeError, ValueError, urllib.error.HTTPError) as error:
            self.server.error = (
                f"GitHub App manifest conversion failed: {type(error).__name__}"
            )
            self.send_html(502, "<h1>Manifest conversion failed</h1>")


def receive_manifest_conversion(
    config: dict[str, Any],
    app_name: str | None,
    timeout_seconds: int,
    *,
    launch_browser: bool,
) -> dict[str, str]:
    server = ManifestServer(("127.0.0.1", 0), ManifestHandler)
    server.organization = config["organization"]
    server.registration_state = secrets.token_urlsafe(32)
    server.result = None
    server.error = None
    redirect_url = f"http://127.0.0.1:{server.server_port}/callback"
    server.manifest = policy_auditor_manifest(config, redirect_url, app_name)

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    registration_url = f"http://127.0.0.1:{server.server_port}/"
    print(f"Open the local registration bridge: {registration_url}")
    if launch_browser:
        open_browser(registration_url)
    deadline = time.monotonic() + timeout_seconds
    try:
        while (
            server.result is None
            and server.error is None
            and time.monotonic() < deadline
        ):
            time.sleep(0.2)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    if server.error:
        raise RuntimeError(server.error)
    if server.result is None:
        raise TimeoutError("GitHub App manifest registration timed out")
    return server.result


def governance_repository(config: dict[str, Any]) -> str:
    governance = next(
        policy
        for policy in config["repositories"]
        if policy["logical_id"] == "governance"
    )
    return f"{config['organization']}/{governance['name']}"


def configure_repository_credentials(
    config: dict[str, Any],
    converted: dict[str, str],
) -> None:
    repository = governance_repository(config)
    for name, value in (
        ("POLICY_AUDIT_APP_CLIENT_ID", converted["client_id"]),
        ("POLICY_AUDIT_APP_SLUG", converted["slug"]),
    ):
        run_checked(
            [
                "gh",
                "variable",
                "set",
                name,
                "--repo",
                repository,
                "--body",
                value,
            ]
        )
    run_checked(
        [
            "gh",
            "secret",
            "set",
            "POLICY_AUDIT_APP_PRIVATE_KEY",
            "--repo",
            repository,
        ],
        input_text=converted["private_key"],
    )


def installed_app(
    organization: str,
    slug: str,
) -> dict[str, Any] | None:
    installations: list[Any] = []
    total_count: int | None = None
    page = 1
    while total_count is None or len(installations) < total_count:
        response = run_checked(
            [
                "gh",
                "api",
                f"orgs/{organization}/installations?per_page=100&page={page}",
            ],
            capture_output=True,
        )
        payload = json.loads(response.stdout)
        page_items = payload.get("installations")
        page_total = payload.get("total_count")
        if (
            not isinstance(page_items, list)
            or not isinstance(page_total, int)
            or isinstance(page_total, bool)
            or page_total < 0
            or (total_count is not None and page_total != total_count)
            or (not page_items and len(installations) < page_total)
        ):
            raise RuntimeError("installation inventory pagination is invalid")
        total_count = page_total
        installations.extend(page_items)
        page += 1
    if len(installations) != total_count:
        raise RuntimeError("installation inventory item count is invalid")
    matches = [
        item
        for item in installations
        if isinstance(item, dict) and item.get("app_slug") == slug
    ]
    if len(matches) > 1:
        raise RuntimeError("multiple installations use the new App slug")
    return matches[0] if matches else None


def wait_for_installation(
    config: dict[str, Any],
    slug: str,
    timeout_seconds: int,
) -> dict[str, Any]:
    install_url = f"https://github.com/apps/{slug}/installations/new"
    print("Confirm an all-repositories organization installation in the browser.")
    open_browser(install_url)
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        installation = installed_app(config["organization"], slug)
        if installation is not None:
            return installation
        time.sleep(2)
    raise TimeoutError(f"GitHub App installation timed out; open {install_url}")


def verify_installation(
    config: dict[str, Any],
    slug: str,
    installation: dict[str, Any],
) -> None:
    expected = {
        "app_slug": slug,
        "events": [],
        "permissions": EXPECTED_POLICY_AUDITOR_PERMISSIONS,
        "repository_selection": "all",
        "suspended_at": None,
        "target_id": config["organization_id"],
        "target_type": "Organization",
    }
    actual = {name: installation.get(name) for name in expected}
    if actual != expected:
        raise RuntimeError(
            "installed App differs from the reviewed all-repositories, read-only policy"
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("config/repository-policies.json"),
    )
    parser.add_argument("--app-name")
    parser.add_argument(
        "--timeout-seconds",
        type=int,
        default=600,
    )
    parser.add_argument(
        "--no-open",
        action="store_true",
        help="Print the local bridge URL instead of opening a browser.",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Create the App and update the governance repository credentials.",
    )
    args = parser.parse_args()
    if not args.apply:
        parser.error("--apply is required because this creates an external identity")
    if not 60 <= args.timeout_seconds <= 3600:
        parser.error("--timeout-seconds must be between 60 and 3600")
    if not shutil.which("gh"):
        parser.error("gh is required")

    config = load_config(args.config)
    repository = governance_repository(config)
    run_checked(["gh", "auth", "status"])
    configured_names: list[str] = []
    for name in ("POLICY_AUDIT_APP_CLIENT_ID", "POLICY_AUDIT_APP_SLUG"):
        existing = subprocess.run(
            ["gh", "variable", "get", name, "--repo", repository],
            check=False,
            text=True,
            capture_output=True,
        )
        if existing.returncode == 0 and existing.stdout.strip():
            configured_names.append(name)
    secret_inventory = run_checked(
        ["gh", "secret", "list", "--repo", repository, "--json", "name"],
        capture_output=True,
    )
    if any(
        item.get("name") == "POLICY_AUDIT_APP_PRIVATE_KEY"
        for item in json.loads(secret_inventory.stdout)
        if isinstance(item, dict)
    ):
        configured_names.append("POLICY_AUDIT_APP_PRIVATE_KEY")
    if configured_names:
        raise RuntimeError(
            "Policy Auditor credentials already exist; review rotation manually: "
            + ", ".join(sorted(configured_names))
        )

    converted = receive_manifest_conversion(
        config,
        args.app_name,
        args.timeout_seconds,
        launch_browser=not args.no_open,
    )
    configure_repository_credentials(config, converted)
    private_key = converted.pop("private_key")
    del private_key
    installation = wait_for_installation(
        config,
        converted["slug"],
        args.timeout_seconds,
    )
    verify_installation(config, converted["slug"], installation)
    print(
        "Policy Auditor App configured with exact read-only permissions and "
        "all-repositories access."
    )
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuntimeError, TimeoutError, ValueError) as error:
        print(f"bootstrap: {error}", file=sys.stderr)
        sys.exit(1)
