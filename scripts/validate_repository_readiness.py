#!/usr/bin/env python3
"""Validate repository-only release readiness without claiming deployment."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
SHA256 = re.compile(r"^[0-9a-f]{64}$")
GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
IMAGE = re.compile(r"^[a-z0-9./_-]+@sha256:[0-9a-f]{64}$")
PLACEHOLDER = re.compile(r"\b(TBD|TODO|UNKNOWN|UNRESOLVED|RECALCULATE|NOT_BUILT|NOT_PUBLISHED)\b")

REQUIRED = [
    "README.md",
    "REPOSITORY_PROFILE.md",
    "SECURITY.md",
    ".github/CODEOWNERS",
    "docs/BACKUP_RESTORE_ROLLBACK.md",
    "docs/UPGRADE.md",
    "codestra/release/runtime-image.lock.json",
    "codestra/release/config-bundle.manifest.json",
    "scripts/build_config_bundle.py",
    "requirements-validation.txt",
]


def fail(message: str) -> None:
    raise SystemExit(f"ERROR: {message}")


def load(relative: str) -> dict:
    try:
        value = json.loads((ROOT / relative).read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        fail(f"cannot load {relative}: {exc}")
    if not isinstance(value, dict):
        fail(f"{relative} must be a JSON object")
    return value


def main() -> None:
    missing = [path for path in REQUIRED if not (ROOT / path).is_file()]
    if missing:
        fail(f"missing readiness files: {missing}")

    lock = load("codestra/release/runtime-image.lock.json")
    if lock.get("artifactModel") != "verified-upstream-image-plus-signed-config":
        fail("Alertmanager must use release Model B")
    if not IMAGE.fullmatch(str(lock.get("image", ""))):
        fail("runtime image must be an exact sha256 identity")
    if not GIT_SHA.fullmatch(str(lock.get("upstreamTagCommit", ""))):
        fail("upstream tag commit must be an exact Git SHA")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", str(lock.get("linuxAmd64Manifest", ""))):
        fail("linux/amd64 platform manifest must be digest pinned")
    if lock.get("productionActivation") is not False:
        fail("repository source must not activate production")
    signature = lock.get("upstreamSignature", {})
    if signature != {
        "available": False,
        "verification": "NO_SIGSTORE_SIGNATURE_PUBLISHED",
    }:
        fail("upstream signature availability must be recorded exactly")

    manifest = load("codestra/release/config-bundle.manifest.json")
    if manifest.get("component") != "alertmanager":
        fail("configuration manifest has the wrong component")
    if manifest.get("productionActivation") is not False:
        fail("configuration manifest must not activate production")
    files = manifest.get("files")
    governed_files = {
        "codestra/alertmanager.yml",
        "codestra/alert-routing-policy.json",
        "codestra/middleware-alert-contract.json",
        "codestra/api/service-contract.v1.json",
        "codestra/web-config.yml",
    }
    if not isinstance(files, dict) or set(files) != governed_files:
        fail("configuration manifest must contain exactly the five governed files")
    for relative, expected in files.items():
        path = ROOT / relative
        if not path.is_file() or not SHA256.fullmatch(str(expected)):
            fail(f"invalid configuration manifest entry: {relative}")
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != expected:
            fail(f"configuration checksum mismatch for {relative}")

    compose = (ROOT / "codestra/compose.yaml").read_text(encoding="utf-8")
    if re.search(r"(?m)^\s*ports\s*:", compose):
        fail("Alertmanager compose must not publish a host port")
    image_lines = re.findall(r"(?m)^\s+image:\s*(\S+)\s*$", compose)
    if image_lines != [lock["image"]]:
        fail("Alertmanager compose image must exactly match the immutable runtime lock")
    web_config = yaml.safe_load(
        (ROOT / "codestra/web-config.yml").read_text(encoding="utf-8")
    )
    tls = web_config.get("tls_server_config", {})
    if tls != {
        "cert_file": "/run/secrets/alertmanager-server-cert",
        "key_file": "/run/secrets/alertmanager-server-key",
        "client_ca_file": "/run/secrets/alertmanager-client-ca",
        "client_auth_type": "RequireAndVerifyClientCert",
        "min_version": "TLS12",
    }:
        fail("Alertmanager native listener must enforce the exact mTLS policy")
    for required in (
        "--web.config.file=/etc/alertmanager/web-config.yml",
        "target: alertmanager-server-cert",
        "target: alertmanager-server-key",
        "target: alertmanager-client-ca",
    ):
        if required not in compose:
            fail(f"Alertmanager compose is missing mTLS control: {required}")

    config = (ROOT / "codestra/alertmanager.yml").read_text(encoding="utf-8")
    for receiver in (
        "email_configs",
        "slack_configs",
        "pagerduty_configs",
        "opsgenie_configs",
        "telegram_configs",
        "sns_configs",
    ):
        if re.search(rf"(?m)^\s*{receiver}\s*:", config):
            fail(f"direct notification receiver is forbidden: {receiver}")

    controlled = [ROOT / path for path in REQUIRED] + [
        ROOT / "codestra/release/config-bundle.manifest.json"
    ]
    for path in controlled:
        if PLACEHOLDER.search(path.read_text(encoding="utf-8")):
            fail(f"placeholder in readiness source: {path.relative_to(ROOT)}")

    for workflow in (ROOT / ".github/workflows").glob("*.yml"):
        text = workflow.read_text(encoding="utf-8")
        for reference in re.findall(r"(?m)^\s*(?:-\s*)?uses:\s*([^\s#]+)", text):
            if reference.startswith("./"):
                continue
            if not re.fullmatch(r"[^@\s]+@[0-9a-f]{40}", reference):
                fail(f"mutable action reference in {workflow.relative_to(ROOT)}: {reference}")

    release_caller = yaml.safe_load(
        (ROOT / ".github/workflows/release-config-bundle.yml").read_text(encoding="utf-8")
    )
    release_job = release_caller.get("jobs", {}).get("release", {})
    expected_authority = (
        "appolon1908-hue/Codestra-Telemetry/.github/workflows/"
        "reusable-release-config-bundle.yml@"
        "777292781faeca9348d0e2ecdce6ac3f50c91d93"
    )
    if release_job.get("uses") != expected_authority:
        fail("release caller must pin the canonical Telemetry workflow authority")
    if release_job.get("with", {}).get("component_id") != "alertmanager":
        fail("release caller component identity mismatch")

    print("ALERTMANAGER_REPOSITORY_READINESS_SOURCE=PASS")
    print("PRODUCTION_ACTIVATION=NO")


if __name__ == "__main__":
    main()
