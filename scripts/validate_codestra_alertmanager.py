#!/usr/bin/env python3
"""Fail-closed source validation for Codestra Alertmanager policy.

This validator intentionally uses only the Python standard library so the
repository can enforce the control-plane contract without adding a CI-only
package dependency.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "codestra" / "alert-routing-policy.json"
CONTRACT = ROOT / "codestra" / "middleware-alert-contract.json"
CONFIG = ROOT / "codestra" / "alertmanager.yml"

ALLOWED_SEVERITIES = ["critical", "high", "warning", "informational"]
FORBIDDEN_RECEIVER_KEYS = [
    "email_configs",
    "slack_configs",
    "pagerduty_configs",
    "opsgenie_configs",
    "wechat_configs",
    "victorops_configs",
    "sns_configs",
    "msteams_configs",
    "msteamsv2_configs",
    "discord_configs",
    "webex_configs",
    "telegram_configs",
]
FORBIDDEN_SECRET_PATTERNS = [
    re.compile(r"(?i)(api[_-]?key|client[_-]?secret|password|token)\s*[:=]\s*['\"]?[A-Za-z0-9/+_.-]{16,}"),
    re.compile(r"https://hooks\.slack\.com/services/"),
]


def fail(message: str) -> None:
    raise SystemExit(f"ERROR: {message}")


def load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        fail(f"missing required file: {path.relative_to(ROOT)}")
    except json.JSONDecodeError as exc:
        fail(f"invalid JSON in {path.relative_to(ROOT)}: {exc}")


def main() -> None:
    policy = load_json(POLICY)
    contract = load_json(CONTRACT)
    try:
        config = CONFIG.read_text(encoding="utf-8")
    except FileNotFoundError:
        fail("missing codestra/alertmanager.yml")

    if policy.get("canonical_host") != "aler.codestra.media":
        fail("canonical Alertmanager host must be aler.codestra.media")
    if policy.get("exposure") != "private_service_with_protected_dns_name":
        fail("Alertmanager must remain documented as network-restricted/private")
    if policy.get("runtime_status") != "SOURCE_PREPARED_NOT_DEPLOYED":
        fail("source policy must not claim runtime deployment")

    severities = policy.get("severity", {})
    if list(severities) != ALLOWED_SEVERITIES:
        fail(f"severity order must be exactly {ALLOWED_SEVERITIES}")

    required_labels = set(policy.get("required_labels", []))
    expected_labels = {
        "alertname",
        "severity",
        "environment",
        "service",
        "codestra_business",
        "owner",
    }
    if not expected_labels.issubset(required_labels):
        fail(f"missing required labels: {sorted(expected_labels - required_labels)}")

    required_annotations = set(policy.get("required_annotations", []))
    expected_annotations = {"summary", "description", "runbook_url"}
    if not expected_annotations.issubset(required_annotations):
        fail(
            "missing required annotations: "
            + str(sorted(expected_annotations - required_annotations))
        )

    safety = policy.get("safety", {})
    forbidden_true = [name for name, enabled in safety.items() if name.startswith("direct_") and enabled]
    if forbidden_true:
        fail(f"direct notification/write paths must stay disabled: {forbidden_true}")
    if safety.get("secrets_in_git") is not False:
        fail("secrets_in_git must be false")
    if safety.get("native_service_public_exposure") is not False:
        fail("native_service_public_exposure must be false")

    if contract.get("status") != "SOURCE_AUTHORITY_ACCEPTED_RUNTIME_ENDPOINT_NOT_PROVEN":
        fail("Middleware contract must not claim a live/proven endpoint")
    authority = contract.get("middleware_source_authority", {})
    if authority != {
        "repository": "appolon1908-hue/Middleware-",
        "protected_branch": "main",
        "protected_merge_sha": "65b8e511a412c4ba922876e906f95b9f2e4277a1",
        "canonical_path": "/v1/integrations/alertmanager/events",
    }:
        fail("Middleware source authority must match its accepted protected merge")
    if "forbid_automatic_business_system_mutation" not in contract.get(
        "middleware_responsibilities", []
    ):
        fail("Middleware contract must forbid automatic business-system mutation")
    transport = contract.get("transport", {})
    if transport.get("url_source") != "/run/secrets/middleware-alert-webhook-url":
        fail("Middleware webhook URL must come from the runtime secret file")
    if transport.get("authorization_source") != "/run/secrets/middleware-alert-webhook-token":
        fail("Middleware webhook bearer token must come from the runtime secret file")

    for key in FORBIDDEN_RECEIVER_KEYS:
        if re.search(rf"(?m)^\s*{re.escape(key)}\s*:", config):
            fail(f"direct Alertmanager receiver type is forbidden: {key}")

    if config.count("webhook_configs:") != 6:
        fail("expected exactly six Middleware-only webhook receiver definitions")
    if config.count("url_file: /run/secrets/middleware-alert-webhook-url") != 6:
        fail("every receiver must load the Middleware webhook URL from a secret file")
    if config.count("credentials_file: /run/secrets/middleware-alert-webhook-token") != 6:
        fail("every receiver must load its bearer token from a secret file")
    if config.count("send_resolved: true") != 6:
        fail("every Middleware receiver must send resolved notifications")

    for severity in ALLOWED_SEVERITIES:
        if f'severity = "{severity}"' not in config:
            fail(f"missing route for severity {severity}")

    required_config_fragments = [
        'alertname = "CodestraWatchdog"',
        'alertname = "CodestraDeploymentInProgress"',
        'severity =~ "high|warning|informational"',
        "codestra_business",
        "run/secrets/middleware-alert-webhook-url",
        "run/secrets/middleware-alert-webhook-token",
    ]
    for fragment in required_config_fragments:
        if fragment not in config:
            fail(f"missing required Alertmanager configuration fragment: {fragment}")

    codestra_files = [
        POLICY,
        CONTRACT,
        CONFIG,
        ROOT / "codestra" / "docs" / "OPERATING-MODEL.md",
    ]
    for path in codestra_files:
        text = path.read_text(encoding="utf-8")
        for pattern in FORBIDDEN_SECRET_PATTERNS:
            if pattern.search(text):
                fail(f"secret-like value found in {path.relative_to(ROOT)}")

    # Hostname authority: a service may document its own canonical DNS name, but
    # must not carry stale alternate Alertmanager hostnames.
    all_text = "\n".join(path.read_text(encoding="utf-8") for path in codestra_files)
    stale_alert_hosts = re.findall(r"\b[a-z0-9.-]*alert[a-z0-9.-]*\.codestra\.media\b", all_text, flags=re.I)
    bad_hosts = sorted({host for host in stale_alert_hosts if host.lower() != "aler.codestra.media"})
    if bad_hosts:
        fail(f"stale/alternate Alertmanager hostname(s): {bad_hosts}")

    print("Codestra Alertmanager routing control-plane validation: PASS")


if __name__ == "__main__":
    main()
