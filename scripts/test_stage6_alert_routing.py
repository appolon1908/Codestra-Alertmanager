#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MATRIX = ROOT / "codestra/stage6-alert-routing-tests.v1.json"
CONFIG = ROOT / "codestra/alertmanager.yml"
EXPECTED_CASES = {
    "authentication-failures": ("CodestraAuthenticationFailuresSpike", "warning", "middleware-warning"),
    "external-provider-failures": ("CodestraExternalProviderFailures", "critical", "middleware-critical"),
    "queue-backlog": ("CodestraQueueDepthHigh", "warning", "middleware-warning"),
    "webhook-retries": ("CodestraWebhookRetriesElevated", "warning", "middleware-warning"),
}
REQUIRED_LABELS = {"alertname", "severity", "codestra_business", "service", "environment", "owner"}
LABEL_NAME = re.compile(r"[a-zA-Z_][a-zA-Z0-9_]*")
LABEL_VALUE = re.compile(r"[A-Za-z0-9._:/-]+")


def fail(message: str) -> None:
    raise SystemExit(f"ALERT_ROUTING_CERTIFICATION=FAIL {message}")


def load_matrix() -> dict:
    try:
        value = json.loads(MATRIX.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"invalid matrix: {exc}")
    if not isinstance(value, dict):
        fail("matrix root is not an object")
    return value


def validate_matrix(value: dict) -> list[dict]:
    if value.get("schema_version") != "1.0":
        fail("schema_version must be 1.0")
    if value.get("suite_id") != "codestra-stage6-alert-routing-certification-v1":
        fail("suite_id is invalid")
    if value.get("status") != "SOURCE_TESTS_ONLY_NOT_DEPLOYED":
        fail("matrix must not claim runtime deployment")
    if value.get("delivery_performed") is not False or value.get("production_authorized") is not False:
        fail("source tests cannot authorize delivery or production")
    cases = value.get("cases")
    if not isinstance(cases, list) or len(cases) != len(EXPECTED_CASES):
        fail("case count is invalid")
    seen: set[str] = set()
    for case in cases:
        if not isinstance(case, dict):
            fail("case is not an object")
        case_id = case.get("id")
        if case_id in seen or case_id not in EXPECTED_CASES:
            fail(f"unknown or duplicate case: {case_id}")
        seen.add(case_id)
        labels = case.get("labels")
        if not isinstance(labels, dict) or not REQUIRED_LABELS.issubset(labels):
            fail(f"required labels missing for {case_id}")
        if any(not LABEL_NAME.fullmatch(str(name)) for name in labels):
            fail(f"invalid label name for {case_id}")
        if any(not isinstance(raw, str) or not LABEL_VALUE.fullmatch(raw) for raw in labels.values()):
            fail(f"invalid label value for {case_id}")
        expected_alert, expected_severity, expected_receiver = EXPECTED_CASES[case_id]
        if labels["alertname"] != expected_alert or labels["severity"] != expected_severity:
            fail(f"alert identity mismatch for {case_id}")
        if case.get("expected_receiver") != expected_receiver:
            fail(f"receiver mismatch for {case_id}")
        if labels["environment"] != "staging" or labels["codestra_business"] != "codestra":
            fail(f"non-staging or non-Codestra test labels for {case_id}")
    if seen != set(EXPECTED_CASES):
        fail("required cases are incomplete")
    return cases


def execute(amtool: Path, cases: list[dict]) -> None:
    if not amtool.is_file():
        fail(f"amtool not found: {amtool}")
    for case in cases:
        receiver = case["expected_receiver"]
        labels = case["labels"]
        command = [
            str(amtool),
            "--enable-feature=utf8-strict-mode",
            "config",
            "routes",
            "test",
            f"--config.file={CONFIG}",
            f"--verify.receivers={receiver}",
            *[f"{name}={labels[name]}" for name in sorted(labels)],
        ]
        result = subprocess.run(command, check=False, text=True, capture_output=True)
        if result.returncode != 0:
            fail(f"{case['id']} did not route to {receiver}: {result.stdout.strip()} {result.stderr.strip()}")
        if result.stdout.strip().splitlines()[-1:] != [receiver]:
            fail(f"{case['id']} returned unexpected receiver output")
        print(f"ROUTE_CASE={case['id']} RECEIVER={receiver} PASS")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--amtool", type=Path)
    args = parser.parse_args()
    cases = validate_matrix(load_matrix())
    if args.amtool is not None:
        execute(args.amtool, cases)
    print("ALERT_ROUTING_CERTIFICATION=PASS")
    print("DELIVERY_PERFORMED=NO")
    print("PRODUCTION_AUTHORIZED=NO")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BrokenPipeError:
        raise SystemExit(1)
