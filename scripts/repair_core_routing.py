#!/usr/bin/env python3
"""Prepare an idempotent routing repair for the existing core deployment.

This is a compatibility repair, not a replacement for the canonical release.
It does not change credentials, delivery URLs, authentication, or service state.
"""
from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path

import yaml

FALLBACK = "unclassified-operator-review"
WARNING_MATCHERS = ['severity="warning"', 'environment="production"']


def repair(document: dict) -> dict:
    result = copy.deepcopy(document)
    route = result["route"]
    receivers = {item["name"]: item for item in result["receivers"]}
    required = {"fail-closed-unrouted", "approved-secondary-receiver"}
    if not required.issubset(receivers):
        raise ValueError("not the supported core receiver configuration")
    if route["receiver"] not in {"fail-closed-unrouted", FALLBACK}:
        raise ValueError("unexpected default receiver")
    for receiver in result["receivers"]:
        if set(receiver) != {"name", "webhook_configs"}:
            raise ValueError("only existing webhook receivers are supported")
        for webhook in receiver["webhook_configs"]:
            if "url_file" not in webhook or "url" in webhook:
                raise ValueError("receiver URLs must remain file references")
            authorization = webhook.get("http_config", {}).get("authorization", {})
            if not authorization.get("credentials_file"):
                raise ValueError("authenticated webhook file reference required")
    routes = route.setdefault("routes", [])
    warning = [item for item in routes if set(item.get("matchers", [])) == set(WARNING_MATCHERS)]
    if len(warning) > 1:
        raise ValueError("ambiguous production warning routes")
    if warning and warning[0]["receiver"] != "approved-secondary-receiver":
        raise ValueError("existing production warning route differs")
    if not warning:
        routes.append({
            "matchers": WARNING_MATCHERS,
            "receiver": "approved-secondary-receiver",
            "repeat_interval": "2h",
        })
    fallback = {
        "name": FALLBACK,
        "webhook_configs": copy.deepcopy(
            receivers["fail-closed-unrouted"]["webhook_configs"]
            + receivers["approved-secondary-receiver"]["webhook_configs"]
        ),
    }
    if FALLBACK in receivers and receivers[FALLBACK] != fallback:
        raise ValueError("existing fallback differs; inspect before changing")
    if FALLBACK not in receivers:
        result["receivers"].append(fallback)
    # Unknown/malformed alert metadata remains in quarantine and is also
    # visible in the existing secondary operator queue. Never page it as primary.
    route["receiver"] = FALLBACK
    for label in ["codestra_business", "severity"]:
        if label not in route["group_by"]:
            route["group_by"].append(label)
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.input.resolve() == args.output.resolve() or args.output.exists():
        parser.error("output must be a new candidate file")
    candidate = repair(yaml.safe_load(args.input.read_text()))
    with args.output.open("x", encoding="utf-8") as stream:
        yaml.safe_dump(candidate, stream, sort_keys=False)
    print(json.dumps({"candidate_written": True, "runtime_reloaded": False}))


if __name__ == "__main__":
    main()
