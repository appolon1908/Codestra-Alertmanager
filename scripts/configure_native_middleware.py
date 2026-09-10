#!/usr/bin/env python3
"""Prepare the opt-in native Middleware transport; never edit a running service."""
from __future__ import annotations

import argparse
import copy
from pathlib import Path
from urllib.parse import urlsplit

import yaml

RECEIVERS = {
    "middleware-default", "middleware-heartbeat", "middleware-critical",
    "middleware-high", "middleware-warning", "middleware-informational",
}
SECRET_ROOT = "/run/secrets/"


def configure(source: dict, token_url: str) -> dict:
    url = urlsplit(token_url)
    if (
        url.scheme != "https" or not url.hostname or url.username or url.password
        or url.query or url.fragment
        or not url.path.endswith("/protocol/openid-connect/token")
    ):
        raise ValueError("token URL must be an HTTPS Keycloak token endpoint without credentials")
    result = copy.deepcopy(source)
    receivers = result.get("receivers", [])
    if len(receivers) != 6 or {r.get("name") for r in receivers} != RECEIVERS:
        raise ValueError("expected the six principal Middleware receivers")
    for receiver in receivers:
        if set(receiver) != {"name", "webhook_configs"}:
            raise ValueError("only native Middleware webhooks are supported")
        webhooks = receiver["webhook_configs"]
        if len(webhooks) != 1:
            raise ValueError("each receiver must have exactly one webhook")
        webhook = webhooks[0]
        if (
            webhook.get("url_file") != SECRET_ROOT + "middleware-alert-webhook-url"
            or "url" in webhook or webhook.get("send_resolved") is not True
            or not 1 <= webhook.get("max_alerts", 0) <= 100
        ):
            raise ValueError("unexpected URL, resolution policy or alert batch limit")
        tls = {
            "ca_file": SECRET_ROOT + "middleware-alert-trust-bundle",
            "cert_file": SECRET_ROOT + "alertmanager-middleware-client-cert",
            "key_file": SECRET_ROOT + "alertmanager-middleware-client-key",
            "min_version": "TLS12", "insecure_skip_verify": False,
        }
        desired = {
            "oauth2": {
                "client_id": "alertmanager-service",
                "client_secret_file": SECRET_ROOT + "alertmanager-oidc-client-secret",
                "token_url": token_url,
                "scopes": ["observability.alerts.write"],
                "tls_config": copy.deepcopy(tls),
            },
            "tls_config": tls,
            "http_headers": {
                "X-Alertmanager-Native-Webhook": {"values": ["v4"]},
                "X-Tenant-ID": {"values": ["codestra-platform"]},
                "X-Source-Deployment": {
                    "files": [SECRET_ROOT + "alertmanager-source-deployment"],
                },
            },
        }
        legacy = {"authorization": {
            "type": "Bearer",
            "credentials_file": SECRET_ROOT + "middleware-alert-webhook-token",
        }}
        if webhook.get("http_config") not in (legacy, desired):
            raise ValueError("unrecognized existing authentication; inspect before migration")
        webhook["http_config"] = desired
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--token-url", required=True)
    args = parser.parse_args()
    if args.input.resolve() == args.output.resolve():
        parser.error("output must be a separate candidate file")
    candidate = configure(yaml.safe_load(args.input.read_text()), args.token_url)
    with args.output.open("x", encoding="utf-8") as handle:
        yaml.safe_dump(candidate, handle, sort_keys=False)
    print("Candidate written; native validation and accepted release are still required.")


if __name__ == "__main__":
    main()
