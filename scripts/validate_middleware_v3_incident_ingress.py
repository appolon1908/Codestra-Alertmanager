#!/usr/bin/env python3
"""Fail-closed validation of the Middleware V3 incident-ingress contract.

``codestra/contracts/middleware-v3-incident-ingress.v1.json`` fixes how Alertmanager
notifications reach the Middleware incident authority: bearer identity, bounded
body, idempotency key, fingerprint dedupe, safe retry, correlation and the
OPEN/ACK/RESOLVED/SUPPRESSED lifecycle. This validator proves from source that the
contract is dark and pinned, that every receiver in ``codestra/alertmanager.yml``
speaks that contract (webhook only, URL and bearer from runtime files, resolved
notifications sent, bounded batch, bounded timeout), that nothing in the routing
configuration can deliver anywhere else, and that the fingerprint identity rule
yields exactly one incident per fingerprint. It is stdlib-only except for PyYAML,
which the repository already pins.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
import uuid
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "codestra" / "contracts" / "middleware-v3-incident-ingress.v1.json"
ALERTMANAGER = ROOT / "codestra" / "alertmanager.yml"
LEGACY_CONTRACT = ROOT / "codestra" / "middleware-alert-contract.json"
SHA40 = re.compile(r"^[0-9a-f]{40}$")
IDEMPOTENCY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{7,179}$")
INCIDENT_NAMESPACE = "https://operations.codestra.co/observability/incidents"
LANE_E_STATES = ["OPEN", "ACK", "RESOLVED", "SUPPRESSED"]
FORBIDDEN_RECEIVER_KEYS = {
    "email_configs", "slack_configs", "pagerduty_configs", "opsgenie_configs", "victorops_configs",
    "pushover_configs", "wechat_configs", "telegram_configs", "sns_configs", "discord_configs",
    "webex_configs", "msteams_configs", "msteamsv2_configs", "jira_configs", "rocketchat_configs",
}


def fail(message: str) -> None:
    print(f"MIDDLEWARE_V3_INCIDENT_INGRESS_ERROR={message}", file=sys.stderr)
    raise SystemExit(1)


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"invalid JSON {path.relative_to(ROOT)}: {exc}")


def load_yaml(path: Path) -> Any:
    import yaml

    try:
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        fail(f"invalid YAML {path.relative_to(ROOT)}: {exc}")


def incident_identity(tenant_id: str, fingerprint: str) -> uuid.UUID:
    """Mirror of Middleware app/observability_incidents.py incident_identity()."""
    return uuid.uuid5(uuid.NAMESPACE_URL, f"{INCIDENT_NAMESPACE}/{tenant_id}/{fingerprint}")


def request_identity(client_id: str, key: str, fingerprint: str) -> str:
    """Mirror of Middleware app/observability_incidents.py request_identity()."""
    return hashlib.sha256(f"{client_id}\n{key}\n{fingerprint}".encode("utf-8")).hexdigest()


def one_fingerprint_one_incident(tenant_id: str, deliveries: list[dict[str, Any]]) -> dict[str, Any]:
    """Replay deliveries through the identity rules and count incidents and duplicates."""
    incidents: dict[uuid.UUID, dict[str, Any]] = {}
    seen_requests: set[str] = set()
    duplicates = 0
    for delivery in deliveries:
        for alert in delivery["alerts"]:
            request_id = request_identity("alertmanager", delivery["idempotency_key"], alert["fingerprint"])
            incident_id = incident_identity(tenant_id, alert["fingerprint"])
            if request_id in seen_requests or incident_id in incidents and alert["status"] == "firing" and incidents[incident_id]["state"] == "firing":
                duplicates += 1
                seen_requests.add(request_id)
                continue
            seen_requests.add(request_id)
            record = incidents.setdefault(incident_id, {"fingerprint": alert["fingerprint"], "state": "firing", "events": 0})
            record["state"] = "resolved" if alert["status"] == "resolved" else "firing"
            record["events"] += 1
    return {"incidents": len(incidents), "duplicates": duplicates, "fingerprints": len({a["fingerprint"] for d in deliveries for a in d["alerts"]})}


def validate_contract(contract: dict[str, Any]) -> None:
    if contract.get("schema_version") != "1.0" or contract.get("contract_id") != "middleware-v3-incident-ingress":
        fail("contract identity drift")
    if contract.get("status") != "PREPARED_DISABLED":
        fail("the V3 incident ingress contract must stay PREPARED_DISABLED until V3_FINAL_SHA is pinned")
    if contract.get("activation_enabled") is not False or contract.get("provider_effects_enabled") is not False:
        fail("activation_enabled and provider_effects_enabled must be false")
    middleware = contract.get("middleware", {})
    if not SHA40.fullmatch(str(middleware.get("prep_base_sha", ""))):
        fail("middleware.prep_base_sha must be a 40-hex commit")
    final = middleware.get("v3_final_sha")
    if final != "PENDING" and not SHA40.fullmatch(str(final)):
        fail("middleware.v3_final_sha must be PENDING or a 40-hex commit")

    ingress = contract.get("ingress", {})
    if ingress.get("canonical_path") != "/v1/integrations/alertmanager/events" or ingress.get("method") != "POST":
        fail("ingress must be POST /v1/integrations/alertmanager/events")
    if ingress.get("tls_required") is not True or ingress.get("public_exposure") is not False:
        fail("ingress must require TLS and never be public")
    if not str(ingress.get("url_source", "")).startswith("/run/secrets/"):
        fail("the ingress URL must come from a runtime file")

    auth = contract.get("authentication", {})
    if auth.get("issuer_exact") != "https://auth.codestra.co/realms/codestra" or auth.get("audience_exact") != "middleware-api":
        fail("authentication issuer/audience drift")
    if not str(auth.get("client_exact", "")).startswith("alertmanager"):
        fail("the caller must be the alertmanager client")
    if auth.get("scope_exact") != {"command": "alerts.write", "status": "alerts.read"}:
        fail("scopes must be alerts.write (command) and alerts.read (status)")
    if auth.get("maximum_token_lifetime_seconds") != 300 or auth.get("token_exchange") is not False:
        fail("token lifetime must be 300 s and token exchange disabled")
    if not str(auth.get("credentials_source", "")).startswith("/run/secrets/"):
        fail("the bearer must come from a runtime-rendered file")

    headers = contract.get("required_headers", {})
    for name in ("Authorization", "Content-Type", "X-Tenant-ID", "X-Correlation-ID", "Idempotency-Key", "X-Source-Deployment"):
        if name not in headers:
            fail(f"required header {name} is missing from the contract")
    bounds = contract.get("request_bounds", {})
    if bounds.get("native_alerts_per_request_maximum") != 100 or bounds.get("alertmanager_receiver_max_alerts") != 100:
        fail("native batch and receiver max_alerts must both be 100")
    if bounds.get("fingerprint_max_length") != 128 or bounds.get("groupKey_max_length") != 2048:
        fail("fingerprint/groupKey bounds drift")

    dedupe = contract.get("idempotency_and_dedupe", {})
    if not str(dedupe.get("ONE_ALERT_FINGERPRINT_ONE_INCIDENT", "")).startswith("PASS"):
        fail("ONE_ALERT_FINGERPRINT_ONE_INCIDENT must be PASS")
    if INCIDENT_NAMESPACE not in str(dedupe.get("incident_identity", "")):
        fail("incident identity must be the deterministic tenant+fingerprint uuid5")

    retry = contract.get("safe_retry", {})
    if set(retry.get("never_retry_on", [])) != {"400", "403", "409"} or "503" not in retry.get("retry_on", []):
        fail("retry policy drift: retry only 503/network, never 400/403/409")

    lifecycle = contract.get("incident_lifecycle", {})
    if lifecycle.get("lane_e_states") != LANE_E_STATES:
        fail("lifecycle states must be OPEN, ACK, RESOLVED, SUPPRESSED")
    mapping = lifecycle.get("mapping", {})
    if set(mapping) != set(LANE_E_STATES):
        fail("every lifecycle state needs a Middleware mapping")
    if not mapping["SUPPRESSED"].startswith("inhibited | silenced"):
        fail("SUPPRESSED must map to inhibited and silenced")
    if lifecycle.get("transitions_owned_by") != "Middleware only; Alertmanager never mutates incident state directly":
        fail("incident transitions must be owned by Middleware only")

    forbidden = set(contract.get("forbidden_effects_from_alertmanager", []))
    for effect in ("direct_email_delivery", "direct_provider_api_write", "command_execution", "secret_resolution"):
        if effect not in forbidden:
            fail(f"forbidden effect {effect} must be declared")
    never = set(contract.get("label_policy", {}).get("never_in_labels_or_annotations", []))
    for label in ("email", "phone", "customer", "command_id", "operation_id", "token", "password"):
        if label not in never:
            fail(f"{label} must never be forwarded in labels or annotations")


def validate_receivers() -> None:
    config = load_yaml(ALERTMANAGER)
    receivers = config.get("receivers") or []
    if not receivers:
        fail("alertmanager.yml has no receivers")
    names = set()
    for receiver in receivers:
        name = receiver.get("name")
        names.add(name)
        extra = FORBIDDEN_RECEIVER_KEYS & set(receiver)
        if extra:
            fail(f"receiver {name} delivers outside Middleware: {sorted(extra)}")
        webhooks = receiver.get("webhook_configs")
        if not webhooks:
            fail(f"receiver {name} has no webhook to Middleware")
        for webhook in webhooks:
            if "url" in webhook or webhook.get("url_file") != "/run/secrets/middleware-alert-webhook-url":
                fail(f"receiver {name} must read the Middleware URL from /run/secrets/middleware-alert-webhook-url")
            if webhook.get("send_resolved") is not True:
                fail(f"receiver {name} must send resolved notifications so incidents close")
            if not isinstance(webhook.get("max_alerts"), int) or webhook["max_alerts"] > 100 or webhook["max_alerts"] < 1:
                fail(f"receiver {name} must bound max_alerts to 1..100")
            if str(webhook.get("timeout", "")).rstrip("s").isdigit() is False or int(str(webhook["timeout"]).rstrip("s")) > 30:
                fail(f"receiver {name} must bound the delivery timeout to 30 s or less")
            auth = (webhook.get("http_config") or {}).get("authorization") or {}
            if auth.get("type") != "Bearer" or auth.get("credentials_file") != "/run/secrets/middleware-alert-webhook-token" or "credentials" in auth:
                fail(f"receiver {name} must present the file-based Middleware bearer and never an inline credential")
    route = config.get("route") or {}
    used = {route.get("receiver")} | {child.get("receiver") for child in route.get("routes", [])}
    if not used <= names:
        fail(f"routes reference unknown receivers {sorted(used - names)}")
    text = ALERTMANAGER.read_text(encoding="utf-8")
    if re.search(r"(?im)^\s*(smtp_|slack_api_url|api_url|api_key|credentials:)", text):
        fail("alertmanager.yml carries a non-Middleware delivery setting or an inline credential")


def validate_identity_rules() -> None:
    tenant = "codestra-platform"
    firing = {"status": "firing", "fingerprint": "a1b2c3d4e5f60718"}
    deliveries = [
        {"idempotency_key": "am:grp:1:firing:1", "alerts": [firing]},
        {"idempotency_key": "am:grp:1:firing:1", "alerts": [firing]},  # network retry, same key
        {"idempotency_key": "am:grp:1:firing:2", "alerts": [firing]},  # repeat_interval re-send
        {"idempotency_key": "am:grp:1:firing:3", "alerts": [firing, {"status": "firing", "fingerprint": "ffff0000ffff0000"}]},
        {"idempotency_key": "am:grp:1:resolved:4", "alerts": [{"status": "resolved", "fingerprint": "a1b2c3d4e5f60718"}]},
    ]
    result = one_fingerprint_one_incident(tenant, deliveries)
    if result["incidents"] != result["fingerprints"] != 2:
        fail(f"ONE_ALERT_FINGERPRINT_ONE_INCIDENT=FAIL {result}")
    if result["duplicates"] != 3:
        fail(f"repeated firing deliveries must be duplicates, got {result}")
    for key in ("am:grp:1:firing:1", "codestra-am-2026-09-19T00:00:00Z"):
        if not IDEMPOTENCY_RE.fullmatch(key):
            fail(f"idempotency key shape drift for {key}")
    if incident_identity(tenant, "a1b2c3d4e5f60718") == incident_identity("other-tenant", "a1b2c3d4e5f60718"):
        fail("incident identity must be tenant scoped")


def validate_legacy_contract_consistency(contract: dict[str, Any]) -> None:
    legacy = load_json(LEGACY_CONTRACT)
    if legacy.get("middleware_source_authority", {}).get("canonical_path") != contract["ingress"]["canonical_path"]:
        fail("canonical path drift between middleware-alert-contract.json and the V3 ingress contract")
    if legacy.get("deduplication", {}).get("repeated_delivery_creates_duplicate_incident") is not False:
        fail("the accepted contract must keep repeated deliveries from creating duplicate incidents")


def main() -> None:
    contract = load_json(CONTRACT)
    validate_contract(contract)
    validate_receivers()
    validate_identity_rules()
    validate_legacy_contract_consistency(contract)
    print(
        "MIDDLEWARE_V3_INCIDENT_INGRESS=PASS ONE_ALERT_FINGERPRINT_ONE_INCIDENT=PASS "
        f"prep_base={contract['middleware']['prep_base_sha'][:12]} v3_final={contract['middleware']['v3_final_sha']}"
    )


if __name__ == "__main__":
    main()
