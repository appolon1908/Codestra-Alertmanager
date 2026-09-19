"""Alertmanager -> Middleware V3 incident ingress: dark, pinned, one fingerprint = one incident."""

from __future__ import annotations

import copy
import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "validate_middleware_v3_incident_ingress", ROOT / "scripts" / "validate_middleware_v3_incident_ingress.py"
)
assert SPEC is not None and SPEC.loader is not None
VALIDATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATOR)


class IncidentIngressContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = json.loads(VALIDATOR.CONTRACT.read_text(encoding="utf-8"))

    def reject(self, contract: dict) -> None:
        with self.assertRaises(SystemExit):
            VALIDATOR.validate_contract(contract)

    def test_source_passes(self) -> None:
        VALIDATOR.validate_contract(self.contract)
        VALIDATOR.validate_receivers()
        VALIDATOR.validate_identity_rules()
        VALIDATOR.validate_legacy_contract_consistency(self.contract)

    def test_pins(self) -> None:
        self.assertEqual(self.contract["middleware"]["prep_base_sha"], "22d023a9c65b0789a0f7ee6c28548753521a9eff")
        self.assertEqual(self.contract["middleware"]["v3_final_sha"], "PENDING")

    def test_activation_and_public_exposure_are_rejected(self) -> None:
        for path, value in (
            (("status",), "ACTIVE"),
            (("activation_enabled",), True),
            (("ingress", "public_exposure"), True),
            (("ingress", "tls_required"), False),
            (("authentication", "token_exchange"), True),
            (("authentication", "maximum_token_lifetime_seconds"), 3600),
            (("authentication", "audience_exact"), "openbao"),
        ):
            mutated = copy.deepcopy(self.contract)
            target = mutated
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = value
            self.reject(mutated)

    def test_lifecycle_and_dedupe_are_required(self) -> None:
        mutated = copy.deepcopy(self.contract)
        mutated["incident_lifecycle"]["lane_e_states"] = ["OPEN", "RESOLVED"]
        self.reject(mutated)
        mutated = copy.deepcopy(self.contract)
        mutated["idempotency_and_dedupe"]["ONE_ALERT_FINGERPRINT_ONE_INCIDENT"] = "FAIL"
        self.reject(mutated)
        mutated = copy.deepcopy(self.contract)
        mutated["safe_retry"]["never_retry_on"] = ["400"]
        self.reject(mutated)
        mutated = copy.deepcopy(self.contract)
        mutated["label_policy"]["never_in_labels_or_annotations"].remove("email")
        self.reject(mutated)

    def test_one_alert_fingerprint_one_incident(self) -> None:
        firing = {"status": "firing", "fingerprint": "0123456789abcdef"}
        deliveries = [{"idempotency_key": f"am:g:firing:{n}", "alerts": [firing]} for n in range(1, 25)]
        result = VALIDATOR.one_fingerprint_one_incident("codestra-platform", deliveries)
        self.assertEqual(result["incidents"], 1)
        self.assertEqual(result["duplicates"], 23)
        # A network retry with the same Idempotency-Key is a replay, not an event.
        deliveries.append(dict(deliveries[0]))
        result = VALIDATOR.one_fingerprint_one_incident("codestra-platform", deliveries)
        self.assertEqual(result["incidents"], 1)
        self.assertEqual(result["duplicates"], 24)
        # A resolve then a new firing reopens the same incident identity.
        deliveries.append({"idempotency_key": "am:g:resolved:1", "alerts": [{"status": "resolved", "fingerprint": "0123456789abcdef"}]})
        deliveries.append({"idempotency_key": "am:g:firing:99", "alerts": [firing]})
        result = VALIDATOR.one_fingerprint_one_incident("codestra-platform", deliveries)
        self.assertEqual(result["incidents"], 1)

    def test_incident_identity_is_deterministic_and_tenant_scoped(self) -> None:
        a = VALIDATOR.incident_identity("codestra-platform", "abc")
        self.assertEqual(a, VALIDATOR.incident_identity("codestra-platform", "abc"))
        self.assertNotEqual(a, VALIDATOR.incident_identity("codestra-platform", "abd"))
        self.assertNotEqual(a, VALIDATOR.incident_identity("other", "abc"))
        self.assertNotEqual(
            VALIDATOR.request_identity("alertmanager", "k1", "abc"),
            VALIDATOR.request_identity("alertmanager", "k2", "abc"),
        )

    def test_receivers_only_reach_middleware_with_file_credentials(self) -> None:
        import yaml

        config = yaml.safe_load(VALIDATOR.ALERTMANAGER.read_text(encoding="utf-8"))
        for receiver in config["receivers"]:
            self.assertEqual(set(receiver) - {"name"}, {"webhook_configs"}, receiver["name"])
            for webhook in receiver["webhook_configs"]:
                self.assertEqual(webhook["url_file"], "/run/secrets/middleware-alert-webhook-url")
                self.assertTrue(webhook["send_resolved"])
                self.assertLessEqual(webhook["max_alerts"], 100)
                self.assertEqual(webhook["http_config"]["authorization"]["credentials_file"], "/run/secrets/middleware-alert-webhook-token")
                self.assertNotIn("credentials", webhook["http_config"]["authorization"])


if __name__ == "__main__":
    unittest.main()
