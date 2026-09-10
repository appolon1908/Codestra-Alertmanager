import copy
import importlib.util
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("transport", ROOT / "scripts/configure_native_middleware.py")
transport = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(transport)
TOKEN_URL = "https://identity.example.invalid/realms/codestra/protocol/openid-connect/token"


class NativeTransportTests(unittest.TestCase):
    def setUp(self):
        self.source = yaml.safe_load((ROOT / "codestra/alertmanager.yml").read_text())

    def test_preserves_routing_inhibition_limits_and_resolutions(self):
        result = transport.configure(self.source, TOKEN_URL)
        self.assertEqual(result["route"], self.source["route"])
        self.assertEqual(result["inhibit_rules"], self.source["inhibit_rules"])
        for before, after in zip(self.source["receivers"], result["receivers"]):
            left = copy.deepcopy(before["webhook_configs"][0])
            right = copy.deepcopy(after["webhook_configs"][0])
            left.pop("http_config")
            right.pop("http_config")
            self.assertEqual(left, right)

    def test_uses_keycloak_file_secrets_and_native_headers(self):
        result = transport.configure(self.source, TOKEN_URL)
        for receiver in result["receivers"]:
            http = receiver["webhook_configs"][0]["http_config"]
            self.assertNotIn("authorization", http)
            self.assertEqual(http["oauth2"]["client_id"], "alertmanager-service")
            self.assertIn("client_secret_file", http["oauth2"])
            self.assertFalse(http["tls_config"]["insecure_skip_verify"])
            self.assertNotIn("Idempotency-Key", http["http_headers"])
            self.assertEqual(http["http_headers"]["X-Alertmanager-Native-Webhook"], {"values": ["v4"]})

    def test_idempotent_and_input_unmodified(self):
        before = copy.deepcopy(self.source)
        result = transport.configure(self.source, TOKEN_URL)
        self.assertEqual(self.source, before)
        self.assertEqual(transport.configure(result, TOKEN_URL), result)

    def test_rejects_unsafe_token_urls(self):
        for url in ["http://id.invalid/realms/a/protocol/openid-connect/token",
                    "https://user:pass@id.invalid/realms/a/protocol/openid-connect/token",
                    TOKEN_URL + "?secret=value", TOKEN_URL + "#fragment",
                    "https://id.invalid/wrong"]:
            with self.subTest(url=url), self.assertRaises(ValueError):
                transport.configure(self.source, url)

    def test_rejects_unknown_receivers_direct_delivery_or_auth(self):
        for mutation in ["receiver", "direct", "auth", "duplicate"]:
            source = copy.deepcopy(self.source)
            if mutation == "receiver":
                source["receivers"][0]["name"] = "unknown"
            elif mutation == "direct":
                source["receivers"][0]["email_configs"] = [{}]
            elif mutation == "duplicate":
                source["receivers"].append(copy.deepcopy(source["receivers"][0]))
            else:
                source["receivers"][0]["webhook_configs"][0]["http_config"] = {}
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                transport.configure(source, TOKEN_URL)

    def test_rejects_unbounded_or_unresolved_webhooks(self):
        for key, value in [("max_alerts", 0), ("max_alerts", 101), ("send_resolved", False), ("url", "https://example.invalid")]:
            source = copy.deepcopy(self.source)
            source["receivers"][0]["webhook_configs"][0][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                transport.configure(source, TOKEN_URL)
