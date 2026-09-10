import copy
import importlib.util
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location("repair", Path(__file__).resolve().parents[1] / "scripts/repair_core_routing.py")
repair = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(repair)


def config():
    def receiver(name, path):
        return {"name": name, "webhook_configs": [{
            "url_file": "/run/secrets/" + path,
            "send_resolved": True,
            "http_config": {"authorization": {"type": "Bearer", "credentials_file": "/run/secrets/bearer"}},
        }]}
    return {
        "route": {"receiver": "fail-closed-unrouted", "group_by": ["alertname", "environment", "service"], "routes": [
            {"matchers": ['severity="critical"', 'environment="production"'], "receiver": "approved-primary-receiver", "continue": True},
            {"matchers": ['severity="critical"', 'environment="production"'], "receiver": "approved-recovery-receiver"},
        ]},
        "receivers": [receiver("fail-closed-unrouted", "rejected"), receiver("approved-secondary-receiver", "secondary"), receiver("approved-primary-receiver", "primary"), receiver("approved-recovery-receiver", "recovery")],
    }


class RoutingRepairTests(unittest.TestCase):
    def test_warning_and_quarantine_are_operator_visible(self):
        candidate = repair.repair(config())
        warning = candidate["route"]["routes"][-1]
        self.assertEqual(warning["receiver"], "approved-secondary-receiver")
        self.assertEqual(set(warning["matchers"]), set(repair.WARNING_MATCHERS))
        fallback = candidate["receivers"][-1]
        self.assertEqual([w["url_file"] for w in fallback["webhook_configs"]], ["/run/secrets/rejected", "/run/secrets/secondary"])
        self.assertTrue(all(w["send_resolved"] for w in fallback["webhook_configs"]))

    def test_critical_routes_and_authentication_are_preserved(self):
        original = config()
        candidate = repair.repair(original)
        self.assertEqual(candidate["route"]["routes"][:2], original["route"]["routes"])
        self.assertEqual(candidate["receivers"][:4], original["receivers"])

    def test_idempotent_and_does_not_mutate_input(self):
        original = config()
        before = copy.deepcopy(original)
        once = repair.repair(original)
        self.assertEqual(original, before)
        self.assertEqual(repair.repair(once), once)

    def test_groups_business_and_severity_separately(self):
        self.assertTrue({"codestra_business", "severity"}.issubset(repair.repair(config())["route"]["group_by"]))

    def test_rejects_unauthenticated_receiver(self):
        value = config()
        value["receivers"][0]["webhook_configs"][0]["http_config"] = {}
        with self.assertRaises(ValueError):
            repair.repair(value)

    def test_rejects_direct_delivery(self):
        value = config()
        value["receivers"][0]["email_configs"] = [{}]
        with self.assertRaises(ValueError):
            repair.repair(value)

    def test_rejects_unknown_default(self):
        value = config()
        value["route"]["receiver"] = "custom"
        with self.assertRaises(ValueError):
            repair.repair(value)

    def test_rejects_conflicting_warning_policy(self):
        value = config()
        value["route"]["routes"].append({"matchers": repair.WARNING_MATCHERS, "receiver": "approved-primary-receiver"})
        with self.assertRaises(ValueError):
            repair.repair(value)
