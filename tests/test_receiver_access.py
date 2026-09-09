import importlib.util
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("receiver_access", ROOT / "scripts/verify_receiver_access.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ReceiverAccessTests(unittest.TestCase):
    def container(self):
        return {"Id": "running-container", "Config": {"User": "nobody"}, "Mounts": [
            {"Destination": "/run/secrets/alertmanager_primary_receiver_url"},
            {"Destination": "/run/secrets/alertmanager_recovery_receiver_url"},
            {"Destination": "/etc/alertmanager/alertmanager.yml"}]}

    def test_denied_file_blocks_readiness_without_printing_contents(self):
        calls = []
        def run(args, **kwargs):
            calls.append(args)
            return subprocess.CompletedProcess(args, 1 if "recovery" in args[-1] else 0)
        report = module.verify(self.container(), run)
        self.assertFalse(report["ready"])
        self.assertFalse(report["notification_delivery_verified"])
        self.assertEqual(len(calls), 4)
        self.assertTrue(all(call[3] == "test" for call in calls))
        self.assertTrue(all("--user" not in call for call in calls))

    def test_readable_files_do_not_claim_delivery(self):
        report = module.verify(self.container(), lambda args, **kw: subprocess.CompletedProcess(args, 0))
        self.assertTrue(report["ready"])
        self.assertFalse(report["notification_delivery_verified"])

    def test_root_and_missing_mounts_rejected(self):
        for identity, mounts in [("root", self.container()["Mounts"]), ("nobody", [])]:
            self.assertFalse(module.verify({"Config": {"User": identity}, "Mounts": mounts})["ready"])
