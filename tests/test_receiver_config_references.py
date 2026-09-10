import importlib.util
import json
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("receiver_access", ROOT / "scripts/verify_receiver_access.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ReceiverConfigurationTests(unittest.TestCase):
    url = "/run/secrets/alertmanager_primary_receiver_url"
    credential = "/run/secrets/alertmanager_receiver_bearer"

    def config(self):
        return {"receivers": [{"name": "existing",
                              "webhook_configs": [{"url_file": self.url,
                                 "http_config": {"authorization": {
                                     "type": "Bearer", "credentials_file": self.credential}}}]}]}

    def container(self, include_credential=False):
        paths = [self.url] + ([self.credential] if include_credential else [])
        return {"Id": "runtime", "Config": {"User": "nobody"},
                "Mounts": [{"Destination": p, "RW": False} for p in paths]}

    def run_ok(self, args, **kwargs):
        return subprocess.CompletedProcess(args, 0)

    def test_missing_configured_auth_mount_blocks_even_if_all_mounted_urls_readable(self):
        report = module.verify(self.container(), self.run_ok, self.config())
        self.assertFalse(report["ready"])
        missing = next(x for x in report["files"] if x["path"] == self.credential)
        self.assertFalse(missing["mounted"])
        self.assertFalse(missing["readable"])

    def test_complete_access_does_not_claim_notification_delivery(self):
        report = module.verify(self.container(True), self.run_ok, self.config())
        self.assertTrue(report["ready"])
        self.assertTrue(report["configuration_references_verified"])
        self.assertFalse(report["notification_delivery_verified"])

    def test_writable_credential_mount_rejected(self):
        container = self.container(True)
        container["Mounts"][1]["RW"] = True
        self.assertFalse(module.verify(container, self.run_ok, self.config())["ready"])

    def test_nested_tls_basic_auth_and_legacy_bearer_files_collected(self):
        paths = ["/run/secrets/ca", "/run/secrets/cert", "/run/secrets/key",
                 "/run/secrets/basic", "/run/secrets/legacy"]
        config = {"receivers": [{"webhook_configs": [{"http_config": {
            "tls_config": dict(zip(["ca_file", "cert_file", "key_file"], paths[:3])),
            "basic_auth": {"password_file": paths[3]}, "bearer_token_file": paths[4]}}]}]}
        self.assertEqual(module.configured_references(config), sorted(paths))

    def test_invalid_and_escaping_configuration_rejected(self):
        for config in [None, {}, {"receivers": []}]:
            with self.assertRaises(ValueError):
                module.configured_references(config)
        for value in ["/tmp/secret", "/run/secrets/../escape", "/run/secrets//duplicate", 42]:
            config = {"receivers": [{"webhook_configs": [{"url_file": value}]}]}
            with self.assertRaises(ValueError):
                module.configured_references(config)

    def test_inline_values_are_never_in_report(self):
        config = self.config()
        config["receivers"][0]["webhook_configs"][0]["http_config"]["authorization"]["credentials"] = "private-marker"
        report = module.verify(self.container(True), self.run_ok, config)
        self.assertNotIn("private-marker", json.dumps(report))

    def test_compatibility_override_adds_only_two_readonly_existing_file_mounts(self):
        import yaml
        override = yaml.safe_load((ROOT / "operations/core-receiver-mounts/compose.override.yaml").read_text())
        self.assertEqual(set(override), {"services"})
        self.assertEqual(set(override["services"]), {"alertmanager"})
        service = override["services"]["alertmanager"]
        self.assertEqual(set(service), {"volumes"})
        self.assertEqual(len(service["volumes"]), 2)
        for mount in service["volumes"]:
            self.assertTrue(mount["read_only"])
            self.assertFalse(mount["bind"]["create_host_path"])
            self.assertTrue(mount["source"].startswith("/etc/codestra/secrets/monitoring/"))
