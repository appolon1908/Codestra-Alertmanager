import importlib.util
from pathlib import Path
import stat
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
spec = importlib.util.spec_from_file_location("mode_repair", ROOT / "scripts/repair_receiver_modes.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ReceiverModePlanTests(unittest.TestCase):
    def container(self, **mount_changes):
        return {"Config": {"User": "nobody"}, "Mounts": [{
            "Type": "bind", "RW": False,
            "Source": "/etc/codestra/secrets/monitoring/primary_receiver_url",
            "Destination": "/run/secrets/alertmanager_primary_receiver_url",
            **mount_changes}]}

    def metadata(self, **changes):
        return SimpleNamespace(st_mode=stat.S_IFREG | 0o400, st_nlink=1, st_size=50,
                               st_uid=0, st_gid=0, **changes)

    def test_root_only_file_becomes_group_readable_without_public_access(self):
        with patch.object(Path, "resolve", lambda p: p), patch.object(Path, "lstat", return_value=self.metadata()):
            changes = module.plan(self.container())
        self.assertEqual(changes[0]["before_mode"], "0o400")
        self.assertEqual(changes[0]["after_gid"], 65534)
        self.assertEqual(changes[0]["after_mode"], "0o440")

    def test_unrelated_path_writable_mount_and_alias_rejected(self):
        for changes in ({"Source": "/etc/other/file"}, {"RW": True}, {"Type": "volume"}):
            with patch.object(Path, "resolve", lambda p: p), self.assertRaises(ValueError):
                module.plan(self.container(**changes))
        with patch.object(Path, "resolve", return_value=Path("/etc/other/file")), self.assertRaises(ValueError):
            module.plan(self.container())

    def test_hardlinked_or_unowned_file_and_root_runtime_rejected(self):
        for field, value in (("st_uid", 1000), ("st_nlink", 2), ("st_size", 0)):
            metadata = self.metadata()
            setattr(metadata, field, value)
            with patch.object(Path, "resolve", lambda p: p), patch.object(Path, "lstat", return_value=metadata), self.assertRaises(ValueError):
                module.plan(self.container())
        container = self.container()
        container["Config"]["User"] = "root"
        with self.assertRaises(ValueError):
            module.plan(container)
