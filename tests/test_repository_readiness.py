from __future__ import annotations

import hashlib
import json
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class RepositoryReadinessTests(unittest.TestCase):
    def test_validator_passes(self) -> None:
        subprocess.run(
            ["python3", "scripts/validate_repository_readiness.py"],
            cwd=ROOT,
            check=True,
        )

    def test_bundle_is_deterministic_and_contains_only_governed_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            first = Path(directory) / "first.tar.gz"
            second = Path(directory) / "second.tar.gz"
            for output in (first, second):
                subprocess.run(
                    ["python3", "scripts/build_config_bundle.py", "--output", str(output)],
                    cwd=ROOT,
                    check=True,
                )
            self.assertEqual(hashlib.sha256(first.read_bytes()).digest(), hashlib.sha256(second.read_bytes()).digest())
            manifest = json.loads(
                (ROOT / "codestra/release/config-bundle.manifest.json").read_text()
            )
            with tarfile.open(first, "r:gz") as archive:
                names = set(archive.getnames())
            self.assertEqual(
                names,
                set(manifest["files"]) | {"codestra/release/config-bundle.manifest.json"},
            )

    def test_no_direct_provider_receiver_or_public_port(self) -> None:
        config = (ROOT / "codestra/alertmanager.yml").read_text()
        compose = (ROOT / "codestra/compose.yaml").read_text()
        lock = json.loads(
            (ROOT / "codestra/release/runtime-image.lock.json").read_text()
        )
        self.assertNotIn("email_configs:", config)
        self.assertNotIn("smtp_", config)
        self.assertNotIn("\n    ports:\n", compose)
        self.assertIn(f"image: {lock['image']}", compose)
        self.assertNotIn("ALERTMANAGER_IMAGE", compose)

    def test_release_job_is_structurally_pinned(self) -> None:
        import yaml

        workflow = yaml.safe_load(
            (ROOT / ".github/workflows/release-config-bundle.yml").read_text()
        )
        job = workflow["jobs"]["release"]
        self.assertEqual(job["with"]["component_id"], "alertmanager")
        self.assertTrue(job["uses"].endswith("@777292781faeca9348d0e2ecdce6ac3f50c91d93"))


if __name__ == "__main__":
    unittest.main()
