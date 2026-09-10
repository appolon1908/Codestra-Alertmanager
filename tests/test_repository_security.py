#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "validate_repository_security", ROOT / "scripts/validate_repository_security.py"
)
assert SPEC and SPEC.loader
VALIDATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATOR)


class RepositorySecurityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.sync_source = (ROOT / ".github/workflows/upstream-source-sync.yml").read_text()
        self.sync_document = yaml.safe_load(self.sync_source)

    def test_current_repository_security_contract(self) -> None:
        VALIDATOR.validate_repository()

    def test_mutable_upstream_ref_is_rejected(self) -> None:
        source = json.loads((ROOT / "CODESTRA_UPSTREAM.json").read_text())
        lock = json.loads((ROOT / "CODESTRA_UPSTREAM_LOCK.json").read_text())
        source["upstream_ref"] = "main"
        with self.assertRaisesRegex(ValueError, "upstream_ref_must_be_exact_commit"):
            VALIDATOR.validate_upstream(source, lock)

    def test_sync_uses_reviewed_retry_safe_pull_request(self) -> None:
        VALIDATOR.validate_sync(self.sync_source, self.sync_document)
        unsafe = self.sync_source.replace(
            'git push origin "HEAD:refs/heads/${SYNC_BRANCH}"',
            "git push origin HEAD:main",
        )
        with self.assertRaisesRegex(ValueError, "protected_branch_sync_forbidden"):
            VALIDATOR.validate_sync(unsafe, self.sync_document)
        for token in (
            '[[ "$REMOTE_SHA" == "$LOCAL_SHA" ]]',
            "if (( ${#OPEN_PRS[@]} > 1 )); then",
            'export GIT_AUTHOR_DATE="$UPSTREAM_TIMESTAMP"',
            'head=${REPOSITORY_OWNER}:${SYNC_BRANCH}',
            '[[ "$PR_BASE" == main ]]',
            '[[ "$PR_HEAD" == "$SYNC_BRANCH" ]]',
            '[[ "$PR_OWNER" == "$REPOSITORY_OWNER" ]]',
            '[[ "$PR_REPOSITORY" == "$GITHUB_REPOSITORY" ]]',
            '[[ "$PR_HEAD_SHA" == "$LOCAL_SHA" ]]',
        ):
            self.assertIn(token, self.sync_source)

    def test_existing_sync_pr_identity_is_fully_bound(self) -> None:
        self.assertIn("base=main", self.sync_source)
        self.assertIn('head=${REPOSITORY_OWNER}:${SYNC_BRANCH}', self.sync_source)
        unsafe = self.sync_source.replace(
            '[[ "$PR_HEAD_SHA" == "$LOCAL_SHA" ]]',
            '[[ -n "$PR_HEAD_SHA" ]]',
        )
        with self.assertRaisesRegex(ValueError, "reviewed_sync_boundary_missing"):
            VALIDATOR.validate_sync(unsafe, self.sync_document)

    def test_bot_created_pr_dispatches_exact_branch_validation(self) -> None:
        self.assertEqual(
            self.sync_document["permissions"],
            {"actions": "write", "contents": "write", "pull-requests": "write"},
        )
        self.assertIn(
            'gh workflow run validate.yml --repo "$GITHUB_REPOSITORY" --ref "$SYNC_BRANCH"',
            self.sync_source,
        )

    def test_vendored_tree_is_bound_to_deterministic_transformed_commit(self) -> None:
        source = (ROOT / ".github/workflows/validate.yml").read_text()
        self.assertIn('fetch --depth 1 --no-tags origin "$upstream_ref"', source)
        self.assertIn('transformed_tree="$(git -C "$staging/source" write-tree)"', source)
        self.assertIn("git rev-parse 'HEAD:upstream'", source)
        self.assertIn('vendored_expected_tree="$lock_tree"', source)
        self.assertIn('[[ "$vendored_tree" == "$vendored_expected_tree" ]]', source)
        self.assertIn('[[ "$transformed_tree" == "$expected_tree" ]]', source)

    def test_metadata_bootstrap_keeps_current_vendored_tree_bound_to_lock(self) -> None:
        source = json.loads((ROOT / "CODESTRA_UPSTREAM.json").read_text())
        lock = json.loads((ROOT / "CODESTRA_UPSTREAM_LOCK.json").read_text())
        source["upstream_ref"] = "a" * 40
        source["source_transform"]["transformed_tree_oid"] = "b" * 40
        with self.assertRaisesRegex(ValueError, "upstream_lock_not_bound_to_exact_ref"):
            VALIDATOR.validate_upstream(source, lock)
        VALIDATOR.validate_upstream(source, lock, allow_pending_sync=True)
        workflow = (ROOT / ".github/workflows/validate.yml").read_text()
        self.assertIn("${#changed_paths[@]} == 1", workflow)
        self.assertIn('"${changed_paths[0]}" == CODESTRA_UPSTREAM.json', workflow)
        self.assertIn("CODESTRA_PENDING_UPSTREAM_SYNC=1", workflow)

    def test_slack_fixture_transform_is_exact_and_bounded(self) -> None:
        source = json.loads((ROOT / "CODESTRA_UPSTREAM.json").read_text())
        lock = json.loads((ROOT / "CODESTRA_UPSTREAM_LOCK.json").read_text())
        pending_sync = os.environ.get("CODESTRA_PENDING_UPSTREAM_SYNC") == "1"
        VALIDATOR.validate_upstream(source, lock, allow_pending_sync=pending_sync)
        transform = source["source_transform"]
        self.assertEqual(transform["expected_occurrences"], 6)
        self.assertEqual(transform["expected_paths"], VALIDATOR.EXPECTED_PATHS)
        if not pending_sync:
            self.assertEqual(
                transform["transformed_tree_oid"],
                lock["source_transform"]["transformed_tree_oid"],
            )
        self.assertIn(
            'git read-tree --prefix=upstream/ "${TRANSFORMED_COMMIT}^{tree}"',
            self.sync_source,
        )
        self.assertNotIn(
            'git read-tree --prefix=upstream/ "${UPSTREAM_SHA}^{tree}"',
            self.sync_source,
        )
        unsafe = json.loads(json.dumps(source))
        unsafe["source_transform"]["expected_paths"].append("unexpected")
        with self.assertRaisesRegex(ValueError, "source_transform_authority_drift"):
            VALIDATOR.validate_upstream(
                unsafe, lock, allow_pending_sync=pending_sync
            )

    def test_actions_are_pinned_and_validation_is_unconditional(self) -> None:
        source = (ROOT / ".github/workflows/validate.yml").read_text()
        VALIDATOR.validate_workflow(source)
        unsafe = source.replace("pull_request:\n", "pull_request:\n    paths:\n      - scripts/**\n")
        with self.assertRaisesRegex(ValueError, "pull_request_validation_must_be_unconditional"):
            VALIDATOR.validate_workflow(unsafe)

    def test_whitespace_gate_checks_the_committed_base_to_head_range(self) -> None:
        source = (ROOT / ".github/workflows/validate.yml").read_text()
        self.assertIn("fetch-depth: 0", source)
        self.assertIn('base_sha="${{ github.event.pull_request.base.sha }}"', source)
        self.assertIn(
            'git diff --check "$base_sha" "$GITHUB_SHA" -- . \':(exclude)upstream\'',
            source,
        )

    def test_repository_tests_are_included_in_secret_scan(self) -> None:
        source = (ROOT / "scripts/reject_repository_secrets.sh").read_text()
        self.assertNotIn("--exclude-dir=tests", source)
        unsafe = source.replace(
            '-path "$search_root/upstream"',
            '-path "*/upstream"',
        )
        with self.assertRaisesRegex(ValueError, "repository_tests_must_be_secret_scanned"):
            VALIDATOR.validate_secret_scanner(unsafe)

    def test_secret_scan_matches_secrets_and_fails_on_traversal_errors(self) -> None:
        scanner = ROOT / "scripts/reject_repository_secrets.sh"
        with tempfile.TemporaryDirectory() as directory:
            scan_root = Path(directory)
            (scan_root / "clean.txt").write_text("no credential material\n")
            clean = subprocess.run(
                [scanner, scan_root], check=False, capture_output=True, text=True
            )
            self.assertEqual(clean.returncode, 0)

            ignored_root = scan_root / "upstream"
            ignored_root.mkdir()
            secret = "CLIENT" + "_SECRET = " + ("A" * 24) + "\n"
            (ignored_root / "credential.txt").write_text(secret)
            ignored = subprocess.run(
                [scanner, scan_root], check=False, capture_output=True, text=True
            )
            self.assertEqual(ignored.returncode, 0)

            nested = scan_root / "tests/upstream"
            nested.mkdir(parents=True)
            (nested / "credential.txt").write_text(secret)
            found = subprocess.run(
                [scanner, scan_root], check=False, capture_output=True, text=True
            )
            self.assertEqual(found.returncode, 1)
            (nested / "credential.txt").unlink()

            binary_secret = scan_root / "nul-prefixed-credential.txt"
            binary_secret.write_bytes(b"\0unrelated\n" + secret.encode())
            binary_found = subprocess.run(
                [scanner, scan_root], check=False, capture_output=True, text=True
            )
            self.assertEqual(binary_found.returncode, 1)
            binary_secret.unlink()

            for serialized_secret in (
                '{"' + "client_" + "secret" + '":"' + ("B" * 32) + '"}\n',
                "client_" + "secret: " + ("C" * 32) + "\n",
                (
                    '{"'
                    + "Author"
                    + "ization"
                    + '":"'
                    + "Bearer "
                    + ("D" * 32)
                    + '"}\n'
                ),
                (
                    "{ '"
                    + "author"
                    + "ization"
                    + "' : '"
                    + "bearer "
                    + ("E" * 32)
                    + "' }\n"
                ),
                (
                    "Author"
                    + "ization: "
                    + "Bearer "
                    + "abc/def+ghijklmnopqrstuvwxyz==\n"
                ),
                (
                    '{"'
                    + "Author"
                    + "ization"
                    + '":"'
                    + "Bearer "
                    + "abc"
                    + "\\/"
                    + "defghijklmnopqrstuvwxyz=="
                    + '"}\n'
                ),
            ):
                serialized = scan_root / "serialized-credential.txt"
                serialized.write_text(serialized_secret)
                serialized_found = subprocess.run(
                    [scanner, scan_root], check=False, capture_output=True, text=True
                )
                self.assertEqual(serialized_found.returncode, 1)
                serialized.unlink()

            for label in ("ENCRYPTED", "DSA"):
                private_key = scan_root / "private-key.txt"
                private_key.write_text(
                    "-----"
                    + "BEGIN "
                    + label
                    + " PRIVATE"
                    + " KEY-----\nfixture\n"
                )
                private_key_found = subprocess.run(
                    [scanner, scan_root], check=False, capture_output=True, text=True
                )
                self.assertEqual(private_key_found.returncode, 1)
                private_key.unlink()

            os.symlink(scan_root / "missing-target", scan_root / "dangling")
            failed = subprocess.run(
                [scanner, scan_root], check=False, capture_output=True, text=True
            )
            self.assertGreater(failed.returncode, 1)

    def test_secret_scan_covers_credentials_removed_before_final_head(self) -> None:
        scanner = ROOT / "scripts/reject_repository_secrets.sh"
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            subprocess.run(["git", "init", "-q", repository], check=True)
            subprocess.run(
                ["git", "-C", repository, "config", "user.name", "scanner-test"],
                check=True,
            )
            subprocess.run(
                ["git", "-C", repository, "config", "user.email", "scanner@example.invalid"],
                check=True,
            )
            tracked = repository / "policy.txt"
            tracked.write_text("clean\n")
            subprocess.run(["git", "-C", repository, "add", "policy.txt"], check=True)
            subprocess.run(["git", "-C", repository, "commit", "-qm", "base"], check=True)
            base_sha = subprocess.check_output(
                ["git", "-C", repository, "rev-parse", "HEAD"], text=True
            ).strip()

            transient = repository / "transient.txt"
            transient.write_text("CLIENT" + "_SECRET=" + ("Z" * 32) + "\n")
            subprocess.run(["git", "-C", repository, "add", "transient.txt"], check=True)
            subprocess.run(
                ["git", "-C", repository, "commit", "-qm", "introduce transient"],
                check=True,
            )
            transient.unlink()
            subprocess.run(["git", "-C", repository, "add", "-u"], check=True)
            subprocess.run(
                ["git", "-C", repository, "commit", "-qm", "remove transient"],
                check=True,
            )
            head_sha = subprocess.check_output(
                ["git", "-C", repository, "rev-parse", "HEAD"], text=True
            ).strip()

            final_tree = subprocess.run(
                [scanner, repository], check=False, capture_output=True, text=True
            )
            self.assertEqual(final_tree.returncode, 0)
            history = subprocess.run(
                [scanner, "--git-range", base_sha, head_sha],
                cwd=repository,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(history.returncode, 1)
            self.assertIn("transient.txt", history.stderr)

    def test_secret_scanner_cannot_skip_nul_containing_files(self) -> None:
        source = (ROOT / "scripts/reject_repository_secrets.sh").read_text()
        self.assertIn("grep -aEiq", source)
        unsafe = source.replace("grep -aEiq", "grep -IlEi")
        with self.assertRaisesRegex(
            ValueError, "binary_secret_scan_must_not_be_skipped"
        ):
            VALIDATOR.validate_secret_scanner(unsafe)


if __name__ == "__main__":
    unittest.main(verbosity=2)
