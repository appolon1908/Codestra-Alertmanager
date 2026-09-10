#!/usr/bin/env python3
"""Validate Codestra Alertmanager protected source authority."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]

EXPECTED_PATHS = [
    "config/config_test.go",
    "config/notifiers_test.go",
    "config/testdata/conf.slack-both-url-and-token.yml",
    "config/testdata/conf.slack-default-app-token.yml",
    "config/testdata/conf.slack-update-message-and-webhook.yml",
]


def _validate_source_transform(transform: object) -> str:
    if not isinstance(transform, dict):
        raise ValueError("source_transform_authority_drift")
    expected = {
        "rule": "replace Slack incoming-webhook test fixture host with hooks.slack.invalid",
        "needle": "https://hooks.slack.com/services/",
        "replacement": "https://hooks.slack.invalid/services/",
        "expected_occurrences": 6,
        "expected_paths": EXPECTED_PATHS,
    }
    if {key: transform.get(key) for key in expected} != expected:
        raise ValueError("source_transform_authority_drift")
    if set(transform) != {*expected, "transformed_tree_oid"}:
        raise ValueError("source_transform_authority_drift")
    tree = transform.get("transformed_tree_oid")
    if not isinstance(tree, str) or re.fullmatch(r"[0-9a-f]{40}", tree) is None:
        raise ValueError("source_transform_tree_must_be_exact_oid")
    return tree


def _validate_lock_transform(transform: object) -> str:
    if not isinstance(transform, dict):
        raise ValueError("source_transform_lock_drift")
    expected = {
        "rule": "replace Slack incoming-webhook test fixture host with hooks.slack.invalid",
        "expected_occurrences": 6,
        "expected_paths": EXPECTED_PATHS,
    }
    if {key: transform.get(key) for key in expected} != expected:
        raise ValueError("source_transform_lock_drift")
    if set(transform) != {*expected, "transformed_tree_oid"}:
        raise ValueError("source_transform_lock_drift")
    tree = transform.get("transformed_tree_oid")
    if not isinstance(tree, str) or re.fullmatch(r"[0-9a-f]{40}", tree) is None:
        raise ValueError("source_transform_lock_tree_must_be_exact_oid")
    return tree


def validate_upstream(
    source: dict, lock: dict, *, allow_pending_sync: bool = False
) -> None:
    expected = {
        "component": "Alertmanager",
        "codestra_repository": "appolon1908-hue/Codestra-Alertmanager",
        "upstream_repository": "prometheus/alertmanager",
        "upstream_clone_url": "https://github.com/prometheus/alertmanager.git",
        "import_path": "upstream",
        "import_mode": "shallow-source-snapshot",
        "preserve_upstream_license": True,
        "deployment_enabled": False,
        "secret_material_allowed_in_git": False,
    }
    for key, value in expected.items():
        if source.get(key) != value:
            raise ValueError(f"upstream_authority_drift:{key}")
    ref = source.get("upstream_ref")
    if not isinstance(ref, str) or re.fullmatch(r"[0-9a-f]{40}", ref) is None:
        raise ValueError("upstream_ref_must_be_exact_commit")
    for key in (
        "upstream_clone_url",
        "import_path",
        "deployment_enabled",
        "secret_material_allowed_in_git",
    ):
        if lock.get(key) != expected[key]:
            raise ValueError(f"upstream_lock_drift:{key}")
    lock_ref = lock.get("upstream_ref")
    lock_commit = lock.get("upstream_commit")
    if (
        not isinstance(lock_ref, str)
        or re.fullmatch(r"[0-9a-f]{40}", lock_ref) is None
        or lock_commit != lock_ref
    ):
        raise ValueError("upstream_lock_not_bound_to_exact_ref")
    source_tree = _validate_source_transform(source.get("source_transform"))
    lock_tree = _validate_lock_transform(lock.get("source_transform"))
    if not allow_pending_sync and (lock_ref != ref or lock_tree != source_tree):
        raise ValueError("upstream_lock_not_bound_to_exact_ref")


def validate_sync(source: str, document: dict) -> None:
    if (document.get("permissions") or {}) != {
        "actions": "write",
        "contents": "write",
        "pull-requests": "write",
    }:
        raise ValueError("sync_permissions_drift")
    forbidden = (
        r"git\s+push\s+origin\s+(?:HEAD:)?(?:main|staging|production)(?:\s|$)",
        r"git\s+push\s+--force",
    )
    if any(re.search(pattern, source) for pattern in forbidden):
        raise ValueError("protected_branch_sync_forbidden")
    required = (
        "[[ \"$UPSTREAM_REF\" =~ ^[0-9a-f]{40}$ ]]",
        "[[ \"$UPSTREAM_SHA\" == \"$UPSTREAM_REF\" ]]",
        'SYNC_BRANCH="sync/alertmanager-upstream-${UPSTREAM_SHA}"',
        "expected_occurrences = 6",
        "if set(counts) != expected_paths",
        "if sum(counts.values()) != expected_occurrences",
        '[[ "$TRANSFORMED_TREE_OID" == "$EXPECTED_TRANSFORMED_TREE" ]]',
        'git read-tree --prefix=upstream/ "${TRANSFORMED_COMMIT}^{tree}"',
        '[[ "$REMOTE_SHA" == "$LOCAL_SHA" ]]',
        'head=${REPOSITORY_OWNER}:${SYNC_BRANCH}',
        '[[ "$PR_BASE" == main ]]',
        '[[ "$PR_HEAD" == "$SYNC_BRANCH" ]]',
        '[[ "$PR_OWNER" == "$REPOSITORY_OWNER" ]]',
        '[[ "$PR_REPOSITORY" == "$GITHUB_REPOSITORY" ]]',
        '[[ "$PR_HEAD_SHA" == "$LOCAL_SHA" ]]',
        "Multiple open synchronization pull requests found.",
        "gh pr create",
        "--base main",
        'gh workflow run validate.yml --repo "$GITHUB_REPOSITORY" --ref "$SYNC_BRANCH"',
        "'synchronized_at': os.environ['UPSTREAM_TIMESTAMP']",
        'export GIT_AUTHOR_DATE="$UPSTREAM_TIMESTAMP"',
        'export GIT_COMMITTER_DATE="$UPSTREAM_TIMESTAMP"',
    )
    for token in required:
        if token not in source:
            raise ValueError(f"reviewed_sync_boundary_missing:{token}")
    if 'git read-tree --prefix=upstream/ "${UPSTREAM_SHA}^{tree}"' in source:
        raise ValueError("raw_upstream_tree_must_not_bypass_bounded_transform")


def validate_workflow(source: str) -> None:
    required = (
        "pull_request:",
        "workflow_dispatch:",
        "validate-source:",
        "name: validate-source",
        "actions/checkout@11d5960a326750d5838078e36cf38b85af677262",
        "actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065",
        "persist-credentials: false",
        "fetch-depth: 0",
        "Classify exact metadata bootstrap change",
        'git diff --name-only -z "$base_sha" "$GITHUB_SHA"',
        "${#changed_paths[@]} == 1",
        '"${changed_paths[0]}" == CODESTRA_UPSTREAM.json',
        "CODESTRA_PENDING_UPSTREAM_SYNC=1",
        "Bind vendored Git tree to deterministic transformed official commit",
        'vendored_expected_tree="$lock_tree"',
        "git rev-parse 'HEAD:upstream'",
        '[[ "$vendored_tree" == "$vendored_expected_tree" ]]',
        '[[ "$transformed_tree" == "$expected_tree" ]]',
        "scripts/reject_repository_secrets.sh .",
        'scripts/reject_repository_secrets.sh --git-range "$base_sha" "$GITHUB_SHA"',
        'git diff --check "$base_sha" "$GITHUB_SHA" -- . \':(exclude)upstream\'',
    )
    for token in required:
        if token not in source:
            raise ValueError(f"validation_boundary_missing:{token}")
    if re.search(r"uses:\s+actions/(?:checkout|setup-python)@v\d+", source):
        raise ValueError("mutable_action_reference")
    if re.search(r"pull_request:\s*\n\s+paths:", source):
        raise ValueError("pull_request_validation_must_be_unconditional")
    if re.search(r"^\s*git diff --check\s*$", source, re.MULTILINE):
        raise ValueError("whitespace_check_must_use_committed_range")
    if "--exclude-dir=tests" in source:
        raise ValueError("repository_tests_must_be_secret_scanned")
    if re.search(r"!\s+grep\s+-R", source):
        raise ValueError("secret_scan_errors_must_fail_closed")


def validate_secret_scanner(source: str) -> None:
    if "--exclude-dir=tests" in source or "*/upstream" in source:
        raise ValueError("repository_tests_must_be_secret_scanned")
    if re.search(r"grep\s+-[^\n]*I", source):
        raise ValueError("binary_secret_scan_must_not_be_skipped")
    required = (
        'find "$search_root"',
        '-path "$search_root/.git"',
        '-path "$search_root/upstream"',
        "-type f -o -type l",
        '[[ -L "$path" ]]',
        "grep -aEiq",
        "find_status=$?",
        "secret_scan_status=$?",
        'exit "$secret_scan_status"',
        '[[ "${1:-}" == --git-range ]]',
        'git rev-list --reverse --topo-order "${base_sha}..${head_sha}"',
        'git ls-tree -r -z --full-tree "$commit_sha"',
        'git cat-file blob "$object_sha"',
    )
    for token in required:
        if token not in source:
            raise ValueError(f"secret_scan_boundary_missing:{token}")
    if re.search(r"!\s+grep\s+-R", source):
        raise ValueError("secret_scan_errors_must_fail_closed")


def validate_repository() -> None:
    paths = {
        "source": ROOT / "CODESTRA_UPSTREAM.json",
        "lock": ROOT / "CODESTRA_UPSTREAM_LOCK.json",
        "sync": ROOT / ".github/workflows/upstream-source-sync.yml",
        "validate": ROOT / ".github/workflows/validate.yml",
        "secret_scanner": ROOT / "scripts/reject_repository_secrets.sh",
    }
    for path in paths.values():
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"required_regular_file_missing:{path.relative_to(ROOT)}")
    source = json.loads(paths["source"].read_text())
    lock = json.loads(paths["lock"].read_text())
    sync_source = paths["sync"].read_text()
    validate_source = paths["validate"].read_text()
    secret_scanner_source = paths["secret_scanner"].read_text()
    validate_upstream(
        source,
        lock,
        allow_pending_sync=os.environ.get("CODESTRA_PENDING_UPSTREAM_SYNC") == "1",
    )
    validate_sync(sync_source, yaml.safe_load(sync_source))
    yaml.safe_load(validate_source)
    validate_workflow(validate_source)
    validate_secret_scanner(secret_scanner_source)
    if (ROOT / "upstream/.git").exists():
        raise ValueError("nested_upstream_git_metadata_forbidden")


if __name__ == "__main__":
    try:
        validate_repository()
    except (OSError, ValueError, json.JSONDecodeError, yaml.YAMLError) as error:
        raise SystemExit(f"ALERTMANAGER_SOURCE_SECURITY=FAIL ERROR={error}") from error
    print("ALERTMANAGER_SOURCE_SECURITY=PASS")
    print("UPSTREAM_COMMIT_PINNED=YES")
    print("DETERMINISTIC_SOURCE_TRANSFORM=PASS")
    print("SYNC_THROUGH_REVIEWED_PR=YES")
    print("DEPLOYMENT_ENABLED=NO")
