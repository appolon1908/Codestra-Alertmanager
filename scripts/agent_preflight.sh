#!/usr/bin/env bash
set -euo pipefail
root="$(git rev-parse --show-toplevel)"
cd "$root"
auth="$root/CODESTRA_AGENT_AUTHORITY.json"
test -f "$auth" || { echo "PREFLIGHT_FAIL_AUTHORITY_MISSING"; exit 40; }
readarray -t meta < <(python3 - "$auth" <<'PY'
import json,sys
a=json.load(open(sys.argv[1],encoding="utf-8"))
for k in ("lane_state","preserved_worktree","preserved_branch","preserved_local_head","authoritative_remote_sha","canonical_successor_worktree"):
    print(a.get(k,""))
PY
)
state="${meta[0]}"; expected_root="${meta[1]}"; expected_branch="${meta[2]}"; expected_head="${meta[3]}"; remote_main="${meta[4]}"; successor="${meta[5]}"
branch="$(git branch --show-current)"
head="$(git rev-parse HEAD)"
case "${1:-}" in
  --audit)
    test "$state" = "preserved-read-only" || { echo "PREFLIGHT_FAIL_AUDIT_STATE"; exit 41; }
    test "$(realpath "$root")" = "$(realpath "$expected_root")" || { echo "PREFLIGHT_FAIL_WRONG_WORKTREE"; exit 42; }
    test "$branch" = "$expected_branch" || { echo "PREFLIGHT_FAIL_WRONG_BRANCH"; exit 43; }
    test "$head" = "$expected_head" || { echo "PREFLIGHT_FAIL_LOCAL_HEAD_MOVED"; exit 44; }
    git diff --check
    if git grep -n -E '^(<<<<<<<|=======|>>>>>>>)' -- ':!AGENTS.md' ':!CODESTRA_AGENT_AUTHORITY.json' >/dev/null 2>&1; then
      echo "PREFLIGHT_FAIL_CONFLICT_MARKERS"; exit 45
    fi
    echo "PREFLIGHT_AUDIT_PASS state=$state local=$head authoritative_main=$remote_main successor=$successor"
    exit 0
    ;;
  --ci)
    test "$state" = "active" || { echo "PREFLIGHT_FAIL_PRESERVED_LANE"; exit 50; }
    ;;
  "")
    test "$state" = "active" || { echo "PREFLIGHT_FAIL_PRESERVED_LANE"; exit 50; }
    ;;
  *)
    echo "usage: $0 [--audit|--ci]"; exit 64
    ;;
esac

# Active-lane checks. These are unreachable until authority is explicitly activated.
test -n "$branch" && test "$branch" != main && test "$branch" != master || { echo "PREFLIGHT_FAIL_PROTECTED_OR_DETACHED"; exit 51; }
test -z "$(git status --porcelain)" || { echo "PREFLIGHT_FAIL_DIRTY"; exit 52; }
upstream="$(git rev-parse --abbrev-ref '@{u}' 2>/dev/null || true)"
test -n "$upstream" || { echo "PREFLIGHT_FAIL_NO_UPSTREAM"; exit 53; }
test "$(git rev-parse '@{u}')" = "$head" || { echo "PREFLIGHT_FAIL_STALE_SHA"; exit 54; }
for v in LIVE_WRITES_ENABLED N8N_PRODUCTION_WORKFLOWS_ENABLED VICIDIAL_WRITE_ENABLED CALLBACK_DISPATCH_ENABLED MESSAGING_ENABLED OUTBOX_WORKER_ENABLED; do
  value="${!v:-false}"
  case "$value" in false|0|"") ;; *) echo "PREFLIGHT_FAIL_PRODUCTION_EFFECT $v"; exit 55;; esac
done
git diff --check
echo "PREFLIGHT_PASS branch=$branch head=$head upstream=$upstream"
