#!/usr/bin/env bash
set -Eeuo pipefail

pattern="(BEGIN ([A-Z0-9][A-Z0-9 -]{0,63} )?PRIVATE KEY|[\"']?Authorization[\"']?[[:space:]]*:[[:space:]]*[\"']?[[:space:]]*Bearer[[:space:]]+([-A-Za-z0-9._~+]|\\\\?/){16,}=*|[\"']?client_secret[\"']?[[:space:]]*[:=][[:space:]]*[^[:space:]<]+)"
scan_staging="$(mktemp -d)"
trap 'rm -rf -- "$scan_staging"' EXIT

scan_path() {
  local path="$1"
  local label="${2:-$path}"
  local secret_scan_status

  set +e
  # Treat every tracked byte stream as text. GNU grep's -I/without-match mode
  # silently accepts a file merely because it contains a NUL byte.
  LC_ALL=C grep -aEiq "$pattern" -- "$path"
  secret_scan_status=$?
  set -e
  case "$secret_scan_status" in
    0)
      echo "Control-plane secret pattern detected: ${label}" >&2
      exit 1
      ;;
    1)
      ;;
    *)
      echo "Secret scan failed before completing for ${label} (grep status ${secret_scan_status})." >&2
      exit "$secret_scan_status"
      ;;
  esac
}

if [[ "${1:-}" == --git-range ]]; then
  base_sha="${2:-}"
  head_sha="${3:-}"
  [[ "$base_sha" =~ ^[0-9a-f]{40}$ ]] || {
    echo 'Secret scan base must be an exact commit SHA.' >&2
    exit 2
  }
  [[ "$head_sha" =~ ^[0-9a-f]{40}$ ]] || {
    echo 'Secret scan head must be an exact commit SHA.' >&2
    exit 2
  }
  git cat-file -e "${base_sha}^{commit}"
  git cat-file -e "${head_sha}^{commit}"
  git rev-list --reverse --topo-order "${base_sha}..${head_sha}" \
    > "$scan_staging/commits"
  while IFS= read -r commit_sha; do
    [[ "$commit_sha" =~ ^[0-9a-f]{40}$ ]] || {
      echo 'Secret scan encountered an invalid commit identity.' >&2
      exit 2
    }
    git ls-tree -r -z --full-tree "$commit_sha" > "$scan_staging/tree"
    while IFS= read -r -d '' entry; do
      metadata="${entry%%$'\t'*}"
      path="${entry#*$'\t'}"
      [[ "$entry" == *$'\t'* && "$path" != "$entry" ]] || {
        echo 'Secret scan encountered an invalid tree entry.' >&2
        exit 2
      }
      [[ "$path" == upstream || "$path" == upstream/* ]] && continue
      read -r mode object_type object_sha <<< "$metadata"
      [[ "$mode" =~ ^[0-7]{6}$ && "$object_type" == blob && "$object_sha" =~ ^[0-9a-f]{40,64}$ ]] || {
        echo "Secret scan refuses non-regular tree entry: ${commit_sha}:${path}" >&2
        exit 2
      }
      [[ "$mode" != 120000 ]] || {
        echo "Secret scan refuses symbolic link: ${commit_sha}:${path}" >&2
        exit 2
      }
      git cat-file blob "$object_sha" > "$scan_staging/blob"
      scan_path "$scan_staging/blob" "${commit_sha}:${path}"
    done < "$scan_staging/tree"
  done < "$scan_staging/commits"
  exit 0
fi

search_root="${1:-.}"
path_list="$scan_staging/paths"

set +e
find "$search_root" \
  \( -path "$search_root/.git" -o -path "$search_root/upstream" \) -prune -o \
  \( -type f -o -type l \) -print0 > "$path_list"
find_status=$?
set -e
if (( find_status != 0 )); then
  echo "Secret scan traversal failed (find status ${find_status})." >&2
  exit "$find_status"
fi

while IFS= read -r -d '' path; do
  if [[ -L "$path" ]]; then
    echo "Secret scan refuses symbolic link: ${path}" >&2
    exit 2
  fi
  scan_path "$path"
done < "$path_list"
