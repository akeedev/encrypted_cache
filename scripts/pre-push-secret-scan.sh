#!/usr/bin/env bash
set -euo pipefail

if [[ "${SECRET_SCAN_ALLOW:-}" == "1" ]]; then
  exit 0
fi

empty_tree="4b825dc642cb6eb9a060e54bf8d69288fbee4904"

patterns=(
  '-----BEGIN (RSA|EC|OPENSSH|PRIVATE) KEY-----'
  'AKIA[0-9A-Z]{16}'
  'ASIA[0-9A-Z]{16}'
  'ghp_[A-Za-z0-9]{36}'
  'github_pat_[A-Za-z0-9_]{22,}'
  'xox[baprs]-[A-Za-z0-9-]{10,}'
  '\bIBAN\b|\b[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}\b'
  '\bISIN\b|\b[A-Z]{2}[A-Z0-9]{9}[0-9]\b'
  '\bBearer[[:space:]]+[A-Za-z0-9._-]{10,}\b'
  'Authorization:[[:space:]]*Bearer[[:space:]]+[A-Za-z0-9._-]{10,}'
)

pattern_file=$(mktemp)
trap 'rm -f "$pattern_file"' EXIT
printf '%s\n' "${patterns[@]}" > "$pattern_file"

had_matches=0

scan_range() {
  local range="$1"

  # Extract added lines with file context.
  git diff --no-color --unified=0 --diff-filter=AM --text "$range" | \
    awk '
      /^diff --git/ {
        file=$4; sub(/^b\//, "", file);
        next
      }
      /^\+\+\+/ {next}
      /^@@/ {next}
      /^\+/ {print file ":" substr($0,2)}
    ' | \
    grep -nE -i -f "$pattern_file" || true
}

if [ -t 0 ]; then
  # No refs on stdin (should be rare); fall back to scanning HEAD.
  ranges=("${empty_tree}..HEAD")
else
  ranges=()
  while read -r local_ref local_sha remote_ref remote_sha; do
    if [[ -z "${local_sha:-}" || -z "${remote_sha:-}" ]]; then
      continue
    fi
    if [[ "$local_sha" =~ ^0+$ ]]; then
      continue  # deleted ref
    fi
    if [[ "$remote_sha" =~ ^0+$ ]]; then
      ranges+=("${empty_tree}..${local_sha}")
    else
      ranges+=("${remote_sha}..${local_sha}")
    fi
  done
fi

if [ ${#ranges[@]} -eq 0 ]; then
  exit 0
fi

for range in "${ranges[@]}"; do
  matches=$(scan_range "$range")
  if [[ -n "$matches" ]]; then
    if [[ $had_matches -eq 0 ]]; then
      echo "Potential secrets or bank identifiers detected in changes to be pushed:" >&2
      echo >&2
    fi
    echo "$matches" >&2
    had_matches=1
  fi
done

if [[ $had_matches -ne 0 ]]; then
  echo >&2
  echo "Push blocked. Remove/redact the matches, or re-run with SECRET_SCAN_ALLOW=1 to bypass once." >&2
  exit 1
fi

exit 0
