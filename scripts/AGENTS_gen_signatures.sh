#!/usr/bin/env bash
# Generate doc/AGENTS_api_signatures.txt for encrypted_cache.
# Usage: bash scripts/AGENTS_gen_signatures.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

OUTPUT="${REPO_ROOT}/doc/AGENTS_api_signatures.txt"

echo "Generating API signatures for encrypted_cache..."
cd "${REPO_ROOT}"
uv run python scripts/AGENTS_gen_signatures.py > "${OUTPUT}"

LINE_COUNT=$(wc -l < "${OUTPUT}")
echo "Written ${LINE_COUNT} lines to ${OUTPUT}"
