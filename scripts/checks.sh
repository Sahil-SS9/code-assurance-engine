#!/usr/bin/env bash
# Owned evidence gate — run from a checkout with uv available.
# Witnessed reds, clean negatives and exact totals are the claim of record, never prose.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== ruff =="
uv run ruff check .

echo "== unit + adversarial =="
uv run python -m pytest tests/unit tests/adversarial --strict-markers -q

echo "== integration =="
uv run python -m pytest tests/integration --strict-markers -q

echo "== host + platform (expected: skip, recorded blockers) =="
uv run python -m pytest tests/host tests/platform --strict-markers -q

echo "== manifest validation (read-only catalog gate) =="
hermes plugins validate "$(pwd)" --json || hermes plugins validate "$(pwd)"
