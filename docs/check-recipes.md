# Check recipes (v0.1.0)

Declaration-only, versioned, no shell strings. Static tools that load arbitrary project plugins
are NOT automatically safe: proposals start `executable: False` and execution requires the
authority+isolation gates.

## Supported parsers (frozen for v1)
- `junit-xml` — primary machine oracle. Ordered decisions in verify: producer-vs-counted
  reconciliation → zero-collected gap → nonzero-exit gap → failures vs reviewed allowed_failures
  → PASSED.
- `pytest-terminal` — best-effort, verbose-lines observed vs the summary line reported;
  missing summary → UNKNOWN; disagreement → UNKNOWN with a discrepancy surfaced.

## Decision (recorded, not hidden)
- NO JavaScript test runner in v0.1.0: "one explicitly supported JS runner" from the plan was
  NOT frozen; runner support stays pytest/JUnit only this revision. A repo with JS tests still
  inspects/assesses but its assurance stays incomplete (visible, never smoothing over).

## Refusal paths
- Unknown parser id → refuse (never guess).
- Zero collected tests, malformed XML, oversized input (>2000 testcases), missing summary:
  all UNKNOWN with explicit reasons — a green exit alone never clears them.
- All-skipped suites stay a visible gap (skip-visible in test-delta).
