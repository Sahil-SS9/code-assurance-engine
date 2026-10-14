"""pytest terminal-output parser (secondary, best-effort, explicitly honest).

The final summary line is the producer's claim; per-test verbose lines are the observation.
When the summary and the counted lines disagree — or the summary is missing — the outcome is
UNKNOWN with the discrepancy recorded. For machine-oracle guarantees use JUnit XML.
"""

from __future__ import annotations

import re

from . import ParseOutcome

_TEST_LINE = re.compile(
    r"^(?:[^\s:]+\)::)?[^\s:]+::[^\s]+\s+(PASSED|FAILED|ERROR|XFAIL|SKIPPED|S)\s*$"
)
_COUNT_TOKEN = re.compile(r"(\d+)\s+(passed|failed|errors?|skipped|deselected|xfailed|error)")


def parse_text(text: str) -> ParseOutcome:
    lines = [ln.strip() for ln in text.splitlines()]
    test_lines = [ln for ln in lines if _TEST_LINE.match(ln)]
    summary_text = next(
        (
            ln
            for ln in reversed(lines)
            if re.search(r"passed|failed|error|skipped", ln)
            and ln.strip("=").strip()
            and re.search(r"\d", ln)
        ),
        None,
    )
    if not summary_text:
        return ParseOutcome("pytest-terminal", {}, "unknown", ["summary-line-missing"])

    counts = {"passed": 0, "failed": 0, "errors": 0, "skipped": 0}
    for value, label in _COUNT_TOKEN.findall(summary_text):
        if label.startswith("error"):
            counts["errors"] += int(value)
        else:
            counts[label] += int(value)

    observed = {"passed": 0, "failed": 0, "errors": 0, "skipped": 0}
    for line in test_lines:
        token = _TEST_LINE.match(line).group(1)  # type: ignore[union-attr]
        if token == "PASSED":
            observed["passed"] += 1
        elif token in ("FAILED", "ERROR"):
            observed["failed" if token == "FAILED" else "errors"] += 1
        else:
            observed["skipped"] += 1

    discrepancies = [
        f"summary says '{label}'={claimed} but observed {observed.get(label, 0)}"
        for label in ("passed", "failed", "skipped")
        if (claimed := counts.get(label, 0)) and claimed != observed.get(label, 0)
        and observed.get(label, 0) > 0
    ]
    reasons = []
    if not test_lines:
        reasons.append("no-per-test-lines-observed")

    status_hint = "unknown" if (discrepancies or reasons) else "clean"
    return ParseOutcome("pytest-terminal", {**counts}, status_hint, reasons, discrepancies)
