"""JUnit XML parser (collector-owned fixture parsing).

Semantics: counted <testcase> children are the observed truth; totals attributes are the
producer's report. A contradiction surfaces as a discrepancy (status unknown) — it is never
silently reconciled. Zero collected tests, empty input, oversized inputs, malformed XML: all
UNKNOWN with explicit reasons.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET

from ..parsers import ParseOutcome

MAX_BYTES = 4_000_000
MAX_TESTCASES = 2000  # bounded parsing; overflow surfaces as UNKNOWN, never a guessed count

_FAIL_TAGS = {"failure", "error"}
_SKIP_TAGS = {"skipped"}


def parse_text(text: str) -> ParseOutcome:
    raw = text.encode("utf-8")
    if len(raw) > MAX_BYTES:
        return ParseOutcome(
            "junit-xml", {}, "unknown",
            reasons=[f"input-too-large: {len(raw)}>{MAX_BYTES} (junit too-large guard)"],
        )
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as exc:
        return ParseOutcome(
            "junit-xml", {}, "unknown", reasons=[f"xml-parse-failed: {exc.msg}"]
        )
    tag = _tag(root)
    if tag == "testsuite":
        suites = [root]
    elif tag == "testsuites":
        suites = list(root.iter("testsuite"))
    else:
        suites = []
    if not suites:
        return ParseOutcome("junit-xml", {}, "unknown", reasons=["no testsuite element"])

    counts = {"collected": 0, "passed": 0, "failed": 0, "errors": 0, "skipped": 0}
    discrepancies: list[str] = []
    for suite in suites:
        suite_tests = suite.get("tests", None)
        suite_fail = int(suite.get("failures", 0) or 0)
        suite_err = int(suite.get("errors", 0) or 0)
        suite_skip = int(suite.get("skipped", 0) or 0)
        counted = {"failed": 0, "errors": 0, "skipped": 0, "passed": 0}
        for child in suite:
            if _tag(child) != "testcase":
                continue
            counts["collected"] += 1
            outcome_tags = {_tag(g) for g in child}
            if outcome_tags & _FAIL_TAGS:
                counts["failed"] += 1
                counted["failed"] += 1
            elif outcome_tags & _SKIP_TAGS:
                counts["skipped"] += 1
                counted["skipped"] += 1
            else:
                counts["passed"] += 1
                counted["passed"] += 1
        suite_collected = counted["passed"] + counted["failed"] + counted["errors"] + counted["skipped"]
        if suite_tests is not None and int(suite_tests) != suite_collected:
            discrepancies.append(
                f"suite {suite.get('name', '?')}: counted tests={suite_collected} "
                f"but 'tests' attribute says {suite_tests}"
            )
        for label, counted_value, reported in (
            ("failures", counted["failed"], suite_fail),
            ("errors", counted["errors"], suite_err),
            ("skipped", counted["skipped"], suite_skip),
        ):
            if counted_value != reported:
                discrepancies.append(
                    f"suite {suite.get('name', '?')}: counted {label}={counted_value} "
                    f"but attribute says {reported}"
                )

    if counts["collected"] == 0:
        return ParseOutcome(
            "junit-xml", counts, "unknown", ["zero-tests-collected-must-stay-visible"],
            discrepancies,
        )
    if counts["collected"] > MAX_TESTCASES:
        return ParseOutcome(
            "junit-xml", counts, "unknown",
            [f"too-many-testcases: {counts['collected']}>{MAX_TESTCASES}"],
            discrepancies,
        )
    return ParseOutcome(
        "junit-xml", counts,
        "unknown" if discrepancies else "clean",
        [],
        discrepancies,
    )


def _tag(element) -> str:
    return element.tag.rsplit("}", 1)[-1] if "}" in element.tag else element.tag
