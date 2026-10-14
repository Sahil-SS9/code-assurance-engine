"""Parser tests (CT06-lite): supported-version fixtures match the counted truth; corrupt, empty
and contradictory inputs surface UNKNOWN — never guessed PASS.

Witnessed RED: parsers package does not exist yet.
"""

from __future__ import annotations

from hermes_code_assurance import parsers

JUNIT_OK = """<?xml version="1.0" encoding="utf-8"?>
<testsuites>
  <testsuite name="suite-a" tests="2" failures="0" errors="0" skipped="1">
    <testcase classname="pkg.test_a" name="test_one" time="0.001"/>
    <testcase classname="pkg.test_a" name="test_two" time="0.002">
      <skipped message="not today">ignored</skipped>
    </testcase>
  </testsuite>
  <testsuite name="suite-b" tests="3" failures="1" errors="0" skipped="0">
    <testcase classname="pkg.test_b" name="test_three" time="0.001"/>
    <testcase classname="pkg.test_b" name="test_four" time="0.001">
      <failure message="boom">trace...</failure>
    </testcase>
    <testcase classname="pkg.test_b" name="test_five" time="0.001"/>
  </testsuite>
</testsuites>
"""

JUNIT_ATTR_MISMATCH = """<?xml version="1.0"?>
<testsuite name="lying" tests="7" failures="0" errors="0" skipped="0">
  <testcase classname="c" name="t1"/>
  <testcase classname="c" name="t2"/>
  <testcase classname="c" name="t3"/>
</testsuite>
"""


def outcome_of(text):
    return parsers.junit_xml.parse_text(text)


def test_valid_junit_counts_children():
    out = outcome_of(JUNIT_OK)
    assert out.parser_id == "junit-xml"
    assert out.counts == {"collected": 5, "passed": 3, "failed": 1, "errors": 0, "skipped": 1}
    assert out.status_hint == "clean"
    assert out.discrepancies == []


def test_corrupt_xml_is_unknown_not_pass():
    out = outcome_of("<testsuite><testcase>")
    assert out.status_hint == "unknown"
    assert "xml-parse-failed" in out.reasons[0]


def test_empty_input_is_unknown():
    out = outcome_of("")
    assert out.status_hint == "unknown"


def test_zero_tests_is_unknown():
    out = outcome_of('<?xml version="1.0"?>\n<testsuite name="x" tests="0"/>')
    assert out.status_hint == "unknown"
    assert any("zero-tests" in r for r in out.reasons)


def test_attr_totals_lying_is_surfaced_not_reconciled():
    out = outcome_of(JUNIT_ATTR_MISMATCH)
    assert out.status_hint == "unknown"
    assert out.discrepancies, "contradiction between totals attribute and children must surface"
    assert out.counts["collected"] == 3, "counted children are observed truth, not the report"


def test_oversized_input_refused():
    big = "<testsuite>" + "<testcase/>" * 4000 + "</testsuite>"
    out = outcome_of(big)
    assert out.status_hint == "unknown"
    assert any("too-many" in r for r in out.reasons)


PYTEST_OK = """collected 3 items

test_calc.py::test_add PASSED
test_calc.py::test_sub PASSED
test_other.py::test_fail FAILED

============ 2 passed, 1 failed in 0.07s ============
"""

PYTEST_NO_SUMMARY = "collected 2 items\n\ntest_x.py::test_a PASSED\n"


def test_pytest_terminal_clean_counts():
    out = parsers.pytest_terminal.parse_text(PYTEST_OK)
    assert out.parser_id == "pytest-terminal"
    assert out.counts["passed"] == 2
    assert out.counts["failed"] == 1
    assert out.status_hint == "clean"


def test_pytest_summary_missing_is_unknown():
    out = parsers.pytest_terminal.parse_text(PYTEST_NO_SUMMARY)
    assert out.status_hint == "unknown"


def test_pytest_garbage_is_unknown():
    out = parsers.pytest_terminal.parse_text("nothing useful here")
    assert out.status_hint == "unknown"


def test_registry_lists_supported_parsers():
    assert set(parsers.registry().keys()) >= {"junit-xml", "pytest-terminal"}
