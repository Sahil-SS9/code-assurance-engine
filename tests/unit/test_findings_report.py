"""Findings, advisory-model handling and report wording tests (CT15-lite).

Witnessed RED: modules missing.
"""

from __future__ import annotations

import re

import pytest

from hermes_code_assurance import advisory, findings, report
from tests.green_helpers import build_clean_receipt, build_contract  # helper from F1 batch


def _failed_receipt():
    from hermes_code_assurance import evidence

    parser = evidence.parser_of(
        '<?xml version="1.0"?><testsuite tests="2" failures="1">'
        '<testcase name="t1"><failure message="boom"/></testcase>'
        '<testcase name="t2"/></testsuite>',
        "junit-xml",
    )
    receipt = build_clean_receipt(parser=parser, exit_code=1)
    return receipt


def test_failed_check_becomes_observed_finding():
    out = findings.deterministic_findings([_failed_receipt()], contract=build_contract())
    assert out.findings, "failed receipt must produce a finding"
    f = out.findings[0]
    assert f["provenance"] == "observed"
    assert f["severity"] == "high"
    assert f["evidence_refs"]["receipt_id"]


def test_no_findings_is_never_worded_safe():
    text = report.render_assessment(
        {"overall_status": "ASSESSED_WITHIN_DECLARED_SCOPE", "findings": [],
         "checks": [{"check_id": "unit-evidence", "status": "PASSED"}]},
        candidate_summary={"inventory_state": "complete"},
        contract=build_contract(),
    )
    assert "not a" in text.lower() or "no findings" in text.lower()
    assert re.search(r"empty findings is not|findings does not|no findings (?:is|=|means)", text.lower())


def test_empty_findings_explicit_warning_in_report():
    text = report.render_assessment(
        {"overall_status": "ASSESSED_WITHIN_DECLARED_SCOPE", "findings": [], "checks": []},
        candidate_summary={"inventory_state": "complete"},
        contract=build_contract(),
    )
    assert "no findings were produced" in text.lower()
    assert "is not" in text.lower() or "does not mean" in text.lower()


def test_report_escapes_html_in_paths():
    text = report.render_assessment(
        {"overall_status": "INCOMPLETE", "findings": [], "checks": [],
         "candidate": {"repo_root": "<script>alert(1)</script>"}},
        candidate_summary={"inventory_state": "partial"},
        contract=build_contract(),
    )
    assert "<script>" not in text
    assert "&lt;script&gt;" in text


def test_exact_totals_in_report():
    text = report.render_assessment(
        {"overall_status": "INCOMPLETE", "findings": [], "checks": [
            {"check_id": "c1", "status": "UNKNOWN"}, {"check_id": "c2", "status": "NOT_RUN"},
        ]},
        candidate_summary={"inventory_state": "complete"},
        contract=build_contract(),
    )
    assert "UNKNOWN: 1" in text and "NOT_RUN: 1" in text


def test_advisory_model_validated_and_labelled():
    good = advisory.AdvisoryModel(lambda instructions, **kw: {"summary": "looks risky"})
    out = good.propose({"x": 1})
    assert out["provenance"] == "advisory"
    assert out["summary"] == "looks risky"


def test_advisory_bad_schema_refused_not_passed_through():
    bad = advisory.AdvisoryModel(lambda instructions, **kw: {"summary": 123, "extras": "x"})
    with pytest.raises(advisory.AdvisoryRefusal):
        bad.propose({"x": 1})


def test_advisory_failure_is_visible_not_swallowed():
    failing = advisory.AdvisoryModel(lambda instructions, **kw: None)
    out = advisory.render_advisory_if_any(failing, {"x": 1})
    assert out["provenance"] == "advisory-unavailable"
    assert "unavailable" in out["note"].lower()


def test_report_run_never_auto_applies_anything():
    text = report.render_assessment(
        {"overall_status": "INCOMPLETE", "findings": [], "checks": []},
        candidate_summary={"inventory_state": "complete"},
        contract=build_contract(),
    )
    assert "not automatically applied" in text or "no automatic" in text.lower()
