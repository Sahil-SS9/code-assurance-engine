"""C1 regression: verdict honesty — all-skipped / short collections / missing required checks.

Witnessed RED against the frozen base (review probes reproduced all cases first).
"""

from __future__ import annotations

from hermes_code_assurance import evidence
from hermes_code_assurance.verify import reverify
from tests.green_helpers import build_clean_receipt, build_contract


def _fixture(xml: str, contract=None):
    parser = evidence.parser_of(xml, "junit-xml")
    if contract is None:
        return build_clean_receipt(parser=parser), parser
    from tests.green_helpers import build_clean_receipt as b

    return b(parser=parser, contract=contract), parser


def _fixture_under_contract(xml: str, contract):
    return _fixture(xml, contract=contract)


def test_all_skipped_required_suite_does_not_pass():
    receipt, _ = _fixture(
        '<testsuite tests="1" skipped="1"><testcase name="s"><skipped/></testcase></testsuite>'
    )
    verified = reverify(
        receipt, contract=build_contract(), candidate_digest="a" * 64, caller="cli:root"
    )
    assert verified.status != "PASSED"
    assert verified.status in ("UNKNOWN", "INVALID_EVIDENCE")
    assert any("skipped" in note.lower() for note in verified.notes)


def test_short_collection_vs_expected_does_not_pass():
    from hermes_code_assurance.contracts import parse_contract

    body = build_contract().to_dict()
    body.pop("contract_id")  # identity will change with the expected-collection override
    contract = parse_contract(
        {
            **body,
            "required_checks": [
                {
                    "check_id": "unit-evidence",
                    "label": "evidence demo suite",
                    "kind": "test-run",
                    "argv": ["python", "-m", "pytest", "-q"],
                    "cwd": ".",
                    "parser_id": "junit-xml",
                    "expected_collection": {"tests": 2},
                }
            ],
        }
    )
    receipt, _ = _fixture_under_contract(
        '<testsuite tests="1"><testcase name="only-one"/></testsuite>', contract
    )
    verified = reverify(
        receipt, contract=contract, candidate_digest="a" * 64, caller="cli:root"
    )
    assert verified.status != "PASSED"
    assert verified.status == "UNKNOWN"
    assert any("collected" in note.lower() and "expected" in note.lower()
               for note in verified.notes)


def test_positive_control_still_passes():
    receipt, _ = _fixture('<testsuite tests="1"><testcase name="ok"/></testsuite>')
    verified = reverify(
        receipt, contract=build_contract(), candidate_digest="a" * 64, caller="cli:root"
    )
    assert verified.status == "PASSED", verified.notes


def test_service_missing_required_check_cannot_clear_overall(tmp_path):
    """Probe reproduction at the public service seam: one receipt, two required checks."""
    from hermes_code_assurance import service
    from hermes_code_assurance.store import AssessmentStore

    state = tmp_path / "state"
    candidate = tmp_path / "candidate"
    candidate.mkdir(parents=True)
    (candidate / "calc.py").write_text("x = 1\n")
    inspected = service.inspect_candidate(state, str(candidate))
    aid = inspected["assessment_id"]

    from hermes_code_assurance.contracts import parse_contract

    draft = inspected["proposed_contract_draft"]
    draft["goal"] = "review: explicit two-check contract"
    draft["env_allowlist"] = ["PATH", "LANG"]
    draft["required_checks"] = [
        {"check_id": "chk-x", "label": "synthetic", "kind": "test-run",
         "argv": ["python", "-m", "pytest"], "cwd": ".", "parser_id": "junit-xml",
         "expected_collection": {"tests": 1}},
        {"check_id": "chk-y", "label": "synthetic-2", "kind": "test-run",
         "argv": ["python", "-m", "pytest", "-q"], "cwd": ".", "parser_id": "junit-xml",
         "expected_collection": {"tests": 1}},
    ]
    frozen = parse_contract(draft)
    planned = service.plan_checks(state, frozen.to_dict(), aid)


    store = AssessmentStore(state / "assessments.db")
    store.initialize()
    stored = store.get_assessment(aid)["payload"]
    from hermes_code_assurance.evidence import (
        argv_digest_for,
        env_digest_for,
        receipt_id,
    )
    receipt = {
        "status": "UNKNOWN", "check_id": "chk-x", "attempt": 1,
        "candidate_digest": stored["inventory_digest"], "contract_id": frozen.contract_id,
        "argv_digest": argv_digest_for(["python", "-m", "pytest"]),
        "env_digest": env_digest_for(frozen.env_allowlist),
        "caller": "cli:root", "collector": "evaluator-owned-collector-boxed",
        "grant_ref": None,
        "observation_origin": "synthetic-review-fixture-not-real-execution",
        "counts": {"collected": 1, "passed": 1, "failed": 0, "errors": 0, "skipped": 0},
        "parser": {"id": "junit-xml", "version_stamp": "1", "status_hint": "clean",
                   "discrepancies": [], "reasons": []},
        "observed": {"exit_code": 0, "signal": None}, "artifacts": [], "flags": [],
        "created_at": "2026-10-15T00:00:00Z",
    }
    receipt["receipt_id"] = receipt_id(receipt)
    store.append_receipt(aid, receipt)

    verified = service.verify(state, aid, caller="cli:root")
    assert verified["overall_status"] != "ASSESSED_WITHIN_DECLARED_SCOPE"
    assert verified["overall_status"] == "INCOMPLETE"
    assert "chk-y" in verified.get("missing_required", [])
    assert planned["contract_id"] == frozen.contract_id
