"""C5 regression: production paths never trust self-supplied collector strings; synthetic
fixtures cannot clear assurance without authenticated provenance; completion claims honest.

Round-2 scope (recheck be462d7): absent, null, EMPTY and invented-NON-NULL grant references —
spelling must not matter; only independently verified authority proves provenance, and none
exists in this build. Kernel positive control stays a separately labelled test-owned check.
"""

from __future__ import annotations

import pytest

GRANT_VARIANTS = [
    pytest.param(None, id="null-grant"),
    pytest.param("", id="empty-grant"),
    pytest.param("made-up-grant-reference", id="made-up-grant"),
    pytest.param("auth-grant-id-not-issued-by-any-route", id="invented-real-looking-grant"),
]


def _build_case(tmp_path, grant_ref):
    from hermes_code_assurance import service
    from hermes_code_assurance.contracts import parse_contract
    from hermes_code_assurance.evidence import argv_digest_for, env_digest_for, receipt_id
    from hermes_code_assurance.store import AssessmentStore

    state = tmp_path / "state"
    candidate = tmp_path / "candidate"
    candidate.mkdir(parents=True)
    (candidate / "calc.py").write_text("x = 1\n")
    inspected = service.inspect_candidate(state, str(candidate))
    aid = inspected["assessment_id"]

    draft = dict(inspected["proposed_contract_draft"])
    draft["required_checks"] = [
        {"check_id": "chk-trust", "label": "one", "kind": "test-run",
         "argv": ["python", "-m", "pytest"], "cwd": ".", "parser_id": "junit-xml"}
    ]
    frozen = parse_contract(draft)
    service.plan_checks(state, frozen.to_dict(), aid)

    payload = AssessmentStore(state / "assessments.db").get_assessment(aid)["payload"]
    receipt = {
        "status": "PASSED", "check_id": "chk-trust", "attempt": 1,
        "candidate_digest": payload["inventory_digest"], "contract_id": frozen.contract_id,
        "argv_digest": argv_digest_for(["python", "-m", "pytest"]),
        "env_digest": env_digest_for(frozen.env_allowlist),
        "caller": "cli:root", "collector": "evaluator-owned-collector-boxed",
        "grant_ref": grant_ref,
        "observation_origin": "attacker-written-string",
        "counts": {"collected": 1, "passed": 1, "failed": 0, "errors": 0, "skipped": 0},
        "parser": {"id": "junit-xml", "version_stamp": "1", "status_hint": "clean",
                   "discrepancies": [], "reasons": []},
        "observed": {"exit_code": 0, "signal": None}, "artifacts": [], "flags": [],
        "created_at": "2026-10-15T00:00:00Z",
    }
    receipt["receipt_id"] = receipt_id(receipt)
    return state, aid, receipt


@pytest.mark.parametrize("grant_ref", GRANT_VARIANTS, ids=[p.id for p in GRANT_VARIANTS])
def test_public_verify_never_clears_unauthenticated_receipt(tmp_path, grant_ref):
    """Every spelling of grant_ref (absent/null/empty/invented-non-null) stays UNKNOWN at the
    public seam — a receipt's own fields cannot mint provenance in this build."""
    from hermes_code_assurance import service
    from hermes_code_assurance.store import AssessmentStore

    state, aid, receipt = _build_case(tmp_path, grant_ref)
    store = AssessmentStore(state / "assessments.db")
    store.append_receipt(aid, receipt)

    verified = service.verify(state, aid, caller="cli:root")
    check_result = next(r for r in verified["verification"] if r["check_id"] == "chk-trust")
    assert check_result["status"] != "PASSED", (
        "unauthenticated receipt must stay UNKNOWN no matter how grant_ref is spelled"
    )
    assert check_result["status"] == "UNKNOWN"
    assert any("provenance" in str(note).lower() for note in check_result["notes"])
    assert verified["overall_status"] == "INCOMPLETE"
    assert "chk-trust" in verified.get("missing_required", [])


def test_kernel_positive_control_labelled_testowned():
    """TEST-OWNED kernel seam (NOT the public production path): reverify accepts a synthetic
    receipt that carries the explicit trusted-collector identity, proving the verdict mechanics
    retain the ability to pass valid fixture observations. Labelled and isolated on purpose."""
    from hermes_code_assurance import evidence
    from hermes_code_assurance.verify import reverify
    from tests.green_helpers import build_clean_receipt, build_contract

    parser = evidence.parser_of(
        '<?xml version="1.0"?><testsuite tests="1"><testcase name="ok"/></testsuite>',
        "junit-xml",
    )
    receipt = build_clean_receipt(parser=parser)
    verified = reverify(
        receipt, contract=build_contract(), candidate_digest="a" * 64, caller="cli:root",
        trusted_collector_id="evaluator-owned-collector-boxed",
    )
    assert verified.status == "PASSED"
