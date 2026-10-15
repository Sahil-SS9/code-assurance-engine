"""C5 regression: production paths never trust self-supplied collector strings; synthetic
fixtures cannot clear assurance without authenticated provenance; completion claims honest.

Witnessed RED: review showed self-digest receipts with self-set collector names clearing status.
"""

from __future__ import annotations


def test_public_verify_rejects_unauthenticated_receipts(tmp_path):
    from hermes_code_assurance import service
    from hermes_code_assurance.contracts import parse_contract
    from hermes_code_assurance.evidence import (
        argv_digest_for,
        env_digest_for,
        receipt_id,
    )
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

    # Synthetic receipt with a RECOMPUTED self-consistent digest and self-stamped collector id:
    # nothing about this proves authentic collection.
    AssessmentStore(state / "assessments.db").initialize() or None
    store = AssessmentStore(state / "assessments.db")
    payload = store.get_assessment(aid)["payload"]
    receipt = {
        "status": "PASSED", "check_id": "chk-trust", "attempt": 1,
        "candidate_digest": payload["inventory_digest"], "contract_id": frozen.contract_id,
        "argv_digest": argv_digest_for(["python", "-m", "pytest"]),
        "env_digest": env_digest_for(frozen.env_allowlist),
        "caller": "cli:root", "collector": "evaluator-owned-collector-boxed",
        "grant_ref": None,
        "observation_origin": "attacker-written-string",
        "counts": {"collected": 1, "passed": 1, "failed": 0, "errors": 0, "skipped": 0},
        "parser": {"id": "junit-xml", "version_stamp": "1", "status_hint": "clean",
                   "discrepancies": [], "reasons": []},
        "observed": {"exit_code": 0, "signal": None}, "artifacts": [], "flags": [],
        "created_at": "2026-10-15T00:00:00Z",
    }
    receipt["receipt_id"] = receipt_id(receipt)
    store.append_receipt(aid, receipt)

    verified = service.verify(state, aid, caller="cli:root")
    assert verified["overall_status"] == "INCOMPLETE", (
        "a self-stamped collector string cannot carry production acceptance"
    )
    assert any("provenance" in note.get("note", "").lower() or
               "provenance" in str(note).lower()
               for note in (verified.get("reasons") or verified.get("verification", [])))