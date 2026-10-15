"""C3 regression: run/verify state+receipt operations refuse-before-mutation or commit atomically.

Witnessed RED: the review probe reproduced crash-after-partial-write.
"""

from __future__ import annotations

import json

import pytest


def _setup(tmp_path):
    from hermes_code_assurance import service
    from hermes_code_assurance.contracts import parse_contract
    from hermes_code_assurance.store import AssessmentStore

    state = tmp_path / "state"
    candidate = tmp_path / "candidate"
    candidate.mkdir(parents=True)
    (candidate / "calc.py").write_text("x = 1\n")
    inspected = service.inspect_candidate(state, str(candidate))
    aid = inspected["assessment_id"]
    draft = inspected["proposed_contract_draft"]
    draft["required_checks"] = [
        {"check_id": "chk-a", "label": "suite a", "kind": "test-run",
         "argv": ["python", "-m", "pytest"], "cwd": ".", "parser_id": "junit-xml"},
        {"check_id": "chk-b", "label": "suite b", "kind": "test-run",
         "argv": ["python", "-m", "pytest"], "cwd": ".", "parser_id": "junit-xml"},
    ]
    frozen = parse_contract(draft)
    service.plan_checks(state, frozen.to_dict(), aid)
    store = AssessmentStore(state / "assessments.db")
    store.initialize()
    return service, store, aid, frozen


def test_run_before_owner_approval_refuses_without_mutation(tmp_path):
    service, store, aid, _contract = _setup(tmp_path)
    before = len(store.receipts(aid))
    state_before = store.get_assessment(aid)["state"]
    out = service.run_checks(state_path_of(tmp_path), aid, caller="cli:root")
    assert out["status"] == "NOT_APPROVED"
    assert len(store.receipts(aid)) == before, "refusal must not append receipts"
    assert store.get_assessment(aid)["state"] == state_before


def state_path_of(tmp_path):
    return tmp_path / "state"


def test_run_from_approved_is_atomic_interrupted_rollbacks_all(tmp_path, monkeypatch):
    service, store, aid, _contract = _setup(tmp_path)

    def approve():
        store.set_state(aid, "APPROVED", old_state=store.get_assessment(aid)["state"])

    approve()
    before = len(store.receipts(aid))

    from hermes_code_assurance.store import AssessmentStore as _S

    real_append = _S.append_receipt

    calls = {"n": 0}

    def exploding_append(self, assessment_id, payload):
        calls["n"] += 1
        if calls["n"] == 2:
            raise RuntimeError("simulated host crash between receipts")
        return real_append(self, assessment_id, payload)

    monkeypatch.setattr(_S, "append_receipt", exploding_append)
    with pytest.raises(RuntimeError):
        service.run_checks(state_path_of(tmp_path), aid, caller="cli:root")
    after = len(store.receipts(aid))
    assert after == before, "interrupted run must roll back partial receipt writes"
    assert store.get_assessment(aid)["state"] == "APPROVED", "no state change on crash"


def test_repeated_verify_idempotent_no_new_writes(tmp_path):
    service, store, aid, _contract = _setup(tmp_path)
    first = service.verify(tmp_path / "state", aid, caller="cli:root")
    first_payload = json.dumps(store.get_assessment(aid)["payload"], sort_keys=True)
    second = service.verify(tmp_path / "state", aid, caller="cli:root")
    assert first["overall_status"] == second["overall_status"]
    assert json.dumps(store.get_assessment(aid)["payload"], sort_keys=True) == first_payload
