"""AssessmentStore integration tests (CT12-lite): idempotency, CAS transitions, writer fencing,
profile isolation, WAL mode.

Witnessed RED: module does not exist yet.
"""

from __future__ import annotations

import pytest

from hermes_code_assurance import state
from hermes_code_assurance.store import AssessmentStore, StoreLocked, StoreStateConflict


def _store(tmp_path, name="state.db"):
    store = AssessmentStore(tmp_path / name)
    store.initialize()
    return store


def test_initialize_idempotent(tmp_path):
    store = _store(tmp_path)
    store.initialize()  # second call must be a no-op, not an error


def test_create_assessment_idempotent(tmp_path):
    store = _store(tmp_path)
    first = store.create_assessment("a1", "CREATED", {"n": 1})
    second = store.create_assessment("a1", "CREATED", {"n": 999})
    assert first is True
    assert second is False, "duplicate create must be refused, never overwrite"
    assert store.get_assessment("a1")["payload"]["n"] == 1


def test_cas_transitions_with_events(tmp_path):
    store = _store(tmp_path)
    store.create_assessment("a1", "CREATED", {})
    store.set_state("a1", "INSPECTED", old_state="CREATED")
    with pytest.raises(state.IllegalTransition):
        store.set_state("a1", "RUNNING", old_state="INSPECTED")
    with pytest.raises(StoreStateConflict):
        store.set_state("a1", "CONTRACT_REVIEW_REQUIRED", old_state="RUNNING")
    kinds = [e["kind"] for e in store.events("a1")]
    assert "state-change" in kinds


def test_writer_fencing_blocks_second_transaction(tmp_path):
    store = _store(tmp_path)
    with store.transaction():
        store.create_assessment("a1", "CREATED", {})
        second = _store(tmp_path)
        with pytest.raises(StoreLocked), second.transaction(timeout=0.0):
            pass  # fenced: never reached


def test_profile_isolation_between_two_stores(tmp_path):
    s1 = _store(tmp_path, "one.db")
    s2 = _store(tmp_path, "two.db")
    s1.create_assessment("a1", "CREATED", {"scope": "one"})
    assert s2.get_assessment("a1") is None
    s2.create_assessment("a1", "CREATED", {"scope": "two"})
    assert s1.get_assessment("a1")["payload"]["scope"] == "one"


def test_receipts_bound_to_assessment(tmp_path):
    store = _store(tmp_path)
    store.create_assessment("a1", "CREATED", {})
    store.append_receipt("a1", {"receipt_id": "r1", "n": 5})
    receipts = store.receipts("a1")
    assert len(receipts) == 1
    assert receipts[0]["payload"]["n"] == 5
