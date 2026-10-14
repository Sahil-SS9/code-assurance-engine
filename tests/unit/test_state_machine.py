"""Unit tests for the assessment state machine and status vocabularies."""

from __future__ import annotations

import itertools

import pytest

from hermes_code_assurance import state


def test_states_and_statuses_are_declared():
    for candidate_state in (
        "CREATED", "INSPECTED", "CONTRACT_REVIEW_REQUIRED", "APPROVED", "RUNNING", "ASSESSED",
        "HANDOFF_READY", "AUTHORITY_REQUIRED", "EXECUTION_UNAVAILABLE", "INTERRUPTED",
        "BUDGET_STOPPED", "INVALIDATED", "FAILED", "CANCELLED",
    ):
        assert candidate_state in state.ASSESSMENT_STATES
    assert state.CHECK_STATUSES == [
        "PASSED", "FAILED", "UNKNOWN", "NOT_RUN", "INTERRUPTED", "UNSUPPORTED"
    ]
    assert state.OVERALL_STATUSES == [
        "ASSESSED_WITHIN_DECLARED_SCOPE", "FINDINGS_PRESENT", "INCOMPLETE", "INVALID_EVIDENCE"
    ]
    assert state.CLAIM_GRADES == ["observed", "reported", "inferred", "unknown"]


def test_optimistic_forward_path_transitions():
    path = ["CREATED", "INSPECTED", "CONTRACT_REVIEW_REQUIRED", "APPROVED", "RUNNING", "ASSESSED",
            "HANDOFF_READY"]
    for cur, nxt in itertools.pairwise(path):
        assert state.can_transition(cur, nxt)


def test_illegal_transitions_refused():
    assert not state.can_transition("CREATED", "RUNNING")
    assert not state.can_transition("RUNNING", "CREATED")
    assert not state.can_transition("ASSESSED", "APPROVED")
    assert not state.can_transition("HANDOFF_READY", "APPROVED")
    with pytest.raises(state.IllegalTransition):
        state.require_transition("CREATED", "RUNNING")


def test_reopen_and_stop_paths_available():
    assert state.can_transition("RUNNING", "INTERRUPTED")
    assert not state.can_transition("INSPECTED", "CANCELLED")

    # Unknown states must be refused loudly, never treated as valid.
    assert not state.can_transition("MADE_UP", "RUNNING")
    assert not state.can_transition("RUNNING", "MADE_UP")


def test_replaced_statuses_must_not_exist():
    for forbidden in ("SAFE", "SECURE", "READY_TO_MERGE", "PASS", "GREEN"):
        assert forbidden not in state.CHECK_STATUSES
        assert forbidden not in state.OVERALL_STATUSES


def test_handoff_not_worded_as_permission():
    assert state.HANDOFF_NOT_PERMISSION is True
