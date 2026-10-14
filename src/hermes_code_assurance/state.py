"""Assessment state machine and status vocabularies (single source of truth in code).

Grades follow evidence-honest-diagnostics: observed/reported/inferred/unknown, never upgraded.
"""

from __future__ import annotations

ASSESSMENT_STATES = [
    "CREATED", "INSPECTED", "CONTRACT_REVIEW_REQUIRED", "APPROVED", "RUNNING", "ASSESSED",
    "HANDOFF_READY", "AUTHORITY_REQUIRED", "EXECUTION_UNAVAILABLE", "INTERRUPTED",
    "BUDGET_STOPPED", "INVALIDATED", "FAILED", "CANCELLED",
]

_CHECK_STATUSES = ["PASSED", "FAILED", "UNKNOWN", "NOT_RUN", "INTERRUPTED", "UNSUPPORTED"]

_OVERALL = [
    "ASSESSED_WITHIN_DECLARED_SCOPE", "FINDINGS_PRESENT", "INCOMPLETE", "INVALID_EVIDENCE"
]

CLAIM_GRADES = ["observed", "reported", "inferred", "unknown"]
CHECK_STATUSES = _CHECK_STATUSES
OVERALL_STATUSES = _OVERALL

HANDOFF_NOT_PERMISSION = True  # HANDOFF_READY is never approval to apply/merge/deploy

_ALLOWED: set[tuple[str, str]] = {
    ("CREATED", "INSPECTED"),
    ("CREATED", "CANCELLED"),
    ("INSPECTED", "CONTRACT_REVIEW_REQUIRED"),
    ("INSPECTED", "INVALIDATED"),
    ("CONTRACT_REVIEW_REQUIRED", "APPROVED"),
    ("APPROVED", "RUNNING"),
    ("APPROVED", "AUTHORITY_REQUIRED"),
    ("APPROVED", "EXECUTION_UNAVAILABLE"),
    ("AUTHORITY_REQUIRED", "RUNNING"),
    ("AUTHORITY_REQUIRED", "CANCELLED"),
    ("EXECUTION_UNAVAILABLE", "RUNNING"),
    ("EXECUTION_UNAVAILABLE", "CANCELLED"),
    ("RUNNING", "INTERRUPTED"),
    ("RUNNING", "BUDGET_STOPPED"),
    ("RUNNING", "FAILED"),
    ("RUNNING", "CANCELLED"),
    ("RUNNING", "ASSESSED"),
    ("INTERRUPTED", "RUNNING"),
    ("INTERRUPTED", "CANCELLED"),
    ("BUDGET_STOPPED", "RUNNING"),
    ("FAILED", "RUNNING"),
    ("FAILED", "CANCELLED"),
    ("FAILED", "INVALIDATED"),
    ("ASSESSED", "HANDOFF_READY"),
    ("ASSESSED", "INVALIDATED"),
}


class IllegalTransition(ValueError):
    """Transition outside the allowed state graph."""


def can_transition(cur: str, nxt: str) -> bool:
    """False when either state is unknown or the edge is not declared — never permissive."""
    if cur not in ASSESSMENT_STATES or nxt not in ASSESSMENT_STATES:
        return False
    return (cur, nxt) in _ALLOWED


def require_transition(cur: str, nxt: str) -> None:
    if not can_transition(cur, nxt):
        raise IllegalTransition(f"illegal assessment transition: {cur!r} -> {nxt!r}")
