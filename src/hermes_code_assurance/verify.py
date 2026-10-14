"""Reverify: recompute the assessment from immutable receipt observations.

Grades follow evidence-honest-diagnostics: counted children are observed; totals attributes are
reported; contradictions surface — they are never silently reconciled. Structural mismatches
(caller/attempt/candidate/contract/collector/integrity) invalidate the receipt outright.
Decision order: producer-vs-counted discrepancies → zero-collected gap → nonzero-exit gap →
observed failures against the reviewed oracle → else PASSED.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .authority import argv_digest as argv_digest_for
from .authority import env_digest as env_digest_for
from .evidence import TRUSTED_ID, EvidenceTampered, assert_receipt_integrity


@dataclass
class VerifiedOutcome:
    status: str  # PASSED | FAILED | UNKNOWN | INVALID_EVIDENCE | NOT_RUN
    notes: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"status": self.status, "notes": self.notes}


def _invalid(note: str) -> VerifiedOutcome:
    return VerifiedOutcome("INVALID_EVIDENCE", [note])


def _allowed_failures(contract, check_id: str) -> int:
    spec = next((c for c in contract.required_checks if c.check_id == check_id), None)
    if spec is None:
        spec = next((c for c in contract.optional_checks if c.check_id == check_id), None)
    return int(spec.oracle_allowed_failures or 0) if spec else 0


def reverify(
    receipt: dict,
    *,
    contract,
    candidate_digest: str,
    caller: str,
    trusted_collector_id: str = TRUSTED_ID,
    expected_attempt: int = 1,
) -> VerifiedOutcome:
    """Recompute trust in one receipt against the frozen contract and current identity params."""
    if receipt.get("collector") != trusted_collector_id:
        return _invalid(f"collector identity {receipt.get('collector')!r} is not trusted")

    notes = []
    if receipt.get("candidate_digest") != candidate_digest:
        return _invalid("cross-candidate recycling: candidate digest differs")

    if receipt.get("attempt") != expected_attempt:
        notes.append(f"attempt mismatch: {receipt.get('attempt')} != {expected_attempt}")

    if receipt.get("contract_id") != contract.contract_id:
        notes.append("contract id mismatch (receipt written against a different contract)")
    else:
        spec = next(
            (c for c in contract.required_checks if c.check_id == receipt.get("check_id")), None
        )
        if spec is None:
            notes.append("check id not in contract required checks")
        else:
            if receipt.get("argv_digest") != argv_digest_for(spec.argv):
                notes.append("argv digest does not match contract")
            if receipt.get("env_digest") != env_digest_for(contract.env_allowlist):
                notes.append("env digest does not match contract")

    if receipt.get("caller") != caller:
        notes.append(f"caller identity mismatch: {receipt.get('caller')!r} != {caller!r}")

    if notes:
        return VerifiedOutcome("INVALID_EVIDENCE", notes)

    try:
        assert_receipt_integrity(receipt)
    except EvidenceTampered as exc:
        return VerifiedOutcome("INVALID_EVIDENCE", [str(exc)])

    counts = receipt.get("counts") or {}
    if not counts:
        return VerifiedOutcome("NOT_RUN", ["no observation recorded: counts absent"])

    discrepancies = list(receipt.get("parser", {}).get("discrepancies") or [])
    if receipt.get("parser", {}).get("status_hint") == "unknown":
        reasons = list(receipt.get("parser", {}).get("reasons") or [])
        first = discrepancies[0] if discrepancies else (reasons[0] if reasons else "unknown")
        return VerifiedOutcome(
            "UNKNOWN",
            [f"producer-vs-counted discrepancy surfaced (cannot reconcile): {first}"],
        )
    if discrepancies:
        return VerifiedOutcome(
            "UNKNOWN", [f"producer-vs-counted discrepancy surfaced: {discrepancies[0]}"]
        )

    collected = counts.get("collected")
    if not collected:
        return VerifiedOutcome("UNKNOWN", ["zero-test collection stays a visible gap"])

    if (receipt.get("observed") or {}).get("exit_code") != 0:
        return VerifiedOutcome("UNKNOWN", ["nonzero process exit stays a visible gap"])

    failed = (counts.get("failed") or 0) + (counts.get("errors") or 0)
    if failed > _allowed_failures(contract, receipt["check_id"]):
        return VerifiedOutcome(
            "FAILED", [(f"observed failures/errors {failed} > allowed "
                       f"{_allowed_failures(contract, receipt['check_id'])}")]
        )

    notes = []
    if receipt.get("grant_ref") is None:
        notes.append(
            "grant_ref absent: observation has no authority correlation "
            "(test-mode only; production receipts require a trusted grant)"
        )
    return VerifiedOutcome("PASSED", notes)
