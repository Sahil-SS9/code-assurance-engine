"""Findings: deterministic (observed) findings kept strictly separate from advisory proposals.

Numeric model confidence never filters or ranks findings. Empty findings is never treated as a
safe claim — the reporting layer says so explicitly.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class FindingsResult:
    findings: list = field(default_factory=list)
    unknowns: list = field(default_factory=list)
    advisory_notes: list = field(default_factory=list)


def deterministic_findings(receipts: list, *, contract) -> FindingsResult:
    """Compute observed-status findings and unknown gaps from receipts (no model input)."""
    out = FindingsResult()
    for receipt in receipts:
        status = receipt.get("status") or (receipt.get("verified") or {}).get("status")
        spec = _spec_for(contract, receipt.get("check_id"))
        evidence_refs = {
            "receipt_id": receipt.get("receipt_id"),
            "check_id": receipt.get("check_id"),
        }
        if status == "FAILED":
            out.findings.append(
                {
                    "rule": "required-check-failed",
                    "category": "test-failure",
                    "severity": "high" if spec else "medium",
                    "provenance": "observed",
                    "evidence_refs": evidence_refs,
                    "rationale": "received check failed against its reviewed oracle",
                    "status": receipt.get("reason") or "failed",
                    "limits": {"falsifier": "re-run with the same contract for reproduction"},
                }
            )
        elif status == "UNKNOWN":
            out.unknowns.append(
                {
                    "check_id": receipt.get("check_id"),
                    "provenance": "unknown",
                    "reason": receipt.get("detail") or receipt.get("reason"),
                    "limits": {"workspace": "unknown stays unknown; never zero"},
                }
            )
        elif status == "NOT_RUN":
            out.unknowns.append(
                {
                    "check_id": receipt.get("check_id"),
                    "provenance": "unknown",
                    "reason": receipt.get("reason") or "not run",
                    "limits": {"explicit": True},
                }
            )
    return out


def _spec_for(contract, check_id):
    if contract is None or check_id is None:
        return None
    for check in getattr(contract, "required_checks", ()):
        if check.check_id == check_id:
            return check
    return None
