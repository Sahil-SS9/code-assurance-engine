"""Shared, test-only factory helpers for receipts and contracts used across evidence tests."""

from __future__ import annotations


def build_contract():
    from hermes_code_assurance.contracts import parse_contract

    return parse_contract(
        {
            "schema": "check-contract-v1",
            "goal": "evidence verification fixtures",
            "assessed_areas": ["tests/"],
            "required_checks": [
                {
                    "check_id": "unit-evidence",
                    "label": "evidence demo suite",
                    "kind": "test-run",
                    "argv": ["python", "-m", "pytest", "-q"],
                    "cwd": ".",
                    "parser_id": "junit-xml",
                }
            ],
            "env_allowlist": ["PATH"],
            "network_enabled": False,
            "model_enabled": False,
            "supported_platforms": ["linux"],
        }
    )


def build_clean_receipt(*, parser, exit_code=0):
    """A receipt as the boxed collector would stamp it (counts from the parser, honest)."""
    from hermes_code_assurance import evidence  # noqa: F401
    from hermes_code_assurance.evidence import (
        TRUSTED_ID,
        argv_digest_for,
        env_digest_for,
        receipt_id,
    )

    counts = dict(parser.counts)
    receipt = {
        "status": "FAILED" if (parser.counts.get("failed", 0) + parser.counts.get("errors", 0) or 0) > 0 and parser.status_hint != "unknown" else "UNKNOWN",
        "check_id": "unit-evidence",
        "attempt": 1,
        "candidate_digest": "a" * 64,
        "contract_id": build_contract().contract_id,
        "argv_digest": argv_digest_for(["python", "-m", "pytest", "-q"]),
        "env_digest": env_digest_for(["PATH"]),
        "grant_ref": None,
        "caller": "cli:root",
        "collector": TRUSTED_ID,
        "observation_origin": "boxed-collector",
        "counts": counts,
        "parser": {"id": parser.parser_id, "version_stamp": "1", "status_hint": parser.status_hint,
                   "discrepancies": list(parser.discrepancies), "reasons": list(parser.reasons)},
        "observed": {"exit_code": exit_code, "signal": None, "started_at": "2026-10-14T20:00:00Z",
                     "ended_at": "2026-10-14T20:00:01Z"},
        "artifacts": [{"artifact_ref": "art-1", "sha256": "e" * 64}],
        "flags": [],
        "created_at": "2026-10-14T20:00:01Z",
    }
    receipt["receipt_id"] = receipt_id(receipt)
    return receipt
