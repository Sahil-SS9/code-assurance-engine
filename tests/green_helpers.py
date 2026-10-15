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


def build_clean_receipt(*, parser, exit_code=0, contract=None, env=None):
    """A receipt as the boxed collector would stamp it (counts from the parser, honest).
    `contract` overrides the default fixture contract (for expected-collection variants); `env`
    substitutes the env allowlist for the digest (must match the contract under test)."""
    from hermes_code_assurance.evidence import (
        TRUSTED_ID,
        argv_digest_for,
        env_digest_for,
        receipt_id,
    )

    counts = dict(parser.counts)
    bound_contract = contract if contract is not None else build_contract()
    allowlist = list(env if env is not None else bound_contract.env_allowlist)
    check_spec = None
    for spec in bound_contract.required_checks:
        if spec.check_id == "unit-evidence":
            check_spec = spec
            break
    argv = list(check_spec.argv) if check_spec is not None else ["python", "-m", "pytest", "-q"]
    status = (
        "FAILED"
        if (counts.get("failed", 0) + counts.get("errors", 0)) > 0
        and parser.status_hint != "unknown"
        else "UNKNOWN"
    )
    receipt = {
        "status": status,
        "check_id": "unit-evidence",
        "attempt": 1,
        "candidate_digest": "a" * 64,
        "contract_id": bound_contract.contract_id,
        "argv_digest": argv_digest_for(argv),
        "env_digest": env_digest_for(allowlist),
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
