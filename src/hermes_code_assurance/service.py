"""Domain service facade shared by every surface (CLI, slash, tools): one flow, per-surface
request identity recorded. Nothing here imports Hermes; the adapter passes the data directory.
"""

from __future__ import annotations

import json
from pathlib import Path

from . import findings as findings_mod
from .candidate import GitCandidateReader
from .contracts import parse_contract
from .evidence import TRUSTED_ID
from .inspect import classify_inventory, propose_draft_contract
from .jsonio import canonical_json, sha256_hex
from .report import render_assessment, render_assessment_json
from .runner import CheckRunner
from .store import AssessmentStore
from .verify import reverify


def _store(state_dir: Path) -> AssessmentStore:
    store = AssessmentStore(Path(state_dir) / "assessments.db")
    store.initialize()
    return store


def _assessment_digest(payload: dict) -> str:
    return sha256_hex(canonical_json(payload))


def inspect_candidate(state_dir, repo: str, base: str | None = None, head: str | None = None) -> dict:
    """Read-only: inventory + classification + proposed (non-executable) contract draft."""
    reader = GitCandidateReader()
    inv = reader.read(repo, base=base, head=head).as_dict()
    inventory = classify_inventory(inv)
    draft = propose_draft_contract(inv)
    assessment_id = _assessment_digest({"repo": str(repo), "inv_digest": inv["snapshot_digest"]})
    payload = {
        "repo_root": str(repo),
        "base": base,
        "head": head,
        "inventory_digest": inv["snapshot_digest"],
        "inventory_state": inv["inventory_state"],
        "untracked": inv["untracked"],
        "ignored": inv["ignored"],
        "committed_changes": inv["committed_changes"],
        "dirty_tracked": inv["dirty_tracked"],
        "classification": inventory,
        "proposed_contract_draft": draft,
        "toolchain": inv["toolchain"],
        "policy_notes": inv["policy_notes"],
    }
    store = _store(state_dir)
    created = store.create_assessment(assessment_id, "CREATED", payload)
    if created:
        store.set_state(assessment_id, "INSPECTED", old_state="CREATED")
    return {
        "assessment_id": assessment_id,
        "inventory_state": payload["inventory_state"],
        "classification": inventory,
        "proposed_contract_draft": draft,
        "untracked": payload["untracked"],
        "committed_changes": payload["committed_changes"],
        "created": created,
        "policy_notes": payload["policy_notes"],
        "toolchain": payload["toolchain"],
    }


def plan_checks(state_dir, contract_dict: dict, assessment_id: str | None = None) -> dict:
    """Freeze a reviewed contract and bind it to the current assessment."""
    contract = parse_contract(contract_dict)
    store = _store(state_dir)
    if assessment_id is None:
        assessment_id = contract.contract_id
    exists = store.get_assessment(assessment_id)
    state = exists["state"] if exists else "CREATED"
    if state == "CREATED":
        store.set_state(assessment_id, "INSPECTED", old_state="CREATED")
        state = "INSPECTED"
    if state != "CONTRACT_REVIEW_REQUIRED":
        store.set_state(assessment_id, "CONTRACT_REVIEW_REQUIRED", old_state=state)
    merged = store.get_assessment(assessment_id)
    current = merged["payload"]
    current["contract_id"] = contract.contract_id
    current["required_checks"] = [c.to_dict() for c in contract.required_checks]
    current["optional_checks"] = [c.to_dict() for c in contract.optional_checks]
    with store.transaction() as conn:
        conn.execute(
            "UPDATE assessments SET payload=? WHERE id=?",
            (_dump_json(current), assessment_id),
        )
    return {
        "contract_id": contract.contract_id,
        "assessment_id": assessment_id,
        "state": "CONTRACT_REVIEW_REQUIRED",
        "required_checks": [c.check_id for c in contract.required_checks],
    }


def _dump_json(value: dict) -> str:
    return json.dumps(value, sort_keys=True)


def status(state_dir, assessment_id: str) -> dict:
    store = _store(state_dir)
    assessment = store.get_assessment(assessment_id)
    if not assessment:
        return {"assessment_id": assessment_id, "state": "missing", "checks": []}
    receipts = store.receipts(assessment_id)
    checks = [{"check_id": r["payload"].get("check_id"), "status": r["payload"].get("status")}
              for r in receipts]
    return {
        "assessment_id": assessment_id,
        "state": assessment["state"],
        "payload_keys": sorted(assessment["payload"].keys()),
        "checks": checks,
    }


def run_checks(state_dir, assessment_id: str, caller: str = "cli") -> dict:
    """Attempt the gated runner for the assessment's contract. Default: EXECUTION_UNAVAILABLE."""
    store = _store(state_dir)
    assessment = store.get_assessment(assessment_id)
    if not assessment:
        return {"assessment_id": assessment_id, "status": "EXECUTION_UNAVAILABLE",
                "detail": "unknown assessment id"}
    contract_dict = assessment["payload"].get("required_checks")
    if not contract_dict:
        return {"assessment_id": assessment_id, "status": "EXECUTION_UNAVAILABLE",
                "detail": "no frozen contract bound to this assessment"}
    contract = parse_contract({"schema": "check-contract-v1",
                               **assessment["payload"].get("proposed_contract_draft", {}),
                               "required_checks": contract_dict})
    runner = CheckRunner(authority=_default_authority())
    receipts = runner.attempt_checks(
        contract,
        candidate_digest=assessment["payload"].get("inventory_digest", "unavailable"),
        caller=caller,
    )
    for receipt in receipts:
        store.append_receipt(assessment_id, receipt)
    store.set_state(assessment_id, "EXECUTION_UNAVAILABLE", old_state=assessment["state"])
    return {
        "assessment_id": assessment_id,
        "status": "EXECUTION_UNAVAILABLE",
        "detail": "no public owner-grant route demonstrated (C0.2 blocker); all checks NOT_RUN",
        "checks": [{"check_id": r.get("check_id"), "status": r.get("status")} for r in receipts],
    }


def _default_authority():
    from .authority import DenyAllAuthority

    return DenyAllAuthority()


def verify(state_dir, assessment_id: str, caller: str = "cli") -> dict:
    """Reverify persisted receipts (identity layers) and compute an overall status."""
    from .contracts import parse_contract

    store = _store(state_dir)
    assessment = store.get_assessment(assessment_id)
    if not assessment:
        return {"assessment_id": assessment_id, "overall_status": "INVALID_EVIDENCE",
                "reason": "unknown assessment id"}
    contract_payload = assessment["payload"].get("required_checks")
    if not contract_payload:
        return {"assessment_id": assessment_id, "overall_status": "INCOMPLETE",
                "reason": "no frozen contract bound: evidence cannot be reconciled"}
    drafted = assessment["payload"].get("proposed_contract_draft") or {}
    contract = parse_contract(
        {
            **drafted,
            "schema": "check-contract-v1",
            "required_checks": contract_payload,
            "env_allowlist": ["PATH"],
            "network_enabled": False,
            "model_enabled": False,
            "supported_platforms": ["linux"],
        }
    )
    results = []
    receipts_payloads = []
    for rec in store.receipts(assessment_id):
        payload = rec["payload"]
        receipts_payloads.append(payload)
        verified = reverify(
            payload,
            contract=contract,
            candidate_digest=assessment["payload"].get("inventory_digest", ""),
            caller=caller,
            trusted_collector_id=TRUSTED_ID if payload.get("collector") == TRUSTED_ID else "none",
        )
        results.append(verified.to_dict())
    payload = assessment["payload"]
    payload["verification"] = results
    with _store(state_dir).transaction() as conn:
        conn.execute(
            "UPDATE assessments SET state=?, payload=? WHERE id=?",
            ("ASSESSED", _dump_json(payload), assessment_id),
        )
    overall = _overall_from(results)
    return {
        "assessment_id": assessment_id,
        "overall_status": overall,
        "verification": results,
    }


def _overall_from(results: list) -> str:
    if not results:
        return "INCOMPLETE"
    statuses = {r["status"] for r in results}
    if any(s == "FAILED" for s in statuses):
        return "FINDINGS_PRESENT"
    if any(s in ("INVALID_EVIDENCE",) for s in statuses):
        return "INVALID_EVIDENCE"
    if statuses <= {"PASSED"}:
        return "ASSESSED_WITHIN_DECLARED_SCOPE"
    return "INCOMPLETE"


def findings(state_dir, assessment_id: str) -> dict:
    store = _store(state_dir)
    assessment = store.get_assessment(assessment_id)
    if not assessment:
        return {"assessment_id": assessment_id, "findings": [], "unknowns": []}
    contract_payload = assessment["payload"].get("required_checks") or []
    if not contract_payload:
        return {"assessment_id": assessment_id, "findings": [], "unknowns": []}
    drafted = assessment["payload"].get("proposed_contract_draft") or {}
    contract = parse_contract(
        {
            **drafted,
            "schema": "check-contract-v1",
            "required_checks": contract_payload,
            "env_allowlist": ["PATH"],
            "network_enabled": False,
            "model_enabled": False,
            "supported_platforms": ["linux"],
        }
    )
    receipts = [r["payload"] for r in store.receipts(assessment_id)]
    noted = findings_mod.deterministic_findings(receipts, contract=contract)
    return {"assessment_id": assessment_id, "findings": noted.findings,
            "unknowns": noted.unknowns}


def report(state_dir, assessment_id: str, fmt: str = "markdown") -> dict:
    st = status(state_dir, assessment_id)
    f = findings(state_dir, assessment_id)
    payload = {
        "overall_status": st["state"],
        "findings": f.get("findings", []),
        "checks": st.get("checks", []),
        "candidate": {},
    }
    if fmt == "json":
        return {"assessment_id": assessment_id,
                "content": render_assessment_json(payload, candidate_summary={})}
    content = render_assessment(payload, candidate_summary={})
    return {"assessment_id": assessment_id, "content": content}
