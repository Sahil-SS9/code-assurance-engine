"""Domain service facade shared by every surface (CLI, slash, tools): one flow, per-surface
request identity recorded. Nothing here imports Hermes; the adapter passes the data directory.

Repair contract (C1–C5):
- C2: `plan_checks` stores the COMPLETE canonical contract under payload["contract"]; every
  consumer re-parses THAT dict and asserts identity — no draft/default reconstruction anywhere.
- C3: pre-mutation guards + CAS: run refuses unless state==APPROVED; all run mutations happen
  inside one fenced transaction (receipts + state roll back together); verify is idempotent and
  refuses new-receipt drift without a write.
- C5: production trust is STRICT: public verify never clears status on unauthenticated
  provenance (synthetic or self-supplied collector strings stay UNKNOWN; overall cannot reach
  ASSESSED_WITHIN_DECLARED_SCOPE in this build).
- C1: missing required checks are explicit; coverage-complete verdicts need every required id
  to carry current admissible evidence at the right contract/candidate/attempt.
"""

from __future__ import annotations

import json
from pathlib import Path

from . import findings as findings_mod
from .candidate import GitCandidateReader
from .contract_errors import ContractIntegrityRefusal
from .contracts import parse_contract
from .inspect import classify_inventory, propose_draft_contract
from .jsonio import canonical_json, sha256_hex
from .report import render_assessment, render_assessment_json
from .runner import CheckRunner
from .store import AssessmentStore
from .verify import reverify


def _store(state_dir) -> AssessmentStore:
    store = AssessmentStore(Path(state_dir) / "assessments.db")
    store.initialize()
    return store


def _assessment_digest(payload: dict) -> str:
    return sha256_hex(canonical_json(payload))


def _dump_json(value) -> str:
    return json.dumps(value, sort_keys=True)


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
    """Freeze a reviewed contract: the COMPLETE canonical contract is stored verbatim (C2)."""
    contract = parse_contract(contract_dict)
    store = _store(state_dir)
    if assessment_id is None:
        assessment_id = contract.contract_id
    exists = store.get_assessment(assessment_id)
    if exists is None:
        raise KeyError(f"unknown assessment: {assessment_id}")
    state = exists["state"]
    if state != "CONTRACT_REVIEW_REQUIRED":
        store.set_state(assessment_id, "CONTRACT_REVIEW_REQUIRED", old_state=state)
    body = dict(exists["payload"])
    body["contract"] = contract.to_dict()  # C2: complete canonical contract; single source
    body["contract_id"] = contract.contract_id
    with store.transaction() as conn:
        conn.execute(
            "UPDATE assessments SET payload=? WHERE id=?",
            (_dump_json(body), assessment_id),
        )
    return {
        "contract_id": contract.contract_id,
        "assessment_id": assessment_id,
        "state": "CONTRACT_REVIEW_REQUIRED",
        "required_checks": [c.check_id for c in contract.required_checks],
    }


def _assessment_with_contract(store, assessment_id: str):
    """Load the assessment and re-parse the STORED canonical contract (C2). Raises when absent,
    mismatched against its id stamp, or failing to re-validate to the same contract id."""
    assessment = store.get_assessment(assessment_id)
    if not assessment:
        raise KeyError(f"unknown assessment: {assessment_id}")
    contract_body = assessment["payload"].get("contract")
    if not contract_body:
        raise ContractIntegrityRefusal(
            "no canonical contract bound: plan_checks must store the complete contract first"
        )
    contract = parse_contract(contract_body)
    if contract.contract_id != assessment["payload"].get("contract_id"):
        raise ContractIntegrityRefusal("stored contract id does not match re-parsed contract")
    if contract.contract_id != contract_body.get("contract_id"):
        raise ContractIntegrityRefusal("stored contract body fails its own identity stamp")
    return assessment, contract


def _contract_public(assessment_id: str, contract) -> dict:
    return {"contract_id": contract.contract_id, "assessment_id": assessment_id}


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
    """Gated attempt. Refuses pre-mutation unless state==APPROVED (C3); on APPROVED the whole
    run (receipts + state rollup) commits inside ONE fenced transaction and rolls back as one."""
    store = _store(state_dir)
    try:
        assessment, contract = _assessment_with_contract(store, assessment_id)
    except KeyError as exc:
        return {"assessment_id": assessment_id, "status": "NOT_FOUND", "detail": str(exc),
                "receipts_unchanged": True}
    except ContractIntegrityRefusal as exc:
        return {"assessment_id": assessment_id, "status": "EVIDENCE_INTEGRITY_REFUSAL",
                "detail": str(exc), "receipts_unchanged": True}

    state = assessment["state"]
    if state != "APPROVED":
        return {
            "assessment_id": assessment_id,
            "status": "NOT_APPROVED",
            "detail": f"run requires state APPROVED; current state is {state}. Owner approval "
                      "is explicit; no receipts or state changes happen before it.",
            "receipts_unchanged": True,
        }

    runner = CheckRunner(authority=_default_authority())
    with store.transaction():  # C3: one fence; receipts + state roll back together
        receipts = runner.attempt_checks(
            contract,
            candidate_digest=assessment["payload"].get("inventory_digest", "unavailable"),
            caller=caller,
        )
        for receipt in receipts:
            store.append_receipt(assessment_id, receipt)  # nested SAVEPOINTs on the same conn
        store.set_state(assessment_id, "EXECUTION_UNAVAILABLE", old_state="APPROVED")
    return {
        **_contract_public(assessment_id, contract),
        "status": "EXECUTION_UNAVAILABLE",
        "detail": "no public owner-grant route demonstrated (C0.2 blocker); all checks NOT_RUN",
        "checks": [{"check_id": r.get("check_id"), "status": r.get("status")} for r in receipts],
    }


def _default_authority():
    from .authority import DenyAllAuthority

    return DenyAllAuthority()


_verify_allowed_states = ("CONTRACT_REVIEW_REQUIRED", "APPROVED", "AUTHORITY_REQUIRED",
                          "EXECUTION_UNAVAILABLE", "RUNNING", "INTERRUPTED", "BUDGET_STOPPED",
                          "FAILED")


def verify(state_dir, assessment_id: str, caller: str = "cli") -> dict:
    """Reverify persisted receipts (identity layers) and compute overall status.

    C1: every required check id needs current admissible-evidence; missing ids are explicit.

    Idempotent (C3): repeating verify with no new receipts returns the recorded result without
    writing; new receipts since the last assessment REFUSE (evidence-refresh is an explicit
    owner action), also without writing.

    C5: production trust is strict — a receipt without grant correlation stays UNKNOWN no
    matter how self-consistent its hashes; scope-complete overall is unreachable until the
    protected-host trust seam exists.
    """
    store = _store(state_dir)
    try:
        assessment, contract = _assessment_with_contract(store, assessment_id)
    except KeyError as exc:
        return {"assessment_id": assessment_id, "overall_status": "INVALID_EVIDENCE",
                "contract_id": None, "reason": str(exc)}
    except ContractIntegrityRefusal as exc:
        return {"assessment_id": assessment_id, "overall_status": "INVALID_EVIDENCE",
                "contract_id": None, "reason": str(exc)}

    receipt_rows = store.receipts(assessment_id)
    state = assessment["state"]
    if state == "ASSESSED":
        completion = assessment["payload"].get("completion") or {}
        recorded_count = completion.get("receipts_count")
        if len(receipt_rows) == (recorded_count if recorded_count is not None else -1):
            return {**completion, "idempotent": True}
        return {"assessment_id": assessment_id, "overall_status": "EVIDENCE_REFRESH_REQUIRED",
                "detail": "new receipts since last verify: explicit owner re-verification "
                          "required (no silent re-extension)",
                "contract_id": assessment["payload"].get("contract_id"),
                "receipts_unchanged": True}
    if state not in _verify_allowed_states:
        return {"assessment_id": assessment_id, "overall_status": "INVALID_EVIDENCE",
                "detail": f"verify not permitted from state {state}"}

    results = []
    seen_pass: set[str] = set()
    for rec in receipt_rows:
        payload = rec["payload"]
        verified = reverify(
            payload,
            contract=contract,
            candidate_digest=assessment["payload"].get("inventory_digest", ""),
            caller=caller,
            trusted_collector_id=_production_collector_of(payload),
            assert_collector_identity=False,  # collector identity CANNOT be proven from content
        )
        result = verified.to_dict()
        if payload.get("grant_ref") is None and verified.status == "PASSED":
            result["status"] = "UNKNOWN"
            result["notes"] = list(result["notes"]) + [
                ("C5 provenance gate: no authenticated grant correlation — the protected-host "
                "trust source is not connected in this build; synthetic or self-supplied "
                "provenance stays UNKNOWN. Did not clear to PASSED.")
            ]
        if result["status"] == "PASSED":
            seen_pass.add(payload.get("check_id"))
        results.append({**result, "check_id": payload.get("check_id")})

    missing_required = [cid for cid in (c.check_id for c in contract.required_checks)
                        if cid not in seen_pass]
    overall = _overall_from(results, missing_required)
    completion = {
        "overall_status": overall,
        "missing_required": missing_required,
        "receipts_count": len(receipt_rows),
        "verification": results,
        "trust_model": "production-strict: receipts without grant correlation never clear; "
                       "protected-host trust seam not wired in this build (INCOMPLETE by design "
                       "until C0.2/C0.3 land)",
    }
    stored_payload = dict(assessment["payload"])
    stored_payload["completion"] = completion
    with store.transaction() as conn:  # C3: single CAS'd update; refuses on state drift
        cur = conn.execute("SELECT state FROM assessments WHERE id=?", (assessment_id,)).fetchone()
        if cur is None or cur["state"] != state:
            raise RuntimeError("concurrent state change detected: verify refused")
        conn.execute(
            "UPDATE assessments SET state=?, payload=? WHERE id=?",
            ("ASSESSED", _dump_json(stored_payload), assessment_id),
        )
    return {**completion, "assessment_id": assessment_id,
            "contract_id": assessment["payload"].get("contract_id")}


def _production_collector_of(payload: dict):
    """C5: the trusted collector identity comes from an INDEPENDENT host decision, never from
    the receipt's own self-supplied field. Until the protected-host seam exists, every receipt
    is reverified against an untrusted identity string — the identity layers still guard
    (tamper/cross/caller), but nothing accepts a fabricated `collector` field as trust."""
    del payload  # receipt content must not influence the decision
    return "trusted-collector:NOT-AVAILABLE-IN-PRODUCTION-v0.1"


def _overall_from(results: list, missing_required: list) -> str:
    if not results:
        return "INCOMPLETE"
    statuses = {r.get("status") for r in results}
    if "INVALID_EVIDENCE" in statuses:
        return "INVALID_EVIDENCE"
    if missing_required:
        return "INCOMPLETE"
    if "FAILED" in statuses:
        return "FINDINGS_PRESENT"
    # C5 ceiling: trust seam not wired. Even all-PASSED stays INCOMPLETE; scope-complete
    # verdicts are unreachable from the public service in this build.
    return "INCOMPLETE"


def findings(state_dir, assessment_id: str) -> dict:
    store = _store(state_dir)
    try:
        _assessment, contract = _assessment_with_contract(store, assessment_id)
    except KeyError as exc:
        return {"assessment_id": assessment_id, "contract_id": None, "findings": [],
                "unknowns": [], "reason": str(exc)}
    except ContractIntegrityRefusal as exc:
        return {"assessment_id": assessment_id, "contract_id": None, "findings": [],
                "unknowns": [], "reason": str(exc)}
    receipts = [r["payload"] for r in store.receipts(assessment_id)]
    noted = findings_mod.deterministic_findings(receipts, contract=contract)
    return {**_contract_public(assessment_id, contract), "findings": noted.findings,
            "unknowns": noted.unknowns}


def report(state_dir, assessment_id: str, fmt: str = "markdown") -> dict:
    st = status(state_dir, assessment_id)
    f = findings(state_dir, assessment_id)
    completion_payload = {}
    try:
        assessment, _ = _assessment_with_contract(_store(state_dir), assessment_id)
        completion_payload = assessment["payload"].get("completion") or {}
    except (KeyError, ContractIntegrityRefusal):
        completion_payload = {}
    payload = {
        "overall_status": completion_payload.get("overall_status") or st.get("state", "UNKNOWN"),
        "findings": f.get("findings", []),
        "checks": st.get("checks", []),
        "candidate": {},
    }
    if fmt == "json":
        return {"assessment_id": assessment_id,
                "content": render_assessment_json(payload, candidate_summary={})}
    content = render_assessment(payload, candidate_summary={})
    return {"assessment_id": assessment_id, "content": content}
