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
import os
import shutil
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


# ============================================================================ owner journey
#
# M1 step 3 wiring: the public CLI route consumes an owner-signed bundle. The ONLY granted
# execution path in this build (route "cli"); every other surface stays default-denied below.
# All refusals happen BEFORE any mutation: receipts and state stay untouched on denial.


def _staged_oracle(state_dir) -> Path:
    from .owner_authority import AuthorityDenied

    staged = Path(state_dir) / "journey" / "oracle"
    if staged.is_symlink() or not staged.is_dir():
        reason = ("the evaluator oracle is not staged yet: run the journey staging step first "
                  f"(expected {staged})")
        raise AuthorityDenied([reason])
    return staged


def stage_journey(state_dir, assessment_id: str, *, oracle_source: str) -> dict:
    """Stage the evaluator-owned oracle under the state root and return the exact scope bundle
    the owner must place in the request they sign. Read-only for the candidate; never executes."""
    loaded, refusal = _journey_load(state_dir, assessment_id)
    if refusal is not None:
        return {**refusal, "status": refusal["status"]}
    _store_obj, assessment, contract = loaded
    del _store_obj
    journey_dir = Path(state_dir) / "journey"
    staged = journey_dir / "oracle"
    if staged.exists() or staged.is_symlink():
        return {"assessment_id": assessment_id, "status": "ALREADY_STAGED",
                "detail": "the oracle is already staged; refusing to overwrite (stage nothing"
                          " silently)",
                }
    source = Path(oracle_source)
    if source.is_symlink() or not source.is_dir():
        return {"assessment_id": assessment_id, "status": "INVALID_ORACLE_SOURCE",
                "detail": "oracle source must be a real directory (no symlinks)"}
    journey_dir.mkdir(mode=0o700)
    try:
        from hermes_code_assurance.owner_execution import journey_specs_from

        shutil.copytree(source, staged)
        os.chmod(journey_dir, 0o700)
        specs = journey_specs_from(assessment=assessment, contract=contract, staged_oracle=staged)
    except Exception as exc:  # noqa: BLE001 - deliberate: staging failures become honest refusals
        shutil.rmtree(staged, ignore_errors=True)
        from hermes_code_assurance.owner_authority import AuthorityDenied

        if isinstance(exc, AuthorityDenied):
            return {"assessment_id": assessment_id, "status": "AUTHORITY_REFUSED",
                    "detail": "; ".join(exc.reasons)}
        return {"assessment_id": assessment_id, "status": "STAGING_REFUSED",
                "detail": f"{exc}"}
    from hermes_code_assurance.owner_execution import stage_digest_bundle as _bundle

    return {"assessment_id": assessment_id, "status": "STAGED",
            "oracle_source": str(staged), **_bundle(specs)}


def _expected_operation(*, state_dir: str, specs, peek: dict) -> dict:
    """Bind everything the store + engine know; owner/attempt-id come from the signed body."""
    return {
        "schema_version": 1,
        "owner": peek["owner"],
        "route": "cli",
        "data_root": str(Path(state_dir).resolve()),
        "assessment_id": specs.assessment_id,
        "attempt": 1,
        "attempt_id": peek["attempt_id"],
        "check_id": specs.check_id,
        "candidate_digest": specs.candidate_digest,
        "contract_id": specs.contract_id,
        "oracle_digest": specs.oracle_digest,
        "toolchain_digest": specs.toolchain_digest,
        "collector_digest": specs.collector_digest,
        "image": specs.image,
        "isolation_policy_digest": specs.isolation_policy_digest,
        "argv": list(specs.argv),
        "env_digest": specs.env_digest,
        "limits": dict(specs.limits),
        "network": "none",
    }


def approve_contract(state_dir, assessment_id: str, *, owner_keys: str, owner_request: str,
                     owner_signature: str) -> dict:
    """Owner-gated review completion: a verified owner signature moves
    CONTRACT_REVIEW_REQUIRED -> APPROVED. Fixture-class authority is refused here."""
    import hermes_code_assurance.owner_execution as journey

    from .owner_authority import OwnerAuthority

    loaded, refusal = _journey_load(state_dir, assessment_id)
    if refusal is not None:
        return refusal
    store, assessment, contract = loaded
    state = assessment["state"]
    if state != "CONTRACT_REVIEW_REQUIRED":
        return {"assessment_id": assessment_id, "status": "STATE_REFUSED",
                "detail": f"approve requires state CONTRACT_REVIEW_REQUIRED; current {state!r}",
                "receipts_unchanged": True}
    request_bytes, signature_bytes = journey.read_bundle(owner_request, owner_signature)
    peek = journey.peek_owner_operation(request_bytes)
    trust = journey.load_trust_root(owner_keys)
    specs = journey.journey_specs_from(
        assessment=assessment, contract=contract, staged_oracle=_staged_oracle(state_dir)
    )
    authority = OwnerAuthority(trust, None)
    authorization = authority.evaluate(
        request_bytes, signature_bytes,
        _expected_operation(state_dir=str(state_dir), specs=specs, peek=peek),
    )
    if authorization.authority_class != "owner":
        return {"assessment_id": assessment_id, "status": "AUTHORITY_CLASS_REFUSED",
                "detail": "contract approval requires owner-class authority; got "
                          f"{authorization.authority_class!r} (fixture roots never approve)"}
    store.set_state(assessment_id, "APPROVED", old_state="CONTRACT_REVIEW_REQUIRED")
    return {
        "assessment_id": assessment_id,
        "contract_id": authorization.operation.get("contract_id"),
        "state": "APPROVED",
        "authorization": {
            "owner": authorization.owner, "key_id": authorization.key_id,
            "authority_class": authorization.authority_class,
            "request_sha256": authorization.request_sha256,
            "expires_at": authorization.expires_at,
        },
        "detail": "owner signature verified against the exact frozen contract; run_owner_journey "
                  "may consume this grant exactly once",
    }


def run_owner_journey(state_dir, assessment_id: str, *, owner_keys: str, owner_request: str,
                      owner_signature: str, backend=None, caller: str = "cli") -> dict:
    """The single authorized execution route: owner-signed bundle -> one isolated observation.

    Denials of a SUPPLIED bundle refuse before any mutation (receipts unchanged). With no bundle
    (this route does not accept absence), use the default run_checks denial path instead.
    The `backend` parameter is a test seam; production callers pass None (real rootless Docker).
    """
    import hermes_code_assurance.owner_execution as journey

    from .authority import TrustedGrant, argv_digest
    from .owner_authority import AuthorityLedger, OwnerAuthority
    from .owner_execution import OwnerJourneyExecutor
    from .sandbox import RootlessDockerBackend

    loaded, refusal = _journey_load(state_dir, assessment_id)
    if refusal is not None:
        return refusal
    store, assessment, contract = loaded
    state = assessment["state"]
    if state != "APPROVED":
        return {"assessment_id": assessment_id, "status": "NOT_APPROVED",
                "detail": f"run requires state APPROVED; current state is {state}",
                "receipts_unchanged": True}
    request_bytes, signature_bytes = journey.read_bundle(owner_request, owner_signature)
    peek = journey.peek_owner_operation(request_bytes)
    trust = journey.load_trust_root(owner_keys)
    payload = assessment["payload"]
    specs = journey.journey_specs_from(
        assessment=assessment, contract=contract, staged_oracle=_staged_oracle(state_dir)
    )
    ledger = AuthorityLedger(Path(state_dir) / "authority-ledger.db")
    ledger.ensure()
    expected = _expected_operation(state_dir=str(state_dir), specs=specs, peek=peek)
    authorization = OwnerAuthority(trust, ledger).evaluate(
        request_bytes, signature_bytes, expected,
    )  # AuthorityDenied propagates: refusal before any mutation below

    check_id = authorization.operation.get("check_id")
    grants = {
        check_id: TrustedGrant(
            # The kernel requester is the CALLER identity (route), not the owner name: the
            # owner is proven cryptographically (signature + trust root + ledger), not by a
            # caller string. The owner's identity stays in grant_id + the ledger claim row.
            grant_id=f"owner:{authorization.owner}:{authorization.key_id}:"
                     f"{authorization.request_sha256[:16]}",
            requester=caller,
            candidate_digest=str(authorization.operation.get("candidate_digest")),
            contract_id=str(authorization.operation.get("contract_id")),
            check_id=str(check_id),
            argv_sha256=argv_digest(authorization.operation.get("argv") or ()),
            env_sha256=str(authorization.operation.get("env_digest")),
            expires_epoch_seconds=int(authorization.expires_at),
        ),
    }
    trusted_decisions = {
        check_id: {"issuer": "outside-candidate-workspace",
                   "decision_id": f"code-assurance-owner-authorization:{authorization.key_id}"},
    }
    adapter = OwnerJourneyExecutor(
        backend=backend if backend is not None else RootlessDockerBackend(),
        ledger=ledger,
        authorization=authorization,
        state_dir=Path(state_dir),
        contract=contract,
        candidate_source=Path(str(payload.get("repo_root", ""))),
        candidate_base=payload.get("base"),
        candidate_head=payload.get("head"),
        expected_candidate_digest=specs.candidate_digest,
        staged_oracle=_staged_oracle(state_dir),
        caller=caller,
    )
    runner = CheckRunner(authority=_default_authority(), execution_adapter=adapter)
    receipts = runner.attempt_checks(
        contract,
        candidate_digest=specs.candidate_digest,
        caller=caller,
        grants=grants,
        trusted_decisions=trusted_decisions,
    )
    with store.transaction():  # C3: receipts + state roll back together
        for receipt in receipts:
            store.append_receipt(assessment_id, receipt)
        store.set_state(assessment_id, "RUNNING", old_state="APPROVED")
    statuses = {receipt["status"] for receipt in receipts}
    final_status = ("INTERRUPTED" if statuses & {"INTERRUPTED", "UNKNOWN"} else "EXECUTED")
    if final_status == "INTERRUPTED":
        with store.transaction():
            store.set_state(assessment_id, "INTERRUPTED", old_state="RUNNING")
    return {
        **_contract_public(assessment_id, contract),
        "status": final_status,
        "attempt_id": authorization.operation.get("attempt_id"),
        "authorization": {
            "owner": authorization.owner, "key_id": authorization.key_id,
            "authority_class": authorization.authority_class,
            "request_sha256": authorization.request_sha256,
            "expires_at": authorization.expires_at,
        },
        "checks": [{"check_id": r.get("check_id"), "status": r.get("status")}
                   for r in receipts],
        "detail": ("one signed check executed under verified isolation and a protected collector"
                   if final_status == "EXECUTED" else
                   "the signed attempt did not produce a trusted result; receipts are honest"),
    }


def _journey_load(state_dir, assessment_id: str):
    """Load (store, assessment, contract) or an honest refusal dict for the journey routes."""
    store = _store(state_dir)
    try:
        assessment, contract = _assessment_with_contract(store, assessment_id)
    except KeyError as exc:
        return None, {"status": "NOT_FOUND", "reason": str(exc), "receipts_unchanged": True}
    except ContractIntegrityRefusal as exc:
        return None, {"status": "EVIDENCE_INTEGRITY_REFUSAL", "reason": str(exc),
                      "receipts_unchanged": True}
    return (store, assessment, contract), None


_verify_allowed_states = ("CONTRACT_REVIEW_REQUIRED", "APPROVED", "AUTHORITY_REQUIRED",
                          "EXECUTION_UNAVAILABLE", "RUNNING", "INTERRUPTED", "BUDGET_STOPPED",
                          "FAILED")


def verify(state_dir, assessment_id: str, caller: str = "cli") -> dict:
    """Reverify persisted receipts (identity layers) and compute overall status.

    C1: every required check id needs current admissible-evidence; missing ids are explicit.

    Idempotent (C3): repeating verify with no new receipts returns the recorded result without
    writing; new receipts since the last assessment REFUSE (evidence-refresh is an explicit
    owner action), also without writing.

    C5: production trust is strict — a receipt clears only when the private authority ledger
    independently records owner provenance for it; every other receipt stays UNKNOWN no matter
    how self-consistent its hashes.
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

    # The protected-host trust seam: provenance comes ONLY from the private authority ledger
    # written beside the executed claims. The ledger is opened read-if-exists; nothing here
    # creates it, and a missing ledger preserves the exact round-2 behaviour below.
    from .owner_authority import AuthorityLedger

    ledger = AuthorityLedger.open_existing(Path(state_dir) / "authority-ledger.db")

    results = []
    seen_pass: set[str] = set()
    owner_provenanced: set[str] = set()
    provenance_note = (
        "C5 provenance gate: no independently verified authority or collection — the "
        "protected-host trust source is not connected in this build; a receipt's own "
        "grant_ref/collector strings (absent, empty, invented, or self-supplied) cannot "
        "establish provenance. Did not clear to PASSED."
    )
    for rec in receipt_rows:
        payload = rec["payload"]
        provenance = _production_collector_of(payload, ledger, assessment_id)
        has_owner_provenance = provenance is not None
        verified = reverify(
            payload,
            contract=contract,
            candidate_digest=assessment["payload"].get("inventory_digest", ""),
            caller=caller,
            # When provenance exists, the ledger row CONFIRMED this receipt's collector record;
            # assert the receipt's collector field openly against it (restored identity layer).
            # Without provenance the identity layer cannot be proven from content: off, and
            # PASSED observations downgrade to UNKNOWN with the explicit gap note.
            trusted_collector_id=payload.get("collector") if has_owner_provenance
            else _NO_PROVENANCE_COLLECTOR,
            assert_collector_identity=has_owner_provenance,
        )
        result = verified.to_dict()
        # C5 (round-2): at the public production seam, NO receipt field can establish trust —
        # absent, empty, or made-up grant references and self-supplied collector strings alike.
        # Independently recorded owner provenance (the private ledger row joined by receipt_id,
        # bound to this assessment/check/collector) restores the collector identity layer; every
        # other receipt keeps the explicit provenance gap regardless of spelling.
        if verified.status == "PASSED" and not has_owner_provenance:
            result["status"] = "UNKNOWN"
            result["notes"] = list(result["notes"]) + [provenance_note]
        if result["status"] == "PASSED":
            seen_pass.add(payload.get("check_id"))
            if has_owner_provenance:
                owner_provenanced.add(payload.get("check_id"))
        results.append({**result, "check_id": payload.get("check_id"),
                        "provenance": provenance if has_owner_provenance else None})

    missing_required = [cid for cid in (c.check_id for c in contract.required_checks)
                        if cid not in seen_pass]
    overall = _overall_from(results, missing_required, owner_provenanced,
                            tuple(c.check_id for c in contract.required_checks))
    completion = {
        "overall_status": overall,
        "missing_required": missing_required,
        "receipts_count": len(receipt_rows),
        "verification": results,
        "trust_model": "production-strict: receipts clear only on independent owner provenance "
                       "recorded in the private authority ledger for an executed, "
                       "isolation-attested attempt; grant_ref/collector strings of ANY spelling "
                       "are receipt content, not provenance",
    }
    stored_payload = dict(assessment["payload"])
    stored_payload["completion"] = completion
    with store.transaction() as conn:  # C3: single CAS'd update; refuses on state drift
        cur = conn.execute("SELECT state FROM assessments WHERE id=?", (assessment_id,)).fetchone()
        if cur is None or cur["state"] != state:
            raise RuntimeError("concurrent state change detected: verify refused")
        # The verdict transition is audited like every other state change: store.set_state
        # re-CASes on old_state, enforces the state graph and writes the event row here —
        # inside this SAME fenced transaction (independent-review finding, 2026-10-18).
        store.set_state(assessment_id, "ASSESSED", old_state=state)
        conn.execute(
            "UPDATE assessments SET payload=? WHERE id=?",
            (_dump_json(stored_payload), assessment_id),
        )
    return {**completion, "assessment_id": assessment_id,
            "contract_id": assessment["payload"].get("contract_id")}


_NO_PROVENANCE_COLLECTOR = "trusted-collector:NOT-AVAILABLE-IN-PRODUCTION-v0.1"


def _production_collector_of(payload: dict, ledger=None, assessment_id: str | None = None):
    """C5: the trusted collector identity comes from an INDEPENDENT host decision, never from
    the receipt's own self-supplied field. The only independent decision that exists is the
    private authority ledger written beside the executed claims; a receipt is owner-provenanced
    only when a ledger row joins its receipt_id, belongs to this assessment, matches its
    check and collector record, and carries owner-class authority. Returns the ledger's
    provenance marker (owner, key id) or None; the ledger-confirmed collector record is what
    the receipt's own collector field is asserted against."""
    if ledger is None or assessment_id is None:
        return None
    receipt_id_value = payload.get("receipt_id")
    if not receipt_id_value:
        return None
    row = ledger.provenance(receipt_id_value)
    if not row or row.get("authority_class") != "owner":
        return None
    binds = (
        row.get("assessment_id") == str(assessment_id),
        row.get("check_id") == payload.get("check_id"),
        row.get("collector") == payload.get("collector"),
        bool(row.get("key_id")) and bool(row.get("nonce")),
    )
    if not all(binds):
        return None
    return f"owner-ledger:{row['key_id']}"


def _overall_from(results: list, missing_required: list,
                  owner_provenanced: set[str] | None = None,
                  required_ids: tuple | None = None) -> str:
    if not results:
        return "INCOMPLETE"
    statuses = {r.get("status") for r in results}
    if "INVALID_EVIDENCE" in statuses:
        return "INVALID_EVIDENCE"
    if missing_required:
        return "INCOMPLETE"
    if "FAILED" in statuses:
        return "FINDINGS_PRESENT"
    # C5 ceiling, updated by the M1 trust seam: scope-complete verdicts are reachable ONLY when
    # every required check reached PASSED backed by independent owner provenance. Anything less
    # stays INCOMPLETE; no receipt content can lift the ceiling.
    cleared = owner_provenanced or set()
    required = tuple(required_ids or ())
    if required and all(cid in cleared for cid in required):
        return "ASSESSED_WITHIN_DECLARED_SCOPE"
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
