"""C2 regression: the complete frozen contract survives plan→run→verify→findings.

Witnessed RED against the frozen base (review probe reproduced the reconstruction defect).
"""

from __future__ import annotations

from hermes_code_assurance import service
from hermes_code_assurance.contracts import parse_contract


def _nondefault_contract():
    return parse_contract(
        {
            "schema": "check-contract-v1",
            "goal": "REP-C2 owner goal: fidelity across consumers",
            "assessed_areas": ["tests/", "src/"],
            "required_checks": [
                {"check_id": "chk-main", "label": "main suite", "kind": "test-run",
                 "argv": ["python", "-m", "pytest", "-q"], "cwd": ".",
                 "parser_id": "junit-xml", "expected_collection": {"tests": 2},
                 "oracle": {"allowed_failures": 0, "description": "no tolerated failures"}},
            ],
            "optional_checks": [
                {"check_id": "chk-optional", "label": "optional lint", "kind": "static-tool",
                 "argv": ["ruff", "check", "."], "cwd": ".", "parser_id": None,
                 "executable": False},
            ],
            "negative_checks": [],
            "env_allowlist": ["PATH", "LANG", "LC_ALL"],
            "network_enabled": False,
            "model_enabled": False,
            "supported_platforms": ["linux"],
            "timeouts": {"per_check_seconds": 777, "total_seconds": 2222},
            "proposed_by": "human",
        }
    )


def test_contract_survives_all_consumers_unchanged(tmp_path):
    from hermes_code_assurance.store import AssessmentStore

    state = tmp_path / "state"
    candidate = tmp_path / "candidate"
    candidate.mkdir(parents=True)
    (candidate / "calc.py").write_text("x = 1\n")
    inspected = service.inspect_candidate(state, str(candidate))
    aid = inspected["assessment_id"]

    contract = _nondefault_contract()
    planned = service.plan_checks(state, contract.to_dict(), aid)
    assert planned["contract_id"] == contract.contract_id

    store = AssessmentStore(state / "assessments.db")
    store.initialize()
    stored = store.get_assessment(aid)["payload"]
    # C2: the complete canonical contract is stored verbatim and revalidates to the same id.
    assert "contract" in stored, "full frozen contract must be persisted"
    reloaded = parse_contract(stored["contract"])
    assert reloaded.contract_id == contract.contract_id
    assert reloaded.goal == "REP-C2 owner goal: fidelity across consumers"
    assert list(reloaded.env_allowlist) == ["PATH", "LANG", "LC_ALL"]
    assert required_test_count(reloaded) == 2
    assert reloaded.timeouts == (777, 2222)

    # Consumers must all see exactly the frozen contract id (run requires owner-approval state).
    store.set_state(aid, "APPROVED", old_state=store.get_assessment(aid)["state"])
    run_result = service.run_checks(state, aid, caller="cli:root")
    assert run_result["contract_id"] == contract.contract_id
    verify_result = service.verify(state, aid, caller="cli:root")
    assert verify_result["contract_id"] == contract.contract_id
    findings_result = service.findings(state, aid)
    assert findings_result["contract_id"] == contract.contract_id


def required_test_count(contract):
    return contract.required_checks[0].expected_collection[0]
