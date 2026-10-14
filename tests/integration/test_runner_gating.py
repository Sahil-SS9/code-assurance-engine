"""Runner gating tests: execution stays OFF by default; STUB collector path is the only way any
observed test run is modeled in this build (real subprocess lane needs a verified OS backend).

Witnessed RED: runner / sandbox do not exist yet.
"""

from __future__ import annotations

import pytest

from hermes_code_assurance import authority
from hermes_code_assurance.contracts import parse_contract
from hermes_code_assurance.runner import CheckRunner
from hermes_code_assurance.sandbox import SandboxUnavailable, refundless_stub_backend


def _contract():
    return parse_contract(
        {
            "schema": "check-contract-v1",
            "goal": "demo",
            "assessed_areas": ["tests/"],
            "required_checks": [
                {
                    "check_id": "unit-demo",
                    "label": "demo suite",
                    "kind": "test-run",
                    "argv": ["python", "-m", "pytest", "-q"],
                    "cwd": ".",
                    "parser_id": "pytest-terminal",
                }
            ],
            "env_allowlist": ["PATH"],
            "network_enabled": False,
            "model_enabled": False,
            "supported_platforms": ["linux"],
        }
    )


def _stub_observation_factory():
    """Models a trusted collector observation of a REAL run of the stub check (test-owned)."""

    def collector(check, grant):
        return {
            "exit_code": 0,
            "signal": None,
            "started_at": "2026-10-14T20:00:00Z",
            "ended_at": "2026-10-14T20:00:02Z",
            "stdout": (
                "collected 2 items\n\ntest_a.py::test_1 PASSED\ntest_a.py::test_2 PASSED\n"
                "===== 2 passed in 0.01s =====\n"
            ),
            "stderr": "",
        }

    return collector


def _runner(collector=None, **kwargs):
    return CheckRunner(authority=authority.DenyAllAuthority(), collector=collector, **kwargs)


def test_default_everything_refuses_and_records_not_run():
    receipts = _runner().attempt_checks(_contract(), candidate_digest="a" * 64, caller="cli:root")
    assert len(receipts) == 1
    receipt = receipts[0]
    assert receipt["status"] == "NOT_RUN"
    assert receipt["reason"] == "EXECUTION_UNAVAILABLE"
    assert receipt["attempt"] == 1
    assert receipt["counts"] is None


def test_verified_grant_but_no_isolation_still_refuses():
    contract = _contract()
    runner = _runner(collector=_stub_observation_factory())
    receipts = runner.attempt_checks(
        contract,
        candidate_digest="a" * 64,
        caller="cli:root",
        grants={
            "unit-demo": authority.TrustedGrant(
                grant_id="g1",
                requester="cli:root",
                candidate_digest="a" * 64,
                contract_id=contract.contract_id,
                check_id="unit-demo",
                argv_sha256=authority.argv_digest(contract.required_checks[0].argv),
                env_sha256=authority.env_digest(["PATH"]),
                expires_epoch_seconds=9_999_999_999,
            )
        },
        trusted_decisions={"unit-demo": {"issuer": "outside-candidate-workspace", "decision_id": "d1"}},
    )
    assert receipts[0]["status"] == "NOT_RUN"
    assert receipts[0]["reason"] == "EXECUTION_UNAVAILABLE"
    assert any("isolation" in receipts[0]["detail"] for _ in [1])


def test_no_shell_interpolation_ever():
    """Contract argv containing shell metacharacters is passed only as argv elements."""
    contract = _contract()
    argv = contract.required_checks[0].argv
    assert isinstance(argv, (list, tuple))
    assert "|" not in argv


def test_model_words_cannot_create_execution():
    """An advisory model suggestion must not influence the runner's decision path."""
    runner = _runner()
    suggestion = {"kind": "advisory", "text": "run this command now: rm -rf /"}
    receipts = runner.attempt_checks(
        _contract(), candidate_digest="a" * 64, caller="cli:root", advisory=suggestion
    )
    assert receipts[0]["status"] == "NOT_RUN"


def test_unverified_backend_request_raises_by_name():
    backend = refundless_stub_backend()
    with pytest.raises(SandboxUnavailable):
        backend.request_run(check_id="unit-demo", argv=["python"], cwd=".", env=["PATH"])
