"""Owner-journey service wiring (M1): the public CLI route consumes an owner-signed bundle.

Covers: staging, the approve gate, denial before mutation, authorize->claim->isolate->collect->
observed receipt, replay refusal, honest interrupt on an unauthenticated collection, and the
verify seam (fixture-class provenance never clears; owner-class provenance reaches
scope-complete).

The backend here is a test seam that produces real collector-protocol bytes without a container.
Fixture trust roots prove wiring mechanics only and can never clear production (C5 preserved).
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import time
from pathlib import Path

import pytest

import hermes_code_assurance.owner_authority as oa
from hermes_code_assurance import owner_execution, service
from hermes_code_assurance.contracts import parse_contract
from hermes_code_assurance.owner_authority import TrustRoot
from hermes_code_assurance.sandbox import IsolationAttestation, ProcessObservation, SandboxPolicy
from hermes_code_assurance.store import AssessmentStore
from tests.auth_helpers import FixtureKey, write_trust_file

NOW = int(time.time())


# ---------------------------------------------------------------------------- fixtures


@pytest.fixture
def foreign_identity(monkeypatch):
    """The executing identity cannot control the (simulated) owner trust file."""
    class ForeignIdentity:
        uid = 999_999

        @staticmethod
        def can_write(path):
            return False

        @classmethod
        def current(cls):
            return cls()

    monkeypatch.setattr(
        oa.EffectiveIdentity, "current", classmethod(lambda cls: ForeignIdentity())
    )


@pytest.fixture
def tiny_toolchain(tmp_path, monkeypatch):
    """A cheap stand-in for the pytest site-packages the real journey freezes."""
    source = tmp_path / "toolchain-source"
    source.mkdir(mode=0o755)
    for name in ("pytest", "pluggy", "iniconfig", "_pytest", "packaging", "pygments"):
        package = source / name
        package.mkdir()
        (package / "__init__.py").write_text(f"# {name}\n")
    (source / "py.py").write_text("# py\n")
    monkeypatch.setattr(owner_execution, "toolchain_source", lambda: source)
    return source


@pytest.fixture
def trust_fixture(tmp_path):
    """A fixture trust root plus the key whose signature proves wiring mechanics."""
    key = FixtureKey(tmp_path, "journey-key")
    trust = tmp_path / "trust" / "owner-keys.json"
    trust.parent.mkdir(mode=0o755)
    write_trust_file(trust, {"journey-fixture": key.public})
    return key, trust


@pytest.fixture
def state(tmp_path):
    (directory := tmp_path / "state").mkdir(mode=0o700)
    return directory


# ---------------------------------------------------------------------------- helpers


def _journey_contract_body() -> dict:
    """The one frozen journey contract (identical body for any assessment that uses it)."""
    return {
        "schema": "check-contract-v1",
        "goal": "journey: one harmless arithmetic check, owner-approved",
        "assessed_areas": ["calc/ops.py"],
        "required_checks": [{
            "check_id": "calc-oracle",
            "label": "oracle arithmetic",
            "kind": "test-run",
            "argv": list(owner_execution.JOURNEY_CHECK_ARGV),
            "cwd": ".",
            "parser_id": "junit-xml",
            "expected_collection": {"tests": 3},
            "oracle": {"allowed_failures": 0, "description": "calc fixture oracle"},
            "executable": True,
        }],
        "env_allowlist": sorted(owner_execution.JOURNEY_ENV),
        "network_enabled": False,
        "model_enabled": False,
        "supported_platforms": ["linux"],
        "proposed_by": "review",
    }


def _plan_journey(state: Path) -> tuple[str, str]:
    candidate = state.parent / "candidate"
    (candidate / "calc").mkdir(parents=True, exist_ok=True)
    (candidate / "calc" / "ops.py").write_text("def add(a, b):\n    return a + b\n")
    inspected = service.inspect_candidate(str(state), str(candidate))
    frozen = parse_contract(_journey_contract_body())
    service.plan_checks(str(state), frozen.to_dict(), inspected["assessment_id"])
    return inspected["assessment_id"], frozen.contract_id


def _stage(state: Path, aid: str, tmp_path: Path) -> dict:
    oracle_src = tmp_path / "oracle-src" / "tests"
    oracle_src.parent.mkdir(parents=True, exist_ok=True)
    oracle_src.mkdir(exist_ok=True)
    (oracle_src / "test_ops.py").write_text(
        "def test_add():\n    assert True\n"
        "def test_sub():\n    assert True\n"
        "def test_mul():\n    assert True\n"
    )
    return service.stage_journey(str(state), aid, oracle_source=str(oracle_src.parent))


def _candidate_repo(tmp_path: Path, name: str = "candidate") -> Path:
    candidate = tmp_path / name
    (candidate / "calc").mkdir(parents=True, exist_ok=True)
    (candidate / "calc" / "ops.py").write_text("def add(a, b):\n    return a + b\n")
    return candidate


def _prepare(tmp_path: Path, state: Path) -> tuple[str, str, dict]:
    """inspect + plan + stage + the exact operation values the operator script would sign."""
    aid, contract_id = _plan_journey(state)
    bundle = _stage(state, aid, tmp_path)
    operation = {
        "schema_version": 1, "owner": "journey-fixture", "route": "cli",
        "data_root": str(state), "assessment_id": aid, "attempt": 1,
        "attempt_id": "att-journey00001", "check_id": "calc-oracle",
        "candidate_digest": _candidate_digest(state, aid), "contract_id": contract_id,
        "image": owner_execution.JOURNEY_IMAGE, "network": "none",
        "argv": list(owner_execution.JOURNEY_CHECK_ARGV),
        "limits": bundle["limits"],
        "oracle_digest": bundle["oracle_digest"],
        "toolchain_digest": bundle["toolchain_digest"],
        "collector_digest": bundle["collector_digest"],
        "isolation_policy_digest": bundle["policy_digest"],
        "env_digest": bundle["env_digest"],
    }
    return aid, contract_id, operation


class FakeBackend:
    """Never runs a container; emits real collector-protocol bytes."""

    collector_id = "fake-protected-collector-v1"

    def __init__(self, *, junit: bytes, exit_code: int = 0, authenticated: bool = True):
        self.junit = junit
        self.exit_code = exit_code
        self.authenticated = authenticated
        self.policies: list[SandboxPolicy] = []

    @property
    def verified(self) -> bool:
        return True

    def attest(self, policy: SandboxPolicy, inputs) -> IsolationAttestation:
        self.policies.append(policy)
        return IsolationAttestation(
            ok=True, policy_digest=policy.digest(), image=policy.image, image_id="sha256:fake",
            checks=[{"name": "fixture", "ok": True, "expected": 1, "observed": 1}],
            probe_output_sha256="f" * 64, python="3.11.0", kernel="fixture",
            sha256=hashlib.sha256(json.dumps({"p": policy.digest()}).encode()).hexdigest(),
        )

    def run_check(self, *, policy, inputs, check_argv, attempt_id, attestation):
        if self.authenticated:
            output = _collector_stream(os.urandom(16).hex().encode(), self.junit, self.exit_code)
        else:
            output = b"hostile noise without any collector protocol\n"
        return ProcessObservation(
            container_id="0" * 64, name="assure-fake", exit_code=self.exit_code,
            timed_out=False, truncated=False, oom_killed=False, runtime_error="",
            output=output, output_sha256=hashlib.sha256(output).hexdigest(),
            started_at="2026-10-18T10:00:00Z", finished_at="2026-10-18T10:00:03Z",
            duration_seconds=3.0, container_removed=True, cleanup_verified=True,
            launch_digest=hashlib.sha256(b"fake-launch").hexdigest(), problems=[],
        )


def _collector_stream(nonce: bytes, junit: bytes, exit_code: int) -> bytes:
    header = {
        "v": 1, "exit_code": exit_code, "signal": None,
        "child_output_b64": "", "child_output_bytes": 0,
        "child_output_sha256": hashlib.sha256(b"").hexdigest(),
        "child_output_truncated": False, "junit_present": True,
        "junit_b64": base64.b64encode(junit).decode(), "junit_bytes": len(junit),
        "junit_sha256": hashlib.sha256(junit).hexdigest(), "junit_problem": None,
        "deadline_exceeded": False,
    }
    return (
        b"::ASSURE-NONCE-v1 " + nonce + b"\n"
        + b"::ASSURE-RESULT-v1 " + nonce + b" " + json.dumps(header).encode() + b"\n"
    )


def _junit(passing=True) -> bytes:
    failure = "<failure message='boom'/>" if not passing else ""
    return (
        "<testsuite name='oracle' tests='3'"
        f" failures='{0 if passing else 1}' errors='0' skipped='0'>"
        "<testcase classname='test_ops' name='test_add'/>"
        "<testcase classname='test_ops' name='test_sub'/>"
        f"<testcase classname='test_ops' name='test_mul'>{failure}</testcase>"
        "</testsuite>"
    ).encode()


def _store(state: Path) -> AssessmentStore:
    store = AssessmentStore(str(state / "assessments.db"))
    store.initialize()
    return store


def _candidate_digest(state: Path, aid: str) -> str:
    return _store(state).get_assessment(aid)["payload"]["inventory_digest"]


def _signed(tmp_path: Path, key: FixtureKey, operation: dict, *, expires: int = NOW + 1800):
    body = {
        "schema": "code-assurance-owner-request-v1", "summary": "journey fixture approval",
        "operation": operation, "nonce": os.urandom(16).hex(),
        "issued_at": NOW, "expires_at": expires, "max_uses": 1,
    }
    # Every signed bundle lives under its own name: overwriting a shared path would silently
    # turn a replay probe into a fresh signature.
    body_bytes = (json.dumps(body, sort_keys=True, indent=2) + "\n").encode()
    name = hashlib.sha256(body_bytes).hexdigest()[:12]
    request = tmp_path / f"request-{name}.json"
    signature = tmp_path / f"request-{name}.sig"
    request.write_bytes(body_bytes)
    signature.write_bytes(key.sign(body_bytes))
    return request, signature


def _approve_and_run(state: Path, aid: str, operation: dict, key, trust, tmp_path: Path,
                     backend: FakeBackend):
    request, signature = _signed(tmp_path, key, operation)
    service.approve_contract(
        str(state), aid, owner_keys=str(trust), owner_request=str(request),
        owner_signature=str(signature),
    )
    return service.run_owner_journey(
        str(state), aid, owner_keys=str(trust), owner_request=str(request),
        owner_signature=str(signature), backend=backend,
    )


def _ledger(state: Path):
    return oa.AuthorityLedger(state / "authority-ledger.db")


# ---------------------------------------------------------------------------- tests


def test_stage_journey_publishes_the_exact_scope_to_sign(tmp_path, state, tiny_toolchain):
    aid, _ = _plan_journey(state)
    bundle = _stage(state, aid, tmp_path)
    assert set(bundle) >= {
        "assessment_id", "contract_id", "candidate_digest", "oracle_digest", "toolchain_digest",
        "collector_digest", "policy_digest", "env_digest", "argv", "image", "limits",
    }
    assert bundle["assessment_id"] == aid
    assert bundle["argv"] == list(owner_execution.JOURNEY_CHECK_ARGV)
    assert bundle["limits"]["timeout_seconds"] == 60
    assert (state / "journey" / "oracle").is_dir()
    again = _stage(state, aid, tmp_path)
    assert again["status"] == "ALREADY_STAGED"  # exclusive staging: never silently overwritten


def test_approve_refuses_wrong_scope_and_keeps_state(
    tmp_path, state, tiny_toolchain, trust_fixture, foreign_identity
):
    key, trust = trust_fixture
    aid, _, operation = _prepare(tmp_path, state)
    wrong = dict(operation, check_id="a-different-check")
    request, signature = _signed(tmp_path, key, wrong)
    with pytest.raises(oa.AuthorityDenied):
        service.approve_contract(
            str(state), aid, owner_keys=str(trust), owner_request=str(request),
            owner_signature=str(signature),
        )
    assert _store(state).get_assessment(aid)["state"] == "CONTRACT_REVIEW_REQUIRED"


def test_approve_refuses_an_edited_request_kept_under_a_valid_signature(
    tmp_path, state, tiny_toolchain, trust_fixture, foreign_identity
):
    key, trust = trust_fixture
    aid, _, operation = _prepare(tmp_path, state)
    request, signature = _signed(tmp_path, key, operation)
    tampered = tmp_path / "tampered.json"
    tampered.write_bytes(
        (json.dumps({**json.loads(request.read_text()), "summary": "edited"},
                    sort_keys=True, indent=2) + "\n").encode()
    )
    with pytest.raises(oa.AuthorityDenied):
        service.approve_contract(
            str(state), aid, owner_keys=str(trust), owner_request=str(tampered),
            owner_signature=str(signature),
        )
    assert _store(state).get_assessment(aid)["state"] == "CONTRACT_REVIEW_REQUIRED"


def test_approve_with_exact_scope_moves_state_to_approved(
    tmp_path, state, tiny_toolchain, trust_fixture, foreign_identity
):
    key, trust = trust_fixture
    aid, _, operation = _prepare(tmp_path, state)
    request, signature = _signed(tmp_path, key, operation)
    result = service.approve_contract(
        str(state), aid, owner_keys=str(trust), owner_request=str(request),
        owner_signature=str(signature),
    )
    assert result["state"] == "APPROVED"
    assert result["authorization"]["authority_class"] == "owner"
    assert _store(state).get_assessment(aid)["state"] == "APPROVED"


def test_run_without_a_bundle_keeps_the_default_denial(
    tmp_path, state, tiny_toolchain, trust_fixture, foreign_identity
):
    key, trust = trust_fixture
    aid, _, operation = _prepare(tmp_path, state)
    request, signature = _signed(tmp_path, key, operation)
    service.approve_contract(
        str(state), aid, owner_keys=str(trust), owner_request=str(request),
        owner_signature=str(signature),
    )
    result = service.run_checks(str(state), aid, caller="cli")
    store = _store(state)
    receipts = store.receipts(aid)
    assert result["status"] == "EXECUTION_UNAVAILABLE"
    assert all(r["payload"]["status"] == "NOT_RUN" for r in receipts)
    assert store.get_assessment(aid)["state"] == "EXECUTION_UNAVAILABLE"


def test_run_with_valid_bundle_executes_the_observed_pass(
    tmp_path, state, tiny_toolchain, trust_fixture, foreign_identity
):
    key, trust = trust_fixture
    aid, _, operation = _prepare(tmp_path, state)
    backend = FakeBackend(junit=_junit(passing=True))
    result = _approve_and_run(state, aid, operation, key, trust, tmp_path, backend)
    assert result["status"] == "EXECUTED"
    store = _store(state)
    executed = [r["payload"] for r in store.receipts(aid)
                if r["payload"]["check_id"] == "calc-oracle"]
    assert len(executed) == 1
    receipt = executed[0]
    assert receipt["status"] == "PASSED"
    assert receipt["counts"] == {
        "collected": 3, "passed": 3, "failed": 0, "errors": 0, "skipped": 0
    }
    assert receipt["observed"]["exit_code"] == 0
    assert receipt["collector"] == FakeBackend.collector_id
    assert receipt["observation_origin"] == "protected-collector-nonce-v1"
    assert receipt["grant_ref"]
    assert receipt["caller"] == "cli"
    assert store.get_assessment(aid)["state"] == "RUNNING"  # verify() finalizes to ASSESSED
    claims = _ledger(state)._read("SELECT * FROM claims")
    assert len(claims) == 1
    rows = _ledger(state)._read("SELECT * FROM executions")
    assert len(rows) == 1 and rows[0]["receipt_id"] == receipt["receipt_id"]
    assert backend.policies
    assert backend.policies[0].digest() == operation["isolation_policy_digest"]


def test_run_refuses_forged_or_expired_bundles_before_any_mutation(
    tmp_path, state, tiny_toolchain, trust_fixture, foreign_identity
):
    key, trust = trust_fixture
    aid, _, operation = _prepare(tmp_path, state)
    request, signature = _signed(tmp_path, key, operation)
    service.approve_contract(
        str(state), aid, owner_keys=str(trust), owner_request=str(request),
        owner_signature=str(signature),
    )
    forged = _signed(tmp_path, key, dict(operation, candidate_digest="a" * 64))
    expired = _signed(tmp_path, key, operation, expires=NOW - 10)
    for bundle in (forged, expired):
        with pytest.raises(oa.AuthorityDenied):
            service.run_owner_journey(
                str(state), aid, owner_keys=str(trust), owner_request=str(bundle[0]),
                owner_signature=str(bundle[1]), backend=FakeBackend(junit=_junit()),
            )
    store = _store(state)
    assert not store.receipts(aid)
    assert store.get_assessment(aid)["state"] == "APPROVED"


def test_replay_of_a_consumed_signature_is_refused(
    tmp_path, state, tiny_toolchain, trust_fixture, foreign_identity
):
    key, trust = trust_fixture
    aid, _, operation = _prepare(tmp_path, state)
    request, signature = _signed(tmp_path, key, operation)
    service.approve_contract(
        str(state), aid, owner_keys=str(trust), owner_request=str(request),
        owner_signature=str(signature),
    )
    first = service.run_owner_journey(
        str(state), aid, owner_keys=str(trust), owner_request=str(request),
        owner_signature=str(signature), backend=FakeBackend(junit=_junit()),
    )
    assert first["status"] == "EXECUTED"
    # A second assessment approved by its own fresh bundle (same frozen contract body), then
    # offered the CONSUMED one: the same signed request can never run twice — the ledger claim
    # is the durable memory.
    second = service.inspect_candidate(str(state), str(_candidate_repo(tmp_path, "candidate-2")))
    service.plan_checks(str(state), parse_contract(_journey_contract_body()).to_dict(),
                        second["assessment_id"])
    fresh = _signed(tmp_path, key, dict(operation, assessment_id=second["assessment_id"]))
    service.approve_contract(
        str(state), second["assessment_id"], owner_keys=str(trust),
        owner_request=str(fresh[0]), owner_signature=str(fresh[1]),
    )
    with pytest.raises(oa.AuthorityDenied) as caught:
        service.run_owner_journey(
            str(state), second["assessment_id"], owner_keys=str(trust),
            owner_request=str(request), owner_signature=str(signature),
            backend=FakeBackend(junit=_junit()),
        )
    assert any("already consumed" in reason for reason in caught.value.reasons)
    assert len(_store(state).receipts(second["assessment_id"])) == 0
    assert len(_ledger(state)._read("SELECT * FROM claims")) == 1


def test_failing_candidate_comes_out_failed_not_passed(
    tmp_path, state, tiny_toolchain, trust_fixture, foreign_identity
):
    key, trust = trust_fixture
    aid, _, operation = _prepare(tmp_path, state)
    result = _approve_and_run(
        state, aid, operation, key, trust, tmp_path,
        FakeBackend(junit=_junit(passing=False), exit_code=1),
    )
    assert result["status"] == "EXECUTED"  # the run completed; the finding is honest
    receipt = next(r["payload"] for r in _store(state).receipts(aid)
                   if r["payload"]["check_id"] == "calc-oracle")
    assert receipt["status"] == "FAILED"
    assert receipt["counts"]["failed"] == 1


def test_unauthenticated_collection_interrupts_never_passes(
    tmp_path, state, tiny_toolchain, trust_fixture, foreign_identity
):
    key, trust = trust_fixture
    aid, _, operation = _prepare(tmp_path, state)
    _approve_and_run(
        state, aid, operation, key, trust, tmp_path,
        FakeBackend(junit=_junit(), authenticated=False),
    )
    store = _store(state)
    receipt = next(r["payload"] for r in store.receipts(aid)
                   if r["payload"]["check_id"] == "calc-oracle")
    assert receipt["status"] == "INTERRUPTED"
    assert receipt["counts"] is None
    assert store.get_assessment(aid)["state"] == "INTERRUPTED"


def test_verify_owner_provenance_reaches_scope_complete(
    tmp_path, state, tiny_toolchain, trust_fixture, foreign_identity
):
    """owner-class ledger provenance (independently recorded) clears to scope-complete at verify."""
    key, trust = trust_fixture
    aid, _, operation = _prepare(tmp_path, state)
    _approve_and_run(state, aid, operation, key, trust, tmp_path, FakeBackend(junit=_junit()))
    result = service.verify(str(state), aid, caller="cli")
    assert result["overall_status"] == "ASSESSED_WITHIN_DECLARED_SCOPE"
    assert result["verification"][0]["status"] == "PASSED"
    assert result["verification"][0]["provenance"]
    assert result["missing_required"] == []


def test_verify_fixture_provenance_stays_unknown_and_incomplete(
    tmp_path, state, tiny_toolchain, trust_fixture, foreign_identity, monkeypatch
):
    """A fixture-class trust root proves mechanics; its provenance never clears production."""
    key, trust = trust_fixture
    aid, _, operation = _prepare(tmp_path, state)
    request, signature = _signed(tmp_path, key, operation)
    service.approve_contract(  # approval requires owner-class: before the patch below
        str(state), aid, owner_keys=str(trust), owner_request=str(request),
        owner_signature=str(signature),
    )
    monkeypatch.setattr(owner_execution, "load_trust_root", TrustRoot.load_fixture)
    result = service.run_owner_journey(
        str(state), aid, owner_keys=str(trust), owner_request=str(request),
        owner_signature=str(signature), backend=FakeBackend(junit=_junit()),
    )
    assert result["authorization"]["authority_class"] == "fixture"
    verified = service.verify(str(state), aid, caller="cli")
    assert verified["verification"][0]["status"] == "UNKNOWN"
    assert verified["verification"][0]["provenance"] is None
    assert verified["overall_status"] == "INCOMPLETE"
