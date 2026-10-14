"""Authority grant tests: identity binding, expiry, mismatch refusal, trusted-issuer requirement."""

from __future__ import annotations

import pytest

from hermes_code_assurance import authority


def _trusted_decision():
    return {"issuer": "outside-candidate-workspace", "decision_id": "dec-1"}


def _grant(**overrides):
    fields = {
        "grant_id": "g-1",
        "requester": "cli:root",
        "candidate_digest": "a" * 64,
        "contract_id": "b" * 64,
        "check_id": "unit-junit",
        "argv_sha256": "c" * 64,
        "env_sha256": "d" * 64,
        "expires_epoch_seconds": 9_999_999_999,
    }
    fields.update(overrides)
    return authority.TrustedGrant(**fields)


def _request(**overrides):
    fields = {
        "caller": "cli:root",
        "candidate_digest": "a" * 64,
        "contract_id": "b" * 64,
        "check_id": "unit-junit",
        "argv": ["python", "-m", "pytest"],
        "env_digest": "d" * 64,
        "now_epoch_seconds": 1_000_000,
    }
    fields.update(overrides)
    return authority.RunRequest(**fields)


def _digest_of(argv):
    return authority.argv_digest(argv)


def grant_with_real_argv(argv):
    return _grant(argv_sha256=_digest_of(argv))


def test_verify_grant_ok():
    grant = grant_with_real_argv(["python", "-m", "pytest"])
    result = authority.verify_grant(
        grant, _request(argv=["python", "-m", "pytest"]), trusted_decision=_trusted_decision()
    )
    assert result.granted
    assert result.refusals == []


@pytest.mark.parametrize(
    "field,value",
    [
        ("candidate_digest", "f" * 64),
        ("contract_id", "e" * 64),
        ("check_id", "other-check"),
        ("caller", "gateway:model-b"),
        ("env_digest", "1" * 64),
    ],
)
def test_every_identity_field_mismatch_denies(field, value):
    grant = grant_with_real_argv(["python", "-m", "pytest"])
    request = _request(**{field: value, "argv": ["python", "-m", "pytest"]})
    result = authority.verify_grant(
        grant, request, trusted_decision=_trusted_decision()
    )
    assert not result.granted
    assert result.refusals


def test_argv_mismatch_denies():
    grant = grant_with_real_argv(["python", "-m", "pytest", "-q"])
    result = authority.verify_grant(
        grant,
        _request(argv=["python", "-m", "pytest"]),
        trusted_decision=_trusted_decision(),
    )
    assert not result.granted


def test_expired_grant_denies():
    grant = grant_with_real_argv(["python"])
    result = authority.verify_grant(
        grant,
        _request(argv=["python"], now_epoch_seconds=10_000_000_001),
        trusted_decision=_trusted_decision(),
    )
    assert not result.granted
    assert any("expired" in r for r in result.refusals)


def test_missing_or_untrusted_decision_denies():
    grant = grant_with_real_argv(["python"])
    assert not authority.verify_grant(
        grant, _request(argv=["python"]), trusted_decision=None
    ).granted
    assert not authority.verify_grant(
        grant,
        _request(argv=["python"]),
        trusted_decision={"issuer": "candidate-workspace", "decision_id": "d"},
    ).granted, "a decision originating inside model-writable scope is not authority"


def test_json_approved_true_is_never_enough():
    grant = grant_with_real_argv(["python"])
    fake = {"approved": True, "signature": "markdown-looking", "approved_by_hash": "aa" * 32}
    result = authority.verify_grant(
        grant, _request(argv=["python"]), trusted_decision=fake
    )
    assert not result.granted


def test_deny_all_backend_with_full_details():
    result = authority.DenyAllAuthority().decision("any")
    assert not result.granted
    assert "EXECUTION_UNAVAILABLE" in result.refusals[0]
