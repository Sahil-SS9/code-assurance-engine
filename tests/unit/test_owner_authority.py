"""Owner authority (C0.2 kernel): signed exact-scope requests, enrolled keys, one-use claims.

Every key here is an EPHEMERAL evaluator key. These tests prove the verification mechanics and the
refusal matrix; they are NOT a real owner-approved journey.
"""

from __future__ import annotations

import base64
import copy
import json
import os

import pytest

from hermes_code_assurance import owner_authority as oa
from tests.auth_helpers import FixtureKey, make_operation, write_trust_file

NOW = 1_800_000_000
ONE_HOUR = 3600


def _identity(uid=424242, writable=False):
    """A stand-in for the executing identity (the REAL policy code runs against it)."""
    return oa.EffectiveIdentity(uid=uid, can_write=lambda _path: writable)


def _signed(key, operation=None, *, nonce="n" * 32, issued=NOW - 10, expires=NOW + ONE_HOUR,
            summary="run the harmless fixture check"):
    operation = make_operation() if operation is None else operation
    request = oa.build_request_bytes(
        operation, nonce=nonce, issued_at=issued, expires_at=expires, summary=summary
    )
    return request, key.sign_b64(request)


@pytest.fixture
def world(tmp_path):
    key = FixtureKey(tmp_path, "owner-fixture")
    trust_file = write_trust_file(tmp_path / "owner-keys.json", {"sahil": key.public})
    trust = oa.TrustRoot.load_fixture(trust_file)
    ledger = oa.AuthorityLedger(tmp_path / "authority" / "ledger.db")
    ledger.ensure()
    authority = oa.OwnerAuthority(trust, ledger, clock=lambda: NOW)
    return {"key": key, "trust_file": trust_file, "trust": trust, "ledger": ledger,
            "authority": authority, "tmp": tmp_path}


# ---------------------------------------------------------------- happy path and request format


def test_valid_request_is_authorised_and_reports_its_authority_class(world):
    request, signature = _signed(world["key"])
    auth = world["authority"].evaluate(request, signature, make_operation())
    assert auth.owner == "sahil"
    assert auth.key_id == world["key"].key_id
    assert auth.authority_class == "fixture"  # a fixture trust root can never claim 'owner'
    assert auth.nonce == "n" * 32
    assert auth.expires_at == NOW + ONE_HOUR
    assert auth.operation == make_operation()


def test_request_bytes_are_canonical_human_readable_json(world):
    request, _ = _signed(world["key"])
    text = request.decode()
    assert text.endswith("\n") and "\n  " in text, "indented for the human who signs it"
    body = json.loads(text)
    assert body["schema"] == oa.REQUEST_SCHEMA and body["max_uses"] == 1
    assert body["operation"] == make_operation()
    assert request == oa.build_request_bytes(
        make_operation(), nonce="n" * 32, issued_at=NOW - 10, expires_at=NOW + ONE_HOUR,
        summary="run the harmless fixture check",
    ), "deterministic bytes: what the owner signed is exactly reproducible"


def test_signature_accepts_base64_text_with_trailing_newline_and_raw_bytes(world):
    request, signature = _signed(world["key"])
    world["authority"].evaluate(request, signature + "\n", make_operation())
    world["authority"].evaluate(request, base64.b64decode(signature), make_operation())


# ---------------------------------------------------------------- forged / unsigned / wrong key


def test_flipped_signature_bit_is_refused(world):
    request, signature = _signed(world["key"])
    raw = bytearray(base64.b64decode(signature))
    raw[10] ^= 0x04
    with pytest.raises(oa.AuthorityDenied) as caught:
        world["authority"].evaluate(request, bytes(raw), make_operation())
    assert any("signature" in r for r in caught.value.reasons)


def test_request_edited_after_signing_is_refused(world):
    request, signature = _signed(world["key"])
    with pytest.raises(oa.AuthorityDenied) as caught:
        world["authority"].evaluate(request + b" ", signature, make_operation())
    assert any("signature" in r for r in caught.value.reasons)


def test_signature_from_an_unenrolled_key_is_refused(world):
    attacker = FixtureKey(world["tmp"], "attacker")
    request, signature = _signed(attacker)
    with pytest.raises(oa.AuthorityDenied) as caught:
        world["authority"].evaluate(request, signature, make_operation())
    assert any("signature" in r for r in caught.value.reasons)


def test_wrong_actor_operation_names_an_owner_that_is_not_enrolled(world):
    operation = make_operation(owner="mallory")
    request, signature = _signed(world["key"], operation)  # enrolled key signs, wrong actor named
    with pytest.raises(oa.AuthorityDenied) as caught:
        world["authority"].evaluate(request, signature, operation)
    assert any("not enrolled" in r for r in caught.value.reasons)


def test_actor_swap_enrolled_key_of_a_different_owner_is_refused(world):
    other = FixtureKey(world["tmp"], "bob")
    trust_file = write_trust_file(
        world["tmp"] / "two.json", {"sahil": world["key"].public, "bob": other.public}
    )
    authority = oa.OwnerAuthority(oa.TrustRoot.load_fixture(trust_file), world["ledger"],
                                  clock=lambda: NOW)
    operation = make_operation(owner="sahil")
    request, signature = _signed(other, operation)  # bob signs a request naming sahil
    with pytest.raises(oa.AuthorityDenied) as caught:
        authority.evaluate(request, signature, operation)
    assert any("signature" in r for r in caught.value.reasons)


@pytest.mark.parametrize("signature", [b"", b"x" * 63, b"x" * 65, "not base64 !!", None, 12345])
def test_malformed_or_absent_signature_is_refused(world, signature):
    request, _ = _signed(world["key"])
    with pytest.raises(oa.AuthorityDenied):
        world["authority"].evaluate(request, signature, make_operation())


# ---------------------------------------------------------------- time, lifetime, use count


def test_expired_request_is_refused(world):
    request, signature = _signed(world["key"], expires=NOW)
    with pytest.raises(oa.AuthorityDenied) as caught:
        world["authority"].evaluate(request, signature, make_operation())
    assert any("expired" in r for r in caught.value.reasons)


def test_request_issued_in_the_future_is_refused(world):
    request, signature = _signed(world["key"], issued=NOW + 3600, expires=NOW + 7200)
    with pytest.raises(oa.AuthorityDenied) as caught:
        world["authority"].evaluate(request, signature, make_operation())
    assert any("issued in the future" in r for r in caught.value.reasons)


def test_excessive_lifetime_is_refused(world):
    request, signature = _signed(world["key"], issued=NOW - 10, expires=NOW + 3 * 86400)
    with pytest.raises(oa.AuthorityDenied) as caught:
        world["authority"].evaluate(request, signature, make_operation())
    assert any("lifetime" in r for r in caught.value.reasons)


def _signed_body(key, mutate):
    body = {
        "schema": oa.REQUEST_SCHEMA, "summary": "s", "operation": make_operation(),
        "nonce": "n" * 32, "issued_at": NOW - 10, "expires_at": NOW + ONE_HOUR, "max_uses": 1,
    }
    mutate(body)
    request = (json.dumps(body, sort_keys=True, indent=2) + "\n").encode()
    return request, key.sign_b64(request)


@pytest.mark.parametrize(
    "mutate,needle",
    [
        (lambda b: b.update(max_uses=2), "max_uses"),
        (lambda b: b.update(max_uses=True), "max_uses"),
        (lambda b: b.update(schema="other"), "schema"),
        (lambda b: b.update(extra="field"), "unknown"),
        (lambda b: b.pop("nonce"), "missing"),
        (lambda b: b.update(nonce="short"), "nonce"),
        (lambda b: b.update(issued_at="yesterday"), "issued_at"),
        (lambda b: b["operation"].pop("candidate_digest"), "operation fields"),
        (lambda b: b["operation"].update(surprise=1), "operation fields"),
    ],
)
def test_structurally_invalid_signed_requests_are_refused(world, mutate, needle):
    request, signature = _signed_body(world["key"], mutate)
    with pytest.raises(oa.AuthorityDenied) as caught:
        world["authority"].evaluate(request, signature, make_operation())
    assert any(needle in r for r in caught.value.reasons), caught.value.reasons


def test_non_object_oversized_and_duplicate_key_requests_are_refused(world):
    key = world["key"]
    for raw in (b"[1,2,3]", b"x" * 70000, b'{"schema": "a", "schema": "b"}', b"\xff\xfe"):
        with pytest.raises(oa.AuthorityDenied):
            world["authority"].evaluate(raw, key.sign_b64(raw), make_operation())
    with pytest.raises(oa.AuthorityDenied) as caught:  # (openssl cannot sign empty input)
        world["authority"].evaluate(b"", "A" * 88, make_operation())
    assert any("no signed request" in r for r in caught.value.reasons)


# ---------------------------------------------------------------- exact-scope binding


BINDING_FIELDS = [
    ("owner", "someone-else"),
    ("route", "slash"),
    ("data_root", "/another/profile/plugin-data/code-assurance-engine"),
    ("assessment_id", "9" * 64),
    ("attempt", 2),
    ("attempt_id", "att-ffffffffffff"),
    ("check_id", "other-check"),
    ("candidate_digest", "9" * 64),
    ("contract_id", "9" * 64),
    ("oracle_digest", "9" * 64),
    ("toolchain_digest", "9" * 64),
    ("collector_digest", "9" * 64),
    ("image", "python@sha256:" + "9" * 64),
    ("isolation_policy_digest", "9" * 64),
    ("argv", ["python", "-c", "print(1)"]),
    ("env_digest", "9" * 64),
    ("limits", {"timeout_seconds": 600, "output_limit_bytes": 1, "memory_mb": 4096, "pids": 9999,
                "cpus": 64}),
    ("network", "host"),
]


@pytest.mark.parametrize("field,value", BINDING_FIELDS, ids=[f for f, _ in BINDING_FIELDS])
def test_every_scope_field_is_bound_wrong_source_contract_attempt_etc(world, field, value):
    signed_for = make_operation(**{field: value})
    request, signature = _signed(world["key"], signed_for)
    actual_run = make_operation()  # what the engine would really run
    with pytest.raises(oa.AuthorityDenied) as caught:
        world["authority"].evaluate(request, signature, actual_run)
    joined = "; ".join(caught.value.reasons)
    assert field in joined or "not enrolled" in joined, joined


def test_signed_scope_must_match_the_run_exactly_including_field_types(world):
    request, signature = _signed(world["key"], make_operation(attempt=True))
    with pytest.raises(oa.AuthorityDenied):
        world["authority"].evaluate(request, signature, make_operation(attempt=1))


# ---------------------------------------------------------------- replay and the ledger


def test_replay_of_a_consumed_request_is_refused(world):
    request, signature = _signed(world["key"])
    auth = world["authority"].evaluate(request, signature, make_operation())
    world["ledger"].claim(auth, now=NOW)
    with pytest.raises(oa.AuthorityDenied) as caught:
        world["authority"].evaluate(request, signature, make_operation())
    assert any("already consumed" in r for r in caught.value.reasons)


def test_a_re_signed_request_with_the_same_nonce_is_still_a_replay(world):
    request, signature = _signed(world["key"])
    auth = world["authority"].evaluate(request, signature, make_operation())
    world["ledger"].claim(auth, now=NOW)
    again, again_sig = _signed(world["key"], summary="different words, same nonce")
    with pytest.raises(oa.AuthorityDenied) as caught:
        world["authority"].evaluate(again, again_sig, make_operation())
    assert any("already consumed" in r for r in caught.value.reasons)


def test_evaluation_never_writes_the_ledger(world):
    request, signature = _signed(world["key"])
    before = world["ledger"].path.read_bytes()
    world["authority"].evaluate(request, signature, make_operation())
    assert world["ledger"].path.read_bytes() == before
    assert not world["ledger"].is_claimed("n" * 32)


# ---------------------------------------------------------------- trust root policy


def test_owner_trust_root_refuses_a_location_the_executing_identity_controls(tmp_path):
    key = FixtureKey(tmp_path)
    trust_file = write_trust_file(tmp_path / "owner-keys.json", {"sahil": key.public})
    with pytest.raises(oa.AuthorityDenied) as caught:
        oa.TrustRoot.load_owner(trust_file)  # the REAL identity: we own this file
    assert any("controlled by the executing identity" in r for r in caught.value.reasons)


def test_owner_trust_root_accepts_a_foreign_owned_non_writable_location(tmp_path):
    key = FixtureKey(tmp_path)
    trust_file = write_trust_file(tmp_path / "owner-keys.json", {"sahil": key.public})
    trust = oa.TrustRoot.load_owner(trust_file, identity=_identity())
    assert trust.authority_class == "owner"
    assert trust.key_for("sahil").key_id == key.key_id
    assert trust.key_for("nobody") is None


def test_owner_trust_root_refuses_when_the_identity_can_write_it(tmp_path):
    key = FixtureKey(tmp_path)
    trust_file = write_trust_file(tmp_path / "owner-keys.json", {"sahil": key.public})
    with pytest.raises(oa.AuthorityDenied) as caught:
        oa.TrustRoot.load_owner(trust_file, identity=_identity(writable=True))
    assert any("controlled by the executing identity" in r for r in caught.value.reasons)


def test_owner_trust_root_refuses_group_or_world_writable_files(tmp_path):
    key = FixtureKey(tmp_path)
    trust_file = write_trust_file(tmp_path / "owner-keys.json", {"sahil": key.public}, mode=0o664)
    with pytest.raises(oa.AuthorityDenied) as caught:
        oa.TrustRoot.load_owner(trust_file, identity=_identity())
    assert any("writable" in r for r in caught.value.reasons)


def test_owner_trust_root_refuses_symlinked_paths(tmp_path):
    key = FixtureKey(tmp_path)
    real = write_trust_file(tmp_path / "real.json", {"sahil": key.public})
    link = tmp_path / "link.json"
    link.symlink_to(real)
    with pytest.raises(oa.AuthorityDenied) as caught:
        oa.TrustRoot.load_owner(link, identity=_identity())
    assert any("symlink" in r for r in caught.value.reasons)


def test_owner_trust_root_refuses_a_missing_file(tmp_path):
    with pytest.raises(oa.AuthorityDenied):
        oa.TrustRoot.load_owner(tmp_path / "nope.json", identity=_identity())


@pytest.mark.parametrize(
    "mutate,needle",
    [
        (lambda b: b.update(schema="x"), "schema"),
        (lambda b: b.update(keys=[]), "at least one"),
        (lambda b: b["keys"][0].update(key_id="0" * 64), "key_id"),
        (lambda b: b["keys"][0].update(public_key_b64="!!!"), "public_key_b64"),
        (lambda b: b["keys"][0].update(public_key_b64=base64.b64encode(b"short").decode()), "32"),
        (lambda b: b["keys"][0].update(owner="Bad Owner!"), "owner"),
        (lambda b: b["keys"].append(copy.deepcopy(b["keys"][0])), "duplicate"),
        (lambda b: b.update(extra=1), "unknown"),
    ],
)
def test_malformed_trust_files_are_refused(tmp_path, mutate, needle):
    key = FixtureKey(tmp_path)
    trust_file = write_trust_file(tmp_path / "owner-keys.json", {"sahil": key.public})
    body = json.loads(trust_file.read_text())
    mutate(body)
    trust_file.write_text(json.dumps(body))
    for loader in (lambda p: oa.TrustRoot.load_owner(p, identity=_identity()),
                   oa.TrustRoot.load_fixture):
        with pytest.raises(oa.AuthorityDenied) as caught:
            loader(trust_file)
        assert any(needle in r for r in caught.value.reasons), caught.value.reasons


def test_a_fixture_trust_root_never_reports_the_owner_class(tmp_path):
    key = FixtureKey(tmp_path)
    trust_file = write_trust_file(tmp_path / "owner-keys.json", {"sahil": key.public})
    assert oa.TrustRoot.load_fixture(trust_file).authority_class == "fixture"


def test_effective_identity_reports_the_real_process_identity(tmp_path):
    identity = oa.EffectiveIdentity.current()
    assert identity.uid == os.geteuid()
    assert identity.can_write(str(tmp_path)) is True
    assert identity.can_write("/proc/version") is False
