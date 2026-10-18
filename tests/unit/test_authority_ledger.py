"""Authority ledger: durable one-use claims and execution provenance outside candidate control."""

from __future__ import annotations

import os
import stat
import threading

import pytest

from hermes_code_assurance import owner_authority as oa
from tests.auth_helpers import make_operation

NOW = 1_800_000_000


def _auth(nonce="n" * 32, assessment_id="a" * 64, authority_class="owner", **op):
    operation = make_operation(assessment_id=assessment_id, **op)
    return oa.Authorization(
        owner="sahil", key_id="k" * 64, authority_class=authority_class, nonce=nonce,
        request_sha256="r" * 64, issued_at=NOW - 5, expires_at=NOW + 3600, operation=operation,
    )


def _execution(**over):
    fields = {
        "receipt_id": "r1" * 32, "nonce": "n" * 32, "assessment_id": "a" * 64,
        "attempt_id": "att-0123456789ab", "check_id": "calc-oracle",
        "collector": "rootless-docker-collector-v1", "attestation_sha256": "5" * 64,
        "launch_digest": "6" * 64, "container_id": "7" * 64, "now": NOW,
    }
    fields.update(over)
    return fields


@pytest.fixture
def ledger(tmp_path):
    led = oa.AuthorityLedger(tmp_path / "authority" / "ledger.db")
    led.ensure()
    return led


def test_ledger_is_private_to_the_executing_user(ledger):
    directory = stat.S_IMODE(ledger.path.parent.stat().st_mode)
    file_mode = stat.S_IMODE(ledger.path.stat().st_mode)
    assert directory == 0o700 and file_mode == 0o600


def test_ensure_refuses_a_symlinked_ledger_file(tmp_path):
    directory = tmp_path / "authority"
    directory.mkdir(mode=0o700)
    target = tmp_path / "elsewhere.db"
    target.write_bytes(b"")
    (directory / "ledger.db").symlink_to(target)
    with pytest.raises(oa.AuthorityDenied):
        oa.AuthorityLedger(directory / "ledger.db").ensure()


def test_ensure_refuses_a_group_readable_ledger_directory(tmp_path):
    directory = tmp_path / "authority"
    directory.mkdir()
    directory.chmod(0o750)
    with pytest.raises(oa.AuthorityDenied):
        oa.AuthorityLedger(directory / "ledger.db").ensure()


def test_claim_is_one_use(ledger):
    ledger.claim(_auth(), now=NOW)
    assert ledger.is_claimed("n" * 32)
    with pytest.raises(oa.AuthorityDenied) as caught:
        ledger.claim(_auth(), now=NOW + 1)
    assert any("already consumed" in r for r in caught.value.reasons)


def test_claims_survive_a_restart(ledger):
    ledger.claim(_auth(), now=NOW)
    reopened = oa.AuthorityLedger(ledger.path)
    assert reopened.is_claimed("n" * 32)
    with pytest.raises(oa.AuthorityDenied):
        reopened.claim(_auth(), now=NOW + 5)


def test_exactly_one_of_many_concurrent_claims_wins(ledger):
    outcomes = []
    barrier = threading.Barrier(8)

    def worker():
        mine = oa.AuthorityLedger(ledger.path)
        barrier.wait()
        try:
            mine.claim(_auth(), now=NOW)
            outcomes.append("won")
        except oa.AuthorityDenied:
            outcomes.append("refused")

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sorted(outcomes) == ["refused"] * 7 + ["won"]


def test_attempt_count_is_per_assessment(ledger):
    assert ledger.attempt_count("a" * 64) == 0
    ledger.claim(_auth(nonce="1" * 32), now=NOW)
    ledger.claim(_auth(nonce="2" * 32), now=NOW)
    ledger.claim(_auth(nonce="3" * 32, assessment_id="b" * 64), now=NOW)
    assert ledger.attempt_count("a" * 64) == 2
    assert ledger.attempt_count("b" * 64) == 1


def test_execution_provenance_round_trips_and_binds_to_the_claim(ledger):
    ledger.claim(_auth(), now=NOW)
    ledger.record_execution(**_execution())
    found = ledger.provenance("r1" * 32)
    assert found["authority_class"] == "owner"
    assert found["owner"] == "sahil" and found["key_id"] == "k" * 64
    assert found["nonce"] == "n" * 32 and found["assessment_id"] == "a" * 64
    assert found["attempt_id"] == "att-0123456789ab" and found["check_id"] == "calc-oracle"
    assert found["collector"] == "rootless-docker-collector-v1"
    assert found["attestation_sha256"] == "5" * 64
    assert ledger.provenance("no-such-receipt") is None


def test_execution_without_a_claim_is_refused(ledger):
    with pytest.raises(oa.AuthorityDenied):
        ledger.record_execution(**_execution())


def test_one_execution_row_per_receipt(ledger):
    ledger.claim(_auth(), now=NOW)
    ledger.record_execution(**_execution())
    with pytest.raises(oa.AuthorityDenied):
        ledger.record_execution(**_execution())


def test_fixture_class_provenance_is_labelled_fixture(ledger):
    ledger.claim(_auth(authority_class="fixture"), now=NOW)
    ledger.record_execution(**_execution())
    assert ledger.provenance("r1" * 32)["authority_class"] == "fixture"


def test_open_existing_never_creates_a_ledger(tmp_path):
    missing = tmp_path / "authority" / "ledger.db"
    assert oa.AuthorityLedger.open_existing(missing) is None
    assert not missing.exists() and not missing.parent.exists()


def test_open_existing_reads_an_existing_ledger_read_only(ledger):
    ledger.claim(_auth(), now=NOW)
    ledger.record_execution(**_execution())
    reader = oa.AuthorityLedger.open_existing(ledger.path)
    assert reader.provenance("r1" * 32)["nonce"] == "n" * 32
    before = ledger.path.read_bytes()
    assert reader.provenance("other") is None
    assert ledger.path.read_bytes() == before
    assert os.path.exists(ledger.path)
