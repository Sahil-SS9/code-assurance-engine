"""Privacy tests (CT14-lite): scrub-before-persistence, identifier preservation, refuse-not-publish.

Witnessed RED: module does not exist yet.
"""

from __future__ import annotations

import json

import pytest

from hermes_code_assurance import privacy
from hermes_code_assurance.store import AssessmentStore

SEED_AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
SEED_TOKEN = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"


def test_aws_key_scrubbed_from_text():
    out = privacy.redact(f"aws creds {SEED_AWS_KEY} in log")
    assert SEED_AWS_KEY not in out
    assert "REDACTED" in out


def test_github_token_scrubbed():
    out = privacy.redact(f"token {SEED_TOKEN}")
    assert SEED_TOKEN not in out


def test_assignment_and_bearer_scrubbed():
    out = privacy.redact("authorization: Bearer abcdefghijklmnop; api_key = sk-proj0123456789abcdef")
    assert "abcdefghijklmnop" not in out
    assert "sk-proj0123456789abcdef" not in out


def test_identifier_shaped_values_preserved():
    sha = ("ba7816bf8f01cfea414140de5dae2223"
           "b00361a396177a9cb410ff61f20015ad")
    uid = "8b6dd9d6-6a2d-4d67-8b79-77bdaa2b5bcb"
    out = privacy.redact(f"sha {sha} uuid {uid}")
    assert sha in out
    assert uid in out


def test_drop_sensitive_keys_drops_not_truncates():
    scrubbed = privacy.scrub_record(
        {"password": "x" * 40, "authorization": "Bearer xx", "keep": "readme"}
    )
    assert "xx" not in json.dumps(scrubbed["password"]) or scrubbed["password"] != "x" * 40
    assert scrubbed["password"].startswith("[DROPPED") or scrubbed["password"] == "[DROPPED]"
    assert scrubbed["keep"] == "readme"


def test_scrub_nested_record():
    scrubbed = privacy.scrub_record({"env": {"WHATEVER": "passthrough-should-be-dropped"}})
    assert "passthrough-should-be-dropped" not in json.dumps(scrubbed)


def test_refusal_mode_refuses_residual_secrets():
    with pytest.raises(privacy.RedactionFailure):
        privacy.redact_or_refuse("residue akiaiosfodnn7example not caught by list")


def test_seed_secret_absent_from_every_file_the_store_writes(tmp_path):
    """CT14 gate: main db, WAL and journal sidecars included."""
    store = AssessmentStore(tmp_path / "state.db")
    store.initialize()
    store.create_assessment(
        "a1", "CREATED", {"candidate_digest": "0" * 64, "note": f"leak {SEED_TOKEN} leak"}
    )
    store.append_receipt("a1", {"receipt_id": "r1", "env_secret": SEED_AWS_KEY, "n": 1})
    payload = json.dumps(store.get_assessment("a1")["payload"])
    assert SEED_TOKEN not in payload
    receipt_payloads = [json.dumps(r["payload"]) for r in store.receipts("a1")]
    assert all(SEED_AWS_KEY not in p or "[DROPPED" in p for p in receipt_payloads)

    for candidate_file in (
        tmp_path / "state.db",
        tmp_path / "state.db-wal",
        tmp_path / "state.db-journal",
        tmp_path / "state.db.lock",
    ):
        ok = candidate_file.exists()
        if ok:
            raw = candidate_file.read_bytes()
            assert SEED_TOKEN.encode() not in raw
            assert SEED_AWS_KEY.encode() not in raw
