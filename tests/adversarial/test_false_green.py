"""False-green attacks (CT05-lite): forged producer output, tampered receipts, cross-candidate
recycling and prose canaries must never authenticate proof.

Witnessed RED: evidence/verify modules do not exist yet.
"""

from __future__ import annotations

import pytest

from hermes_code_assurance import evidence
from hermes_code_assurance.verify import reverify
from tests.green_helpers import build_clean_receipt, build_contract  # same-dir helper

FORGED_JUNIT = (  # producer LIES via attributes; counted children tell the truth
    '<?xml version="1.0"?>\n<testsuite name="s" tests="2" failures="0" errors="0" skipped="0">'
    '<testcase name="t1"><failure message="boom"/></testcase>'
    '<testcase name="t2"/></testsuite>'
)


def _artifact(bits=b"junit-output-bytes", stamp="box-1"):
    return evidence.aspect_of_output(bits, box=stamp)


def test_exit0_with_forged_xml_is_not_assurance():
    receipt = build_clean_receipt(parser=evidence.parser_of(FORGED_JUNIT, "junit-xml"), exit_code=0)
    verified = reverify(receipt, contract=build_contract(), candidate_digest="a" * 64,
                        caller="cli:root", trusted_collector_id=evidence.TRUSTED_ID)
    assert verified.status in ("UNKNOWN", "INVALID_EVIDENCE")
    assert any("discrepanc" in d for d in verified.notes), \
        "a lying producer totals-attr cannot manufacture a pass"


def test_receipt_digest_tampering_detected():
    receipt = build_clean_receipt(parser=evidence.parser_of(
        '<?xml version="1.0"?><testsuite tests="1"><testcase name="t"/></testsuite>', "junit-xml"))
    receipt["receipt_id"] = evidence.receipt_id(receipt)
    receipt["counts"]["collected"] = 99  # tamper after id stamping
    with pytest.raises(evidence.EvidenceTampered):
        evidence.assert_receipt_integrity(receipt)


def test_cross_candidate_recycled_receipt_rejected():
    receipt = build_clean_receipt(parser=evidence.parser_of(
        '<?xml version="1.0"?><testsuite tests="1"><testcase name="t"/></testsuite>', "junit-xml"))
    receipt["candidate_digest"] = "b" * 64
    verified = reverify(receipt, contract=build_contract(), candidate_digest="a" * 64,
                        caller="cli:root", trusted_collector_id=evidence.TRUSTED_ID)
    assert verified.status == "INVALID_EVIDENCE"
    assert any("candidate" in n.lower() for n in verified.notes)


def test_cross_attempt_rejected():
    receipt = build_clean_receipt(parser=evidence.parser_of(
        '<?xml version="1.0"?><testsuite tests="1"><testcase name="t"/></testsuite>', "junit-xml"))
    receipt["attempt"] = 77
    verified = reverify(receipt, contract=build_contract(), candidate_digest="a" * 64,
                        caller="cli:root", trusted_collector_id=evidence.TRUSTED_ID,
                        expected_attempt=1)
    assert verified.status == "INVALID_EVIDENCE"


def test_caller_mismatch_rejected():
    receipt = build_clean_receipt(parser=evidence.parser_of(
        '<?xml version="1.0"?><testsuite tests="1"><testcase name="t"/></testsuite>', "junit-xml"))
    verified = reverify(receipt, contract=build_contract(), candidate_digest="a" * 64,
                        caller="gateway:bot", trusted_collector_id=evidence.TRUSTED_ID)
    assert verified.status == "INVALID_EVIDENCE"


def test_prose_canary_nowhere_in_machine_proof():
    """'canary ok' strings are not evidence; verify has no slot accepting prose success text."""
    receipt = build_clean_receipt(parser=evidence.parser_of(
        '<?xml version="1.0"?><testsuite tests="1"><testcase name="t"/></testsuite>', "junit-xml"))
    verified = reverify(receipt, contract=build_contract(), candidate_digest="a" * 64,
                        caller="cli:root", trusted_collector_id=evidence.TRUSTED_ID)
    assert not any(k.lower().find("canary") >= 0 for k in verified.to_dict())
    assert verified.status in ("PASSED", "ASSESSED", "UNKNOWN", "INVALID_EVIDENCE")


def test_unparseable_producer_output_is_unknown():
    out = evidence.parser_of("garbage-not-xml", "junit-xml")
    assert out.status_hint == "unknown"
