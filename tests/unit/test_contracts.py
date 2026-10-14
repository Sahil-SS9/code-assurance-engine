"""Unit tests for hermes_code_assurance.contracts — CheckContract v1.

Witnessed RED: written before the module existed.
"""

from __future__ import annotations

import dataclasses

import pytest

from hermes_code_assurance import contracts, jsonio, validators


def minimal_contract() -> dict:
    return {
        "schema": "check-contract-v1",
        "goal": "regression suite for parser module",
        "assessed_areas": ["parsers/junit.py"],
        "required_checks": [
            {
                "check_id": "unit-junit",
                "label": "junit parser unit suite",
                "kind": "test-run",
                "argv": ["python", "-m", "pytest", "tests/unit/test_junit.py"],
                "cwd": ".",
                "parser_id": "pytest-terminal",
            }
        ],
        "optional_checks": [],
        "negative_checks": [],
        "env_allowlist": ["PATH"],
        "network_enabled": False,
        "model_enabled": False,
        "supported_platforms": ["linux"],
    }


def test_roundtrip_and_stable_id():
    c1 = contracts.CheckContract.from_dict(minimal_contract())
    again = contracts.CheckContract.from_dict(minimal_contract())
    c2 = contracts.CheckContract.from_dict(c1.to_dict())
    assert c1.contract_id == c2.contract_id == again.contract_id
    assert len(c1.contract_id) == 64


def test_unknown_top_field_refused():
    bad = minimal_contract()
    bad["surprise"] = 1
    with pytest.raises(contracts.ContractError):
        contracts.CheckContract.from_dict(bad)


def test_missing_goal_refused():
    bad = minimal_contract()
    del bad["goal"]
    with pytest.raises(contracts.ContractError):
        contracts.CheckContract.from_dict(bad)


def test_bad_check_id_refused():
    bad = minimal_contract()
    bad["required_checks"][0]["check_id"] = "Bad_ID!"
    with pytest.raises(contracts.ContractError):
        contracts.CheckContract.from_dict(bad)


def test_empty_argv_refused_and_newline_refused():
    base = minimal_contract()
    empty = contracts.CheckContract.from_dict(base)
    assert empty

    nos = minimal_contract()
    nos["required_checks"][0]["argv"] = []
    with pytest.raises(contracts.ContractError):
        contracts.CheckContract.from_dict(nos)

    inject = minimal_contract()
    inject["required_checks"][0]["argv"][3] = "tests/x\n--forge-key 1"
    with pytest.raises(contracts.ContractError):
        contracts.CheckContract.from_dict(inject)


def test_duplicate_check_id_refused():
    bad = minimal_contract()
    bad["optional_checks"] = [dict(bad["required_checks"][0])]
    with pytest.raises(contracts.ContractError):
        contracts.CheckContract.from_dict(bad)


def test_contract_frozen():
    c = contracts.CheckContract.from_dict(minimal_contract())
    with pytest.raises(dataclasses.FrozenInstanceError):
        c.goal = "mutated"


def test_to_dict_is_a_deep_copy():
    c = contracts.CheckContract.from_dict(minimal_contract())
    exported = c.to_dict()
    exported["required_checks"][0]["check_id"] = "corrupt"
    assert c.to_dict()["required_checks"][0]["check_id"] == "unit-junit"


def test_schema_file_exists_and_validates_example():
    with open("schemas/check-contract-v1.json", "rb") as fh:
        schema = jsonio.load_json_bytes(fh.read())
    validators.validate(schema, c := contracts.CheckContract.from_dict(minimal_contract()).to_dict())
    assert c
