"""Unit tests for hermes_code_assurance.jsonio — bounded, duplicate-resistant JSON IO.

Witnessed RED: these tests were written before the jsonio module existed.
"""

from __future__ import annotations

import json

import pytest

from hermes_code_assurance import jsonio


def test_round_trip_simple():
    data = jsonio.load_json_bytes(b'{"a": 1, "b": ["x"]}')
    assert data == {"a": 1, "b": ["x"]}
    assert jsonio.sha256_hex(b"abc") == (
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )


def test_oversized_input_refused():
    payload = json.dumps({"a": "x" * 30}).encode()
    with pytest.raises(jsonio.TooLarge):
        jsonio.load_json_bytes(payload, max_bytes=10)


def test_too_deep_refused():
    deep = "[" * 40 + "]" * 40
    with pytest.raises(jsonio.TooDeep):
        jsonio.load_json_bytes(deep.encode(), max_depth=32)


def test_duplicate_keys_refused():
    with pytest.raises(jsonio.DuplicateKey):
        jsonio.load_json_bytes(b'{"a": 1, "a": 2}')


def test_nonfinite_numbers_refused():
    with pytest.raises(jsonio.NonFiniteNumber):
        jsonio.load_json_bytes(b'{"x": NaN}')
    with pytest.raises(jsonio.NonFiniteNumber):
        jsonio.load_json_bytes(b'{"x": Infinity}')


def test_syntax_error_refused():
    with pytest.raises(jsonio.JSONSyntaxError):
        jsonio.load_json_bytes(b'{"a": 1')


def test_canonical_json_is_sorted_and_tight():
    out = jsonio.canonical_json({"b": 1, "a": [2, 3]})
    assert out == b'{"a":[2,3],"b":1}'


def test_canonical_json_rejects_nonfinite():
    with pytest.raises(ValueError):
        jsonio.canonical_json({"x": float("nan")})
