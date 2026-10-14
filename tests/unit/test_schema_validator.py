"""Unit tests for the in-tree JSON-schema subset validator.

The schemas under schemas/ only use this subset. Witnessed RED: written before the module existed.
"""

from __future__ import annotations

import pytest

from hermes_code_assurance import validators


def ok(schema, instance):
    validators.validate(schema, instance)  # raises on failure


def bad(schema, instance):
    with pytest.raises(validators.ValidationFailure):
        validators.validate(schema, instance)


def test_object_required_and_type():
    schema = {"type": "object", "properties": {"a": {"type": "string"}}, "required": ["a"]}
    ok(schema, {"a": "x"})
    with pytest.raises(validators.ValidationFailure):
        validators.validate(schema, {"b": "x"})
    with pytest.raises(validators.ValidationFailure):
        validators.validate(schema, {"a": 1})


def test_integer_rejects_bool_and_float():
    schema = {"type": "integer"}
    ok(schema, 5)
    with pytest.raises(validators.ValidationFailure):
        validators.validate(schema, True)
    with pytest.raises(validators.ValidationFailure):
        validators.validate(schema, 5.5)


def test_additional_properties_false():
    schema = {
        "type": "object",
        "properties": {"a": {"type": "integer"}},
        "required": ["a"],
        "additionalProperties": False,
    }
    ok(schema, {"a": 1})
    with pytest.raises(validators.ValidationFailure):
        validators.validate(schema, {"a": 1, "extra": 2})


def test_array_items_minmax():
    schema = {"type": "array", "items": {"type": "integer"}, "minItems": 1, "maxItems": 2}
    ok(schema, [1])
    with pytest.raises(validators.ValidationFailure):
        validators.validate(schema, [])
    with pytest.raises(validators.ValidationFailure):
        validators.validate(schema, [1, 2, 3])
    with pytest.raises(validators.ValidationFailure):
        validators.validate(schema, [1, "x"])


def test_enum_const_pattern():
    ok({"enum": ["a", "b"]}, "a")
    bad({"enum": ["a", "b"]}, "c")
    ok({"const": "fixed"}, "fixed")
    bad({"const": "fixed"}, "other")
    ok({"type": "string", "pattern": "^[a-z]+$"}, "abc")
    bad({"type": "string", "pattern": "^[a-z]+$"}, "abc1")


def test_string_length_and_number_bounds():
    ok({"type": "string", "minLength": 1, "maxLength": 3}, "ab")
    bad({"type": "string", "minLength": 3}, "ab")
    ok({"type": "number", "minimum": 1, "maximum": 2}, 1.5)
    bad({"type": "number", "minimum": 2}, 1.5)
    ok({"type": "integer", "exclusiveMinimum": 1}, 2)
    bad({"type": "integer", "exclusiveMinimum": 1}, 1)


def test_anyof():
    schema = {"anyOf": [{"type": "integer"}, {"type": "string"}]}
    ok(schema, 3)
    ok(schema, "x")
    bad(schema, [])


def test_bad_schema_refused():
    with pytest.raises(validators.SchemaError):
        validators.validate({"type": "nonsense-type"}, 1)
    with pytest.raises(validators.SchemaError):
        validators.validate("not-a-dict", 1)


def test_deep_schema_refused():
    deep = {"type": "object"}
    cur = deep
    for _ in range(50):
        cur = {"type": "object", "properties": {"p": cur}}
    schema = cur
    with pytest.raises(validators.SchemaError):
        validators.validate(schema, {})
