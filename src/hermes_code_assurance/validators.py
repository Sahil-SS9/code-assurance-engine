"""In-tree validator for the documented JSON Schema subset used by schemas/*.json.

Design: refuse-by-name. A keyword outside the supported whitelist raises SchemaError rather than
being silently ignored, so a schema typo can never downgrade validation. Error paths are dotted
(instance-relative) in ValidationFailure messages.
"""

from __future__ import annotations

import re
from typing import Any


class SchemaError(ValueError):
    """The schema itself is not a valid member of the supported subset."""


class ValidationFailure(ValueError):
    """The instance does not validate against the schema."""


_SUPPORTED_KEYWORDS = {
    "$schema", "title", "description", "type", "const", "enum", "properties", "required",
    "additionalProperties", "items", "minItems", "maxItems", "minLength", "maxLength",
    "pattern", "minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum", "anyOf", "allOf",
    "format",
}
_SUPPORTED_TYPES = {"object", "array", "string", "integer", "number", "boolean", "null"}
_MAX_SCHEMA_DEPTH = 24


def _check_schema_shape(schema: Any, depth: int = 0) -> None:
    if depth > _MAX_SCHEMA_DEPTH:
        raise SchemaError("schema nesting exceeds the supported depth")
    if not isinstance(schema, dict):
        raise SchemaError("schema must be an object")
    if "type" in schema and (
        isinstance(schema["type"], str) and schema["type"] not in _SUPPORTED_TYPES
    ):
        raise SchemaError(f"unsupported type keyword: {schema['type']!r}")
    unknown = set(schema) - _SUPPORTED_KEYWORDS
    if unknown:
        raise SchemaError(f"unsupported schema keyword(s): {sorted(unknown)}")
    for keyword in ("properties",):
        sub = schema.get(keyword)
        if sub is not None:
            if not isinstance(sub, dict):
                raise SchemaError(f"{keyword} must be an object")
            for child in sub.values():
                _check_schema_shape(child, depth + 1)
    if schema.get("additionalProperties") is not None and isinstance(
        schema["additionalProperties"], dict
    ):
        _check_schema_shape(schema["additionalProperties"], depth + 1)
    if schema.get("items") is not None:
        _check_schema_shape(schema["items"], depth + 1)
    for combinator in ("anyOf", "allOf"):
        sub = schema.get(combinator)
        if sub is not None:
            if not isinstance(sub, list):
                raise SchemaError(f"{combinator} must be an array")
            for child in sub:
                _check_schema_shape(child, depth + 1)


def _type_ok(expected: str, instance: Any) -> bool:
    if expected == "integer":
        return isinstance(instance, int) and not isinstance(instance, bool)
    if expected == "number":
        return isinstance(instance, (int, float)) and not isinstance(instance, bool)
    if expected == "boolean":
        return isinstance(instance, bool)
    if expected == "string":
        return isinstance(instance, str)
    if expected == "array":
        return isinstance(instance, list)
    if expected == "object":
        return isinstance(instance, dict)
    if expected == "null":
        return instance is None
    return False


def _validate(schema: dict, instance: Any, path: str) -> None:
    if "type" in schema:
        expected = schema["type"]
        ok = _type_ok(expected, instance) if isinstance(expected, str) else any(
            _type_ok(t, instance) for t in expected
        )
        if not ok:
            raise ValidationFailure(f"{path or '$'}: expected type {expected!r}")

    if "const" in schema and instance != schema["const"]:
        raise ValidationFailure(f"{path or '$'}: const mismatch")

    if "enum" in schema and instance not in schema["enum"]:
        raise ValidationFailure(f"{path or '$'}: value not in enum")

    if isinstance(instance, str):
        if "minLength" in schema and len(instance) < schema["minLength"]:
            raise ValidationFailure(f"{path or '$'}: string shorter than minLength")
        if "maxLength" in schema and len(instance) > schema["maxLength"]:
            raise ValidationFailure(f"{path or '$'}: string longer than maxLength")
        if "pattern" in schema and re.search(schema["pattern"], instance) is None:
            raise ValidationFailure(f"{path or '$'}: pattern mismatch")

    if isinstance(instance, (int, float)) and not isinstance(instance, bool):
        if "minimum" in schema and instance < schema["minimum"]:
            raise ValidationFailure(f"{path or '$'}: below minimum")
        if "maximum" in schema and instance > schema["maximum"]:
            raise ValidationFailure(f"{path or '$'}: above maximum")
        if "exclusiveMinimum" in schema and instance <= schema["exclusiveMinimum"]:
            raise ValidationFailure(f"{path or '$'}: below exclusiveMinimum")
        if "exclusiveMaximum" in schema and instance >= schema["exclusiveMaximum"]:
            raise ValidationFailure(f"{path or '$'}: above exclusiveMaximum")

    if isinstance(instance, list):
        if "minItems" in schema and len(instance) < schema["minItems"]:
            raise ValidationFailure(f"{path or '$'}: fewer than minItems")
        if "maxItems" in schema and len(instance) > schema["maxItems"]:
            raise ValidationFailure(f"{path or '$'}: more than maxItems")
        if "items" in schema:
            for i, item in enumerate(instance):
                _validate(schema["items"], item, f"{path}[{i}]")

    if isinstance(instance, dict):
        props = schema.get("properties") or {}
        required = schema.get("required") or []
        for key in required:
            if key not in instance:
                raise ValidationFailure(f"{path or '$'}: missing required property {key!r}")
        additional = schema.get("additionalProperties", True)
        for key, value in instance.items():
            key_path = f"{path}.{key}" if path else key
            if key in props:
                _validate(props[key], value, key_path)
            elif additional is False:
                raise ValidationFailure(f"{path or '$'}: unexpected property {key!r}")
            elif isinstance(additional, dict):
                _validate(additional, value, key_path)

    if "anyOf" in schema:
        errors = []
        for branch in schema["anyOf"]:
            try:
                _validate(branch, instance, path)
            except ValidationFailure as exc:
                errors.append(str(exc))
        if len(errors) == len(schema["anyOf"]):
            raise ValidationFailure(f"{path or '$'}: failed anyOf ({' | '.join(errors)})")

    if "allOf" in schema:
        for branch in schema["allOf"]:
            _validate(branch, instance, path)

    if schema.get("format") == "sha256-hex" and not (
        isinstance(instance, str) and re.fullmatch(r"[0-9a-f]{64}", instance)
    ):
        raise ValidationFailure(f"{path or '$'}: not a sha256 hex digest")


def validate(schema: Any, instance: Any) -> None:
    """Validate *instance* against the subset schema. Raises SchemaError for out-of-subset
    schemas and ValidationFailure (with a dotted path) for invalid instances."""
    _check_schema_shape(schema)
    _validate(schema, instance, "")
