"""Advisory model (optional, OFF by default): strictly schema-validated proposals only.

An advisory layer can never: mint execution, change the frozen contract, modify the oracle,
suppress a finding, or alter deterministic statuses. Its ONLY output lanes are clearly-labelled
'advisory' records. Validation is local (no jsonschema dependency required).
"""

from __future__ import annotations

from . import validators
from .validators import SchemaError, ValidationFailure

_ADVISORY_SCHEMA = {
    "type": "object",
    "properties": {
        "summary": {"type": "string", "minLength": 1, "maxLength": 4000},
        "confidence_note": {"type": "string", "maxLength": 2000},
    },
    "required": ["summary"],
    "additionalProperties": True,
}


class AdvisoryRefusal(ValueError):
    """Model output failed local schema validation: refused, never passed through."""


class AdvisoryModel:
    def __init__(self, complete_structured):
        """complete_structured: callable compatible with the Hermes plugin LLM facade shape."""
        self._complete_structured = complete_structured

    def propose(self, context: dict) -> dict:
        """Returns a labelled, locally-validated advisory proposal. Raises AdvisoryRefusal on
        schema failure. No retry loop (a flaky model is not evidence, and retries cost budget)."""
        try:
            raw = self._complete_structured(
                "You are an advisory reviewer. Propose observations ONLY.",
                input=context,
                json_schema=_ADVISORY_SCHEMA,
            )
        except (SchemaError, ValidationFailure):
            raise AdvisoryRefusal("model output failed local schema validation")
        if not isinstance(raw, dict):
            raise AdvisoryRefusal("model returned no structured output")
        try:
            validators.validate(_ADVISORY_SCHEMA, raw)
        except ValidationFailure as exc:
            raise AdvisoryRefusal(f"model output failed local schema validation: {exc}")
        return {"provenance": "advisory", **raw}


def render_advisory_if_any(model, context: dict) -> dict:
    """Advisory unavailability/hard-failure must stay VISIBLE, never silently swallowed."""
    if model is None:
        return {"provenance": "advisory-unavailable",
                "note": "advisory model lane disabled by default; failure stays visible"}
    try:
        return model.propose(context)
    except AdvisoryRefusal as exc:
        return {"provenance": "advisory-unavailable",
                "note": f"advisory lane unavailable: model output refused ({exc})"}
