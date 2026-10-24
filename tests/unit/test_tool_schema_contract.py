"""Schema contract: tools reach the model as complete function definitions (PR 143753 review).

Witnessed RED at effffefd: adapters passed a bare parameters-only schema; the host registry
wrapped it and the model received six argument-free tools.
"""

from __future__ import annotations

from hermes_code_assurance.adapters.hermes import register_plugin
from tests.unit.test_adapters import FakeCtx


def test_every_tool_schema_is_complete_function_schema():
    ctx = FakeCtx()
    register_plugin(ctx)
    for name, tool in ctx.tools.items():
        schema = tool["schema"]
        assert schema.get("name") == name, f"{name}: schema must carry the tool name"
        assert isinstance(schema.get("description"), str) and schema["description"], (
            f"{name}: schema must carry a description"
        )
        params = schema.get("parameters")
        assert isinstance(params, dict) and params.get("type") == "object", (
            f"{name}: schema must wrap arguments in a JSON-schema parameters object"
        )
        assert "properties" in params, f"{name}: tool must expose its arguments"