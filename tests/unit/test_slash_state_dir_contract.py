"""Slash-surface state-dir contract (skeptic round, finding 3).

The slash surface receives the OPERATOR's typed text, the same trust class as the CLI: an
explicit --state-dir in /assure text is honoured (documented boundary), while TOOL args keep
the guarded ladder (SecurityRefusal on foreign roots, asserted in test_c4_data_dir). These
tests pin that split so the two classes cannot silently swap.
"""

from __future__ import annotations

import json

from hermes_code_assurance.adapters.hermes import register_plugin
from tests.unit.test_adapters import FakeCtx


def test_tool_args_state_dir_stays_guarded(tmp_path):
    """MODEL-typed tool args keep the strict ladder: a foreign state_dir REFUSES."""
    ctx = FakeCtx()
    register_plugin(ctx, state_dir=tmp_path)
    out = json.loads(ctx.tools["assure_status"]["handler"](
        {"assessment_id": "x", "state_dir": "/tmp/attacker-slash-bypass"}))
    assert out["refused"] is True
    assert out["error"].startswith("SecurityRefusal")


def test_slash_surface_honours_explicit_state_dir(tmp_path):
    """OPERATOR-typed slash text keeps the CLI contract: explicit --state-dir is honoured."""
    ctx = FakeCtx()
    register_plugin(ctx, state_dir=tmp_path / "unused-override")
    handler = ctx.commands["assure"]["handler"]
    out = handler(f"inspect --repo {tmp_path} --state-dir {tmp_path / 'explicit-root'}")
    payload = json.loads(out)
    assert payload["assessment_id"]
    assert (tmp_path / "explicit-root" / "assessments.db").exists()