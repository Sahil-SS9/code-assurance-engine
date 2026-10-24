"""C4 regression: per-call data-dir scoping. Trusted override controls every handler; SDK
errors refuse rather than falling back to the bare live home; model-supplied foreign state_dir
values are refused without a write; registration performs no writes.

Witnessed RED: the review reproduced cross-home writes via the bare fallback.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest


class RecordingCtx:
    def __init__(self):
        self.tools = {}

    def register_tool(self, name, toolset, schema, handler, **kwargs):
        self.tools[name] = {"schema": schema, "handler": handler, "toolset": toolset}


@pytest.fixture
def stub_hermes_constants(tmp_path, monkeypatch):
    """Inject the documented public seam (hermes_constants.get_hermes_home → HERMES_HOME)."""
    pkg = tmp_path / "stub_hermes_pkg" / "hermes_constants"
    pkg.mkdir(parents=True)
    (pkg / "__init__.py").write_text(
        "import os\n"
        "from pathlib import Path\n"
        "def get_hermes_home():\n"
        "    return Path(os.environ['HERMES_HOME'])\n",
        encoding="utf-8",
    )

    def install(home: Path):
        monkeypatch.setenv("HERMES_HOME", str(home))
        monkeypatch.syspath_prepend(str(pkg.parent))
        return home

    return install


FORBIDDEN_DEFAULT = Path.home() / ".hermes" / "plugin-data" / "code-assurance-engine"


def test_sdk_error_refuses_instead_of_live_home(tmp_path, monkeypatch):
    """No host SDK seam available in this environment (no hermes modules installed) → refuse.
    The pre-existing reviewed stray directory must stay UNTOUCHED (byte-stat compare)."""

    from hermes_code_assurance.adapters.hermes import register_plugin

    # Only run the bare-fallback proof when the reviewed stray is absent (cleanup is a separate
    # owner-approved action); otherwise verify the refusal leaves its stat unchanged.
    stray_stat = FORBIDDEN_DEFAULT.stat() if FORBIDDEN_DEFAULT.exists() else None

    ctx = RecordingCtx()
    register_plugin(ctx)
    # Surface contract (PR 143753 skeptic round): the TOOL HANDLER surfaces the ladder's
    # refusal as data (never an exception into the host turn); the raise itself is asserted
    # directly on the ladder in test_refusal_raised_by_ladder_directly below.
    out = json.loads(ctx.tools["assure_status"]["handler"]({"assessment_id": "none"}))
    assert out["refused"] is True
    assert out["error"].startswith("StateRootUnavailable")
    if stray_stat is not None:
        assert FORBIDDEN_DEFAULT.stat() == stray_stat, (
            "refusal path must not touch the pre-existing stray directory"
        )
    else:
        assert not FORBIDDEN_DEFAULT.exists()


def test_active_home_resolution_follows_profile_per_call(tmp_path, stub_hermes_constants):
    from hermes_code_assurance.adapters.hermes import register_plugin

    home_a = stub_hermes_constants(tmp_path / "homeA")
    ctx = RecordingCtx()
    register_plugin(ctx)
    json.loads(ctx.tools["assure_status"]["handler"]({"assessment_id": "x1"}))
    assert (home_a / "plugin-data" / "code-assurance-engine" / "assessments.db").exists()

    home_b = stub_hermes_constants(tmp_path / "homeB")
    json.loads(ctx.tools["assure_status"]["handler"]({"assessment_id": "x2"}))
    assert (home_b / "plugin-data" / "code-assurance-engine" / "assessments.db").exists()
    assert not (home_a / "plugin-data" / "code-assurance-engine" / "state2-X").exists()


def test_foreign_state_dir_from_tool_args_refused_without_write(tmp_path):
    from hermes_code_assurance.adapters.hermes import register_plugin

    ctx = RecordingCtx()
    override = tmp_path / "trusted_root"
    register_plugin(ctx, state_dir=override)
    out = json.loads(ctx.tools["assure_status"]["handler"](
        {"assessment_id": "x", "state_dir": "/tmp/attacker-chosen"}))
    assert out["refused"] is True
    assert out["error"].startswith("SecurityRefusal")
    assert not Path("/tmp/attacker-chosen/assessments.db").exists()


def test_refusal_raised_by_ladder_directly(tmp_path):
    """The LADDER still raises (C4 reviewed contract); only the tool surface converts the
    refusal to data."""
    from hermes_code_assurance.adapters.hermes import _resolve_state_dir
    from hermes_code_assurance.adapters_scope import SecurityRefusal

    with pytest.raises(SecurityRefusal):
        _resolve_state_dir("/tmp/attacker-chosen")


def test_explicit_override_controls_every_handler_with_no_registration_writes(tmp_path):
    from hermes_code_assurance.adapters.hermes import register_plugin

    override = tmp_path / "state_override"
    ctx = RecordingCtx()
    report = register_plugin(ctx, state_dir=override)
    assert not override.exists(), "registration must not write"
    json.loads(ctx.tools["assure_status"]["handler"]({"assessment_id": "none"}))
    assert override.exists()
    assert report["commands"] or report["registered_tools"]
