"""Adapter registration tests with a fake host ctx: surface parity, no host coupling at import,
fail-closed craft (missing host surfaces are skipped, never crash), tool schemas present.

Witnessed RED: adapters/cli/service modules do not exist yet.
"""

from __future__ import annotations

import json

from hermes_code_assurance.adapters.hermes import register_plugin


class FakeCtx:
    def __init__(self):
        self.tools = {}
        self.commands = {}
        self.cli_commands = {}
        self.skills = []

    def register_tool(self, name, toolset, schema, handler, **kwargs):
        self.tools[name] = {"schema": schema, "handler": handler, "toolset": toolset}

    def register_command(self, name, handler, **kwargs):
        self.commands[name] = {"handler": handler, **kwargs}

    def register_cli_command(self, name, **kwargs):
        self.cli_commands[name] = kwargs

    def register_skill(self, name, path, **kwargs):
        self.skills.append((name, str(path)))


def test_tool_names_and_schemas_registered():
    ctx = FakeCtx()
    report = register_plugin(ctx)
    expected = {"assure_inspect", "assure_plan_checks", "assure_status", "assure_verify",
                "assure_report", "assure_run"}
    assert expected <= set(ctx.tools)
    for name in expected:
        assert "type" in ctx.tools[name]["schema"]
        assert ctx.tools[name]["toolset"] == "code-assurance"
    assert "assure" in ctx.commands
    assert report["registered_tools"] >= 6


def test_skills_registration_attempted_once():
    ctx = FakeCtx()
    register_plugin(ctx)
    assert ctx.skills and ctx.skills[0][0] == "assure"


def test_host_without_optional_surfaces_still_registers_tools():
    class BareCtx(FakeCtx):
        def register_command(self, *a, **k):
            raise RuntimeError("host does not support slash registration")

        def register_cli_command(self, *a, **k):
            raise RuntimeError("host does not support CLI registration")

        def register_skill(self, *a, **k):
            raise RuntimeError("host does not support skill registration")

    ctx = BareCtx()
    report = register_plugin(ctx)
    assert report["registered_tools"] >= 6
    assert report["skipped_surfaces"], "missing host surfaces are skipped and recorded loudly"


def test_assure_run_tool_is_gated_and_honest(tmp_path):
    import subprocess

    repo = tmp_path / "repoX"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True, capture_output=True)
    (repo / "calc.py").write_text("x = 1\n")
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True, capture_output=True)
    subprocess.run(
        ["git", "-c", "user.email=t@e.test", "-c", "user.name=t", "commit", "-qm", "c1"],
        cwd=repo, check=True, capture_output=True,
    )

    ctx = FakeCtx()
    register_plugin(ctx, state_dir=tmp_path)
    from tests.green_helpers import build_contract

    contract = build_contract()
    inspected = json.loads(ctx.tools["assure_inspect"]["handler"](
        {"repo": str(repo), "state_dir": str(tmp_path)}
    ))
    json.loads(ctx.tools["assure_plan_checks"]["handler"](
        {"contract": contract.to_dict(), "state_dir": str(tmp_path),
         "assessment_id": inspected["assessment_id"]}
    ))
    json.loads(ctx.tools["assure_run"]["handler"](
        {"assessment_id": inspected["assessment_id"], "repo": str(repo), "state_dir": str(tmp_path)}
    ))
    out = json.loads(ctx.tools["assure_run"]["handler"](
        {"assessment_id": inspected["assessment_id"], "repo": str(repo), "state_dir": str(tmp_path)}
    ))
    assert out["status"] == "NOT_APPROVED"
    assert "APPROVED" in out["detail"]
    assert out.get("receipts_unchanged") is True


def test_inspect_tool_flows_end_to_end(tmp_path):
    import subprocess

    repo = tmp_path / "repo0"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True, capture_output=True)
    (repo / "calc.py").write_text("x = 1\n")
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True, capture_output=True)
    subprocess.run(
        ["git", "-c", "user.email=t@e.test", "-c", "user.name=t", "commit", "-qm", "c1"],
        cwd=repo, check=True, capture_output=True,
    )
    (repo / "next.py").write_text("y = 2\n")

    ctx = FakeCtx()
    register_plugin(ctx, state_dir=tmp_path)
    out = json.loads(ctx.tools["assure_inspect"]["handler"]({"repo": str(repo)}))
    assert out["assessment_id"]
    assert out["inventory_state"] == "complete"
    assert "next.py" in out["untracked"]
    assert ctx.commands["assure"]  # slash surface present
