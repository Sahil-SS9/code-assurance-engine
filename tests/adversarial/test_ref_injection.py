"""Adversarial: model-supplied git refs never reach git as options (PR 143753 review, blocking).

Witnessed RED at effffefd: a dash-leading ref was passed to `git diff` as an OPTION and git's
diff output could be redirected to an attacker-chosen output path.
"""

from __future__ import annotations

import json

import pytest

from hermes_code_assurance.adapters.hermes import register_plugin
from tests.unit.test_adapters import FakeCtx


@pytest.fixture
def registered_ctx(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    from tests.conftest import git

    git(repo, "init", "-q")
    (repo / "calc.py").write_text("x = 1\n")
    git(repo, "add", "-A")
    git(repo, "-c", "user.email=t@example.test", "-c", "user.name=t", "commit", "-qm", "c1")
    ctx = FakeCtx()
    register_plugin(ctx, state_dir=tmp_path)
    return ctx


def test_inspect_refuses_dash_leading_base_without_write(registered_ctx, tmp_path):
    out_path = tmp_path / "exfil.diff"
    with pytest.raises(ValueError, match="must not start with '-'"):
        json.loads(registered_ctx.tools["assure_inspect"]["handler"]({
            "repo": str(tmp_path / "repo"), "base": "-o", "head": str(out_path),
        }))
    assert not out_path.exists(), "git output must never be redirected to an attacker path"


def test_inspect_refuses_dash_leading_head(registered_ctx, tmp_path):
    with pytest.raises(ValueError, match="must not start with '-'"):
        json.loads(registered_ctx.tools["assure_inspect"]["handler"]({
            "repo": str(tmp_path / "repo"), "head": "HEAD", "base": "-c",
        }))


def test_service_ref_resolves_before_plumbing(tmp_path):
    """Service layer defence: a REAL git repo must first resolve the ref to a SHA, and a
    dash-leading value must be refused there too (not just at the argv layer)."""
    import subprocess

    from hermes_code_assurance import service
    from hermes_code_assurance.candidate import _resolve_ref

    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True, capture_output=True)
    (repo / "calc.py").write_text("x = 1\n")
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True, capture_output=True)
    subprocess.run(
        ["git", "-c", "user.email=t@example.test", "-c", "user.name=t", "commit", "-qm", "c1"],
        cwd=repo, check=True, capture_output=True,
    )
    resolved = _resolve_ref(repo, "HEAD")
    assert len(resolved) == 40 and " " not in resolved
    with pytest.raises(ValueError, match="must not start with '-'"):
        service.inspect_candidate(tmp_path / "state", str(repo), base="-o",
                                  head=str(tmp_path / "exfil.diff"))
    assert not (tmp_path / "exfil.diff").exists()