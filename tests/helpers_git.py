"""Trusted git helper for fixture repos (test-own scaffolding, not the engine-under-test)."""

from __future__ import annotations

import subprocess
from pathlib import Path


def _git(repo, *args):
    import os

    env = dict(os.environ)
    env["GIT_CONFIG_GLOBAL"] = os.devnull
    env["GIT_CONFIG_SYSTEM"] = os.devnull
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    return subprocess.run(
        ["git", *args], cwd=repo, capture_output=True, text=True, check=True, env=env
    )


def committed_project(tmp_path) -> Path:
    """Minimal committed python project: base commit, then one commit editing calc.py."""
    repo = tmp_path / "project"
    repo.mkdir()
    _git(repo, "init", "-q")
    (repo / "srcroot").mkdir()
    (repo / "srcroot" / "calc.py").write_text("def add(a, b):\n    return a + b\n")
    (repo / "tests").mkdir()
    (repo / "tests" / "test_calc.py").write_text(
        "from srcroot.calc import add\n\n\ndef test_add():\n    assert add(1, 2) == 3\n"
    )
    _git(repo, "add", "-A")
    _git(repo, "-c", "user.email=t@example.test", "-c", "user.name=t", "commit", "-qm", "base")
    (repo / "srcroot" / "calc.py").write_text(
        "def add(a, b):\n    return a + b\n\n\ndef sub(a, b):\n    return a - b\n"
    )
    _git(repo, "add", "-A")
    _git(repo, "-c", "user.email=t@example.test", "-c", "user.name=t", "commit", "-qm", "add sub")
    return repo
