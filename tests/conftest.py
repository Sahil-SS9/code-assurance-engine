"""Shared fixtures: disposable git fixture repos and a git runner used by tests."""

from __future__ import annotations

import os
import subprocess

import pytest


def git(repo_path, *args):
    """Run git plumbing for fixture setup only (trusted, not the engine-under-test)."""
    env = dict(os.environ)
    env["GIT_CONFIG_GLOBAL"] = os.devnull
    env["GIT_CONFIG_SYSTEM"] = os.devnull
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    return subprocess.run(
        ["git", *args], cwd=repo_path, capture_output=True, text=True, check=True, env=env
    )


def make_python_project(repo):
    """Commit a tiny python project with one test."""
    (repo / "srcroot").mkdir()
    (repo / "srcroot" / "calc.py").write_text("def add(a, b):\n    return a + b\n")
    (repo / "tests").mkdir()
    (repo / "tests" / "test_calc.py").write_text(
        "from srcroot.calc import add\n\n\ndef test_add():\n    assert add(1, 2) == 3\n"
    )
    git(repo, "add", "-A")
    git(repo, "-c", "user.email=t@example.test", "-c", "user.name=t", "commit", "-qm", "base")


@pytest.fixture
def repo_factory(tmp_path):
    """Returns fn() -> (repo: Path, base: str, dirty_modification_applied: None)."""

    def _make(project=False):
        repo = tmp_path / f"repo{len(list(tmp_path.iterdir()))}"
        repo.mkdir()
        git(repo, "init", "-q")
        if project:
            make_python_project(repo)
        return repo

    return _make
