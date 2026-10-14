"""Inspect layer tests: pure classification is inert; the git reader defeats repo-config bombs.

CT03-lite: a bounded source scan must not execute project hooks/external filters/fs monitors, and
injection-flavoured file names must remain inert data.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from hermes_code_assurance import inspect as inspect_mod
from tests.helpers_git import _git  # reuse trusted fixture runner

BOMB = '#!/bin/sh\ntouch "pwned.marker"\nexit 1\n'


def _bombify(repo: Path):
    """Plant repo-local exec traps: diff.external, pager and fsmonitor all point at the bomb."""
    script = repo / "bomb.sh"
    script.write_text(BOMB)
    script.chmod(0o755)
    config = repo / ".git" / "config"
    config.write_text(
        config.read_text()
        + f'\n[diff]\n\texternal = {script}\n[core]\n\tpager = {script}\n\tfsmonitor = {script}\n'
    )


@pytest.fixture
def pure_bombs(monkeypatch):
    """Every execution/promotion surface is a bomb for pure-function tests."""

    def boom(*a, **k):  # pragma: no cover - assertion aid
        raise AssertionError("pure inspect path attempted execution")

    import socket
    import subprocess
    import urllib.request

    monkeypatch.setattr(subprocess, "run", boom)
    monkeypatch.setattr(subprocess, "Popen", boom)
    monkeypatch.setattr(socket, "socket", boom)
    monkeypatch.setattr(urllib.request, "urlopen", boom)
    # (builtins.exec/eval NOT patched: pytest's own import machinery legitimately execs modules;
    #  patching them breaks the runner, not the subject under test.)


def test_inventory_classification_is_inert(pure_bombs, tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "migrations" / "v1.sql").parent.mkdir(exist_ok=True)
    inv = {
        'committed_changes': [{"path": "migrations/v1.sql", "status": "A"}],
        'untracked': ["src/weird; rm -rf$.py"],
        'ignored': [],
        'entries': [{"path": "src/weird; rm -rf$.py", "kind": "file", "sha256": "a" * 64}],
    }
    out = inspect_mod.classify_inventory(inv)
    assert out["languages"]["python"] == 1
    assert "migration-risk" in out["risk_hints"]
    assert not (tmp_path / "pwned.marker").exists()


def test_draft_contract_is_inert_and_honest(pure_bombs):
    inv = {
        "committed_changes": [{"path": "tests/test_x.py", "status": "M"}],
        "untracked": [],
        "ignored": [],
        "entries": [{"path": "tests/test_x.py", "kind": "file", "sha256": "a" * 64}],
    }
    draft = inspect_mod.propose_draft_contract(inv)
    assert draft["required_checks"], "python-only repo must propose at least a pytest check"
    for spec in draft["required_checks"]:
        assert spec["executable"] is False, "proposals start read-only; execution is gated later"
    assert draft["proposed_by"] == "review"


def test_reader_defeats_repo_config_bombs(tmp_path):
    from hermes_code_assurance import candidate

    _git(tmp_path, "init", "-q")
    (tmp_path / "calc.py").write_text("x = 1\n")
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "-c", "user.email=t@example.test", "-c", "user.name=t", "commit", "-qm", "c1")
    _bombify(tmp_path)

    reader = candidate.GitCandidateReader()
    inv = reader.read(tmp_path, base="HEAD~0", head=None)

    assert not (tmp_path / "pwned.marker").exists(), "repo-config bomb executed: fences failed"
    assert inv.inventory_state == "complete"
    assert any(e["path"] == "calc.py" for e in inv.entries)


def test_diff_argv_never_uses_shell(tmp_path):
    """The reader's git invocation uses argv lists (never shell=True) and scrubbed env."""
    from hermes_code_assurance import candidate as cand

    holder = {}

    real_run = cand.subprocess.run

    def spy_run(argv, **kwargs):
        holder["argv"] = argv
        holder["kwargs"] = kwargs
        return type(
            "R", (), {"stdout": b"M\tfoo\n", "stderr": b"", "returncode": 0}
        )()

    cand.subprocess.run = spy_run
    try:
        reader = cand.GitCandidateReader()
        Path("/tmp/does/not/matter").mkdir(parents=True, exist_ok=True)
        reader._git_status_porcelain(Path("."))
    finally:
        cand.subprocess.run = real_run
    assert isinstance(holder["argv"], list)
    assert holder["argv"][0] == "git"
    assert holder["kwargs"].get("shell") in (None, False)
    env = holder["kwargs"].get("env", {})
    assert env.get("GIT_CONFIG_GLOBAL") == "/dev/null"
    assert env.get("GIT_CONFIG_NOSYSTEM") == "1"
