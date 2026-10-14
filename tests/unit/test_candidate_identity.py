"""Candidate identity tests on disposable git fixture repos (CT01-lite).

Identity is sha256 over sorted (path, kind, bytes) records produced by the trusted reader —
never the git HEAD alone. Dirty tracked + relevant untracked inputs must flip it; ignored inputs
are recorded but excluded; symlink policy is an explicit record.
"""

from __future__ import annotations

import hashlib
import json
import os

from hermes_code_assurance import candidate


def _hex() -> str:
    """64-char lowercase hex pattern checker."""
    import re

    return re.compile(r"^[0-9a-f]{64}$").pattern


def test_empty_repo_inventory_complete(tmp_path):
    inv = candidate.GitCandidateReader().read(tmp_path, base=None, head=None)
    assert inv.inventory_state == "complete"
    assert len(inv.snapshot_digest) == 64


def test_content_change_flips_identity(tmp_path):
    reader = candidate.GitCandidateReader()
    (tmp_path / "file.txt").write_text("one\n")
    d1 = reader.read(tmp_path, base=None, head=None).snapshot_digest
    (tmp_path / "file.txt").write_text("two\n")
    d2 = reader.read(tmp_path, base=None, head=None).snapshot_digest
    assert d1 != d2


def test_relevant_untracked_flips_identity_and_is_listed(tmp_path):
    reader = candidate.GitCandidateReader()
    (tmp_path / "file.txt").write_text("x\n")
    d1 = reader.read(tmp_path, base=None, head=None).snapshot_digest
    (tmp_path / "new_next.py").write_text("import os\n")
    inv = reader.read(tmp_path, base=None, head=None)
    assert inv.snapshot_digest != d1
    assert "new_next.py" in inv.untracked
    assert inv.inventory_state == "complete"


def test_ignored_inputs_recorded_but_not_part_of_identity(tmp_path):
    from tests.helpers_git import _git as tgit

    tgit(tmp_path, "init", "-q")
    reader = candidate.GitCandidateReader()
    (tmp_path / ".gitignore").write_text("logs/\n")
    logs = tmp_path / "logs"
    logs.mkdir()
    (logs / "app.log").write_text("build-tool noise\n")
    inv = reader.read(tmp_path, base=None, head=None)
    d1 = inv.snapshot_digest
    (logs / "app.log").write_text("more noise\n")
    assert reader.read(tmp_path, base=None, head=None).snapshot_digest == d1
    assert "logs/app.log" in reader.read(tmp_path, base=None, head=None).ignored


def test_symlink_policy_is_explicit(tmp_path):
    (tmp_path / "real.txt").write_text("x=y\n")
    os.symlink("real.txt", tmp_path / "link.txt")
    inv = candidate.GitCandidateReader().read(tmp_path, base=None, head=None)
    entry = next(e for e in inv.entries if e["path"] == "link.txt")
    assert entry["kind"] == "symlink"
    assert entry["sha256"] is None
    assert "symlink" in inv.policy_notes


def test_identity_cross_check_independent_digest(tmp_path):
    reader = candidate.GitCandidateReader()
    (tmp_path / "file.txt").write_text("x\n")
    (tmp_path / "b.bin").write_bytes(b"\x00\x01")
    inv = reader.read(tmp_path, base=None, head=None)
    blob = json.dumps(
        sorted(
            (e["path"], e["kind"], e["sha256"]) for e in inv.entries if e["sha256"] is not None
        ),
        sort_keys=True,
        separators=(",", ":"),
    )
    recomputed = hashlib.sha256(blob.encode()).hexdigest()
    assert recomputed == inv.snapshot_digest


def test_partial_inventory_when_capped(tmp_path):
    for i in range(7):
        (tmp_path / f"f{i}.txt").write_text("x\n")
    inv = candidate.GitCandidateReader(max_files=5).read(tmp_path, base=None, head=None)
    assert inv.inventory_state == "partial"
    assert inv.limits["max_files"] == 5


def test_toolchain_reports_observed_git_and_unknown_env(tmp_path):
    inv = candidate.GitCandidateReader().read(tmp_path, base=None, head=None)
    assert inv.toolchain["git"].startswith("git ")
    assert inv.toolchain["env"] == "unknown"


def test_committed_changes_listed_from_base(tmp_path):
    from tests.helpers_git import committed_project

    repo = committed_project(tmp_path)
    inv = candidate.GitCandidateReader().read(repo, base="HEAD~1", head="HEAD")
    paths = {c["path"] for c in inv.committed_changes}
    assert "srcroot/calc.py" in paths or "tests/test_calc.py" in paths
    assert _hex() and len(inv.snapshot_digest) == 64
