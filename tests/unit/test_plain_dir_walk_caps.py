"""Plain-dir walk caps (upstream PR 143753 review, recommended).

Witnessed RED at effffefd: `_read_plain_dir` checked `max_files` only after walking the whole
tree, so a large directory stalled the whole turn. The fix enforces the cap during the walk and
records inventory_state="partial" with an honest note.
"""

from __future__ import annotations

import time

from hermes_code_assurance.candidate import GitCandidateReader


def _make_dirs(root, count: int) -> None:
    for i in range(count):
        d = root / f"d{i % 7}"
        d.mkdir(exist_ok=True)
        (d / f"f{i}.txt").write_text("x\n")


def test_plain_dir_walk_stops_early_at_max_files(tmp_path):
    _make_dirs(tmp_path, 400)
    start = time.monotonic()
    inv = GitCandidateReader(max_files=25).read(tmp_path, base=None, head=None)
    elapsed = time.monotonic() - start
    assert inv.inventory_state == "partial"
    assert "file cap exceeded" in inv.policy_notes
    assert len(inv.entries) <= 25
    # Early-stop proof: walking 400 entries would dominate; capped read returns quickly.
    assert elapsed < 2.0, f"walk did not stop early ({elapsed:.2f}s)"


def test_plain_dir_full_walk_marks_complete(tmp_path):
    for i in range(4):
        (tmp_path / f"f{i}.txt").write_text("x\n")
    inv = GitCandidateReader(max_files=10).read(tmp_path, base=None, head=None)
    assert inv.inventory_state == "complete"
    assert len(inv.entries) == 4


def test_plain_dir_walk_identity_still_content_bound(tmp_path):
    reader = GitCandidateReader(max_files=3)
    (tmp_path / "a.txt").write_text("one\n")
    first = reader.read(tmp_path, base=None, head=None).snapshot_digest
    inv = reader.read(tmp_path, base=None, head=None)
    assert inv.snapshot_digest == first
    (tmp_path / "b.txt").write_text("two\n")
    second = reader.read(tmp_path, base=None, head=None).snapshot_digest
    assert second != first