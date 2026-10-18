"""Freeze: private read-only copies of every run input, with a content identity.

The frozen tree is what the sandbox mounts; its digest is what the owner signs. Symlinks and
special files are refused (never dereferenced), drift between inspection and freezing is refused,
and modes/mtimes are deliberately NOT part of identity (copies are normalised to 0644/0755).
"""

from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

import pytest

from hermes_code_assurance import freeze
from hermes_code_assurance.candidate import GitCandidateReader
from hermes_code_assurance.jsonio import canonical_json, sha256_hex
from tests.conftest import git

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "first_check"


def _tree(root: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return root


# ------------------------------------------------------------------------ tree identity


def test_tree_digest_binds_content_name_and_structure(tmp_path):
    base = _tree(tmp_path / "a", {"x/one.py": "1", "two.py": "2"})
    digest = freeze.tree_digest(base)
    assert digest == freeze.tree_digest(base), "deterministic"
    (base / "two.py").write_text("3")
    assert freeze.tree_digest(base) != digest, "content change"
    (base / "two.py").write_text("2")
    assert freeze.tree_digest(base) == digest
    (base / "two.py").rename(base / "three.py")
    assert freeze.tree_digest(base) != digest, "rename"
    (base / "three.py").rename(base / "two.py")
    (base / "empty").mkdir()
    assert freeze.tree_digest(base) != digest, "an empty directory is part of the structure"


def test_tree_digest_ignores_bytecode_modes_and_mtime(tmp_path):
    base = _tree(tmp_path / "a", {"m.py": "1"})
    digest = freeze.tree_digest(base)
    (base / "__pycache__").mkdir()
    (base / "__pycache__" / "m.cpython-314.pyc").write_bytes(b"\x00junk")
    (base / "stray.pyc").write_bytes(b"\x00junk")
    os.chmod(base / "m.py", 0o755)
    os.utime(base / "m.py", (1, 1))
    assert freeze.tree_digest(base) == digest


def test_tree_digest_names_selects_top_level_entries(tmp_path):
    base = _tree(tmp_path / "sp", {"pkg_a/a.py": "a", "pkg_b/b.py": "b", "other/o.py": "o"})
    only_a = freeze.tree_digest(base, names=["pkg_a"])
    assert only_a != freeze.tree_digest(base, names=["pkg_b"])
    (base / "other" / "o.py").write_text("changed")
    assert freeze.tree_digest(base, names=["pkg_a"]) == only_a, "unselected entries are not identity"
    (base / "pkg_a" / "a.py").write_text("changed")
    assert freeze.tree_digest(base, names=["pkg_a"]) != only_a
    with pytest.raises(freeze.FreezeRefused):
        freeze.tree_digest(base, names=["missing"])


def test_tree_refuses_symlinks_and_special_files(tmp_path):
    base = _tree(tmp_path / "a", {"m.py": "1"})
    (base / "link").symlink_to(base / "m.py")
    with pytest.raises(freeze.FreezeRefused) as caught:
        freeze.tree_digest(base)
    assert "symlink" in str(caught.value)
    (base / "link").unlink()
    os.mkfifo(base / "pipe")
    with pytest.raises(freeze.FreezeRefused) as caught:
        freeze.tree_digest(base)
    assert "special" in str(caught.value)


def test_names_cannot_escape_the_root(tmp_path):
    base = _tree(tmp_path / "sp", {"pkg/a.py": "a"})
    for bad in ("../x", "/etc", "a/b", ".."):
        with pytest.raises(freeze.FreezeRefused):
            freeze.tree_digest(base, names=[bad])


# ------------------------------------------------------------------------ freezing copies


def test_freeze_directory_copies_verifies_and_normalises_modes(tmp_path):
    src = _tree(tmp_path / "src", {"d/x.py": "print(1)\n", "y.py": "2"})
    os.chmod(src / "y.py", 0o600)
    frozen = freeze.freeze_directory(src, tmp_path / "frozen")
    assert frozen.digest == freeze.tree_digest(src) == freeze.tree_digest(frozen.path)
    assert frozen.file_count == 2 and frozen.total_bytes == len("print(1)\n") + 1
    assert stat.S_IMODE((frozen.path / "y.py").stat().st_mode) == 0o644
    assert stat.S_IMODE((frozen.path / "d").stat().st_mode) == 0o755
    assert (frozen.path / "d" / "x.py").read_text() == "print(1)\n"


def test_freeze_directory_with_names_copies_only_those(tmp_path):
    src = _tree(tmp_path / "sp", {"pkg_a/a.py": "a", "pkg_b/b.py": "b", "pkg_a/__pycache__/z.pyc": "z"})
    frozen = freeze.freeze_directory(src, tmp_path / "frozen", names=["pkg_a"])
    assert sorted(p.name for p in frozen.path.iterdir()) == ["pkg_a"]
    assert not (frozen.path / "pkg_a" / "__pycache__").exists()
    assert frozen.digest == freeze.tree_digest(src, names=["pkg_a"])


def test_freeze_directory_refuses_to_overwrite_an_existing_destination(tmp_path):
    src = _tree(tmp_path / "src", {"x.py": "1"})
    (tmp_path / "frozen").mkdir()
    with pytest.raises(freeze.FreezeRefused):
        freeze.freeze_directory(src, tmp_path / "frozen")


def test_freeze_directory_refuses_oversized_trees(tmp_path, monkeypatch):
    src = _tree(tmp_path / "src", {"x.py": "1"})
    monkeypatch.setattr(freeze, "MAX_TOTAL_BYTES", 0)
    with pytest.raises(freeze.FreezeRefused) as caught:
        freeze.freeze_directory(src, tmp_path / "frozen")
    assert "size" in str(caught.value)


# ------------------------------------------------------------------------ the candidate


def _repo(tmp_path, source: Path = FIXTURES / "candidate_pass") -> Path:
    repo = tmp_path / "repo"
    repo.mkdir(parents=True)
    git(repo, "init", "-q")
    for path in sorted(source.rglob("*")):
        if path.is_file():
            target = repo / path.relative_to(source)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(path.read_bytes())
    git(repo, "add", "-A")
    git(repo, "-c", "user.email=t@example.test", "-c", "user.name=t", "commit", "-qm", "fixture")
    return repo


def test_freeze_candidate_reproduces_the_inspected_snapshot_exactly(tmp_path):
    repo = _repo(tmp_path)
    inventory = GitCandidateReader().read(repo, base=None, head=None).as_dict()
    frozen = freeze.freeze_candidate(inventory, repo, tmp_path / "candidate")
    assert frozen.digest == inventory["snapshot_digest"]
    assert (frozen.path / "calc" / "ops.py").read_bytes() == (repo / "calc" / "ops.py").read_bytes()
    assert not (frozen.path / ".git").exists(), "repository metadata never enters the sandbox"
    expected = sha256_hex(canonical_json(sorted(
        (e["path"], e["kind"], e["sha256"]) for e in inventory["entries"] if e["sha256"] is not None
    )))
    assert frozen.digest == expected, "same identity formula as the candidate reader"


def test_freeze_candidate_refuses_when_a_file_changed_after_inspection(tmp_path):
    repo = _repo(tmp_path)
    inventory = GitCandidateReader().read(repo, base=None, head=None).as_dict()
    (repo / "calc" / "ops.py").write_text("def add(a, b):\n    return 0\n")
    with pytest.raises(freeze.FreezeRefused) as caught:
        freeze.freeze_candidate(inventory, repo, tmp_path / "candidate")
    assert "changed since inspection" in str(caught.value)
    assert not (tmp_path / "candidate").exists(), "no half-frozen tree is left behind"


def test_freeze_candidate_refuses_a_file_added_after_inspection(tmp_path):
    repo = _repo(tmp_path)
    inventory = GitCandidateReader().read(repo, base=None, head=None).as_dict()
    (repo / "calc" / "extra.py").write_text("x = 1\n")
    inventory_after = GitCandidateReader().read(repo, base=None, head=None).as_dict()
    assert inventory_after["snapshot_digest"] != inventory["snapshot_digest"]
    # The stale inventory is still faithfully frozen from ITS entries: the extra file is simply
    # not part of the identity the owner approved, so it is never copied.
    frozen = freeze.freeze_candidate(inventory, repo, tmp_path / "candidate")
    assert not (frozen.path / "calc" / "extra.py").exists()


def test_freeze_candidate_refuses_symlinks_oversized_and_partial_inventories(tmp_path):
    repo = _repo(tmp_path)
    (repo / "calc" / "alias.py").symlink_to(repo / "calc" / "ops.py")
    inventory = GitCandidateReader().read(repo, base=None, head=None).as_dict()
    with pytest.raises(freeze.FreezeRefused) as caught:
        freeze.freeze_candidate(inventory, repo, tmp_path / "c1")
    assert "symlink" in str(caught.value)

    repo2 = _repo(tmp_path / "second")
    big = GitCandidateReader(max_file_bytes=10).read(repo2, base=None, head=None).as_dict()
    with pytest.raises(freeze.FreezeRefused) as caught:
        freeze.freeze_candidate(big, repo2, tmp_path / "c2")
    assert "partial" in str(caught.value) or "not read" in str(caught.value)


def test_freeze_candidate_refuses_unsafe_entry_paths(tmp_path):
    repo = _repo(tmp_path)
    inventory = GitCandidateReader().read(repo, base=None, head=None).as_dict()
    inventory["entries"].append({"path": "../escape.py", "kind": "file", "mode": None, "size": 1,
                                 "sha256": sha256_hex(b"x"), "note": ""})
    with pytest.raises(freeze.FreezeRefused):
        freeze.freeze_candidate(inventory, repo, tmp_path / "candidate")


# ------------------------------------------------------------------------ the entry bundle


def test_entry_bundle_digest_matches_what_is_frozen(tmp_path):
    frozen = freeze.freeze_entry(tmp_path / "entry")
    assert sorted(p.name for p in frozen.path.iterdir()) == ["collect.py", "probe.py"]
    assert frozen.digest == freeze.entry_digest()
    shipped = Path(freeze.__file__).parent / "sandbox_assets"
    assert (frozen.path / "collect.py").read_bytes() == (shipped / "collect.py").read_bytes()
    compiled = subprocess.run(
        ["/usr/bin/env", "python3", "-c",
         "import sys; [compile(open(p).read(), p, 'exec') for p in sys.argv[1:]]",
         str(frozen.path / "collect.py"), str(frozen.path / "probe.py")],
        capture_output=True, check=False,
    )
    assert compiled.returncode == 0, compiled.stderr
