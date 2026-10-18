"""Freeze: private read-only copies of every run input, with a content identity.

The frozen tree is what the sandbox mounts; its digest is what the owner signs. Rules:

- Symlinks and special files are refused, never dereferenced (a link could point at host data).
- Identity is content + relative names + empty directories. Modes, owners and mtimes are
  deliberately NOT identity: copies are normalised to files 0644 / directories 0755.
- Bytecode caches (``__pycache__``, ``*.pyc``) are never identity and never copied.
- The source is read twice (scan, then copy) and the copy is read a third time: any difference
  means the input changed while being frozen and the half-built tree is removed.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import stat
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from .jsonio import canonical_json, sha256_hex

MAX_FILES = 20_000
MAX_TOTAL_BYTES = 256 * 1024 * 1024
MAX_FILE_BYTES = 64 * 1024 * 1024
_EXCLUDED_DIRS = frozenset({"__pycache__"})
_EXCLUDED_SUFFIXES = (".pyc",)
_NAME_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]*$")
_DIGEST_VERSION = 1


class FreezeRefused(RuntimeError):
    """An input cannot be frozen faithfully (symlink, special file, drift, oversize)."""


@dataclass(frozen=True)
class FrozenTree:
    path: Path
    digest: str
    file_count: int
    total_bytes: int


# ------------------------------------------------------------------------ scanning


def _hash_file(path: Path) -> tuple[str, int]:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    except OSError as exc:
        raise FreezeRefused(f"{path} cannot be read safely: {exc.strerror or exc}") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise FreezeRefused(f"{path} is a special file")
        if info.st_size > MAX_FILE_BYTES:
            raise FreezeRefused(f"{path} exceeds the per-file size limit")
        hasher = hashlib.sha256()
        size = 0
        while True:
            block = os.read(fd, 1 << 20)
            if not block:
                break
            size += len(block)
            if size > MAX_FILE_BYTES:
                raise FreezeRefused(f"{path} exceeds the per-file size limit")
            hasher.update(block)
        return hasher.hexdigest(), size
    finally:
        os.close(fd)


def _selected_roots(root: Path, names: Sequence[str] | None) -> list[Path]:
    if names is None:
        return [root]
    selected: list[Path] = []
    for name in names:
        if not _NAME_RE.fullmatch(name) or name in {".", ".."}:
            raise FreezeRefused(f"unsafe entry name {name!r}")
        path = root / name
        if path.is_symlink():
            raise FreezeRefused(f"{path} is a symlink")
        if not path.exists():
            raise FreezeRefused(f"{name!r} does not exist under {root}")
        selected.append(path)
    return selected


def _scan(root: Path, names: Sequence[str] | None):
    """(files, dirs): files = [(relpath, sha256, size)], dirs = [relpath], both sorted."""
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise FreezeRefused(f"{root} is not a plain directory")
    files: list[tuple[str, str, int]] = []
    dirs: list[str] = []
    total = 0
    stack = [(path, path.relative_to(root)) for path in _selected_roots(root, names)]
    while stack:
        path, rel = stack.pop()
        info = os.lstat(path)
        if stat.S_ISLNK(info.st_mode):
            raise FreezeRefused(f"{path} is a symlink; symlinks are never frozen or dereferenced")
        if stat.S_ISDIR(info.st_mode):
            if path.name in _EXCLUDED_DIRS:
                continue
            if str(rel) != ".":
                dirs.append(rel.as_posix())
            for child in os.scandir(path):
                stack.append((Path(child.path), rel / child.name))
        elif stat.S_ISREG(info.st_mode):
            if path.name.endswith(_EXCLUDED_SUFFIXES):
                continue
            digest, size = _hash_file(path)
            total += size
            files.append((rel.as_posix(), digest, size))
            if len(files) > MAX_FILES:
                raise FreezeRefused("too many files to freeze")
            if total > MAX_TOTAL_BYTES:
                raise FreezeRefused("input exceeds the total size limit")
        else:
            raise FreezeRefused(f"{path} is a special file")
    files.sort()
    dirs.sort()
    return files, dirs


def _digest_of(files, dirs) -> str:
    return sha256_hex(
        canonical_json(
            {"v": _DIGEST_VERSION, "files": [[p, h] for p, h, _ in files], "dirs": list(dirs)}
        )
    )


def tree_digest(root: Path, *, names: Sequence[str] | None = None) -> str:
    """Content identity of a directory (or of named top-level entries inside it)."""
    files, dirs = _scan(Path(root), names)
    return _digest_of(files, dirs)


# ------------------------------------------------------------------------ copying


def _write_new(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o644)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(path, 0o644)


def _read_source(path: Path) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise FreezeRefused(f"{path} is a special file")
        if info.st_size > MAX_FILE_BYTES:
            raise FreezeRefused(f"{path} exceeds the per-file size limit")
        chunks = []
        while True:
            block = os.read(fd, 1 << 20)
            if not block:
                break
            chunks.append(block)
        return b"".join(chunks)
    finally:
        os.close(fd)


def _begin(dst: Path) -> None:
    dst = Path(dst)
    if os.path.lexists(dst):
        raise FreezeRefused(f"{dst} already exists; refusing to overwrite a frozen tree")
    if not dst.parent.is_dir():
        raise FreezeRefused(f"{dst.parent} does not exist")
    dst.mkdir(mode=0o755)
    os.chmod(dst, 0o755)


def _abandon(dst: Path) -> None:
    shutil.rmtree(dst, ignore_errors=True)


def freeze_directory(src: Path, dst: Path, *, names: Sequence[str] | None = None) -> FrozenTree:
    """Copy ``src`` (or named top-level entries of it) to a new private tree, verifying identity."""
    src, dst = Path(src), Path(dst)
    files, dirs = _scan(src, names)
    expected = _digest_of(files, dirs)
    _begin(dst)
    try:
        for rel in dirs:
            target = dst / rel
            target.mkdir(parents=True, exist_ok=True, mode=0o755)
            os.chmod(target, 0o755)
        total = 0
        for rel, digest, size in files:
            data = _read_source(src / rel)
            if sha256_hex(data) != digest or len(data) != size:
                raise FreezeRefused(f"{rel} changed while it was being frozen")
            target = dst / rel
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
            os.chmod(target.parent, 0o755)
            _write_new(target, data)
            total += size
        if tree_digest(dst) != expected:
            raise FreezeRefused("frozen copy does not reproduce the source identity")
    except BaseException:
        _abandon(dst)
        raise
    return FrozenTree(path=dst, digest=expected, file_count=len(files), total_bytes=total)


# ------------------------------------------------------------------------ the candidate


def _safe_relative(path: str) -> PurePosixPath:
    rel = PurePosixPath(path)
    if (rel.is_absolute() or not rel.parts or "\x00" in path or "\\" in path
            or any(part in {"", ".", "..", ".git"} for part in rel.parts)):
        raise FreezeRefused(f"unsafe candidate path {path!r}")
    return rel


def freeze_candidate(inventory: dict, repo_root: Path, dst: Path) -> FrozenTree:
    """Freeze exactly the files the reviewed inventory describes, byte-for-byte.

    Identity is the inventory's own snapshot digest, so what the owner approved is what runs."""
    repo_root, dst = Path(repo_root), Path(dst)
    if inventory.get("inventory_state") != "complete":
        raise FreezeRefused("candidate inventory is partial (some files were not read); refusing")
    entries = inventory.get("entries") or []
    for entry in entries:
        if entry.get("kind") == "symlink":
            raise FreezeRefused(f"{entry.get('path')!r} is a symlink in the candidate; refusing")
        if entry.get("kind") != "file" or entry.get("sha256") is None:
            raise FreezeRefused(f"{entry.get('path')!r} was not read (oversized or unsupported)")
    _begin(dst)
    try:
        total = 0
        records = []
        for entry in sorted(entries, key=lambda e: e["path"]):
            rel = _safe_relative(entry["path"])
            source = repo_root.joinpath(*rel.parts)
            data = _read_source(source)
            if sha256_hex(data) != entry["sha256"]:
                raise FreezeRefused(f"{entry['path']} changed since inspection")
            target = dst.joinpath(*rel.parts)
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
            for parent in [target.parent, *target.parent.parents]:
                if parent == dst.parent:
                    break
                os.chmod(parent, 0o755)
            _write_new(target, data)
            total += len(data)
            records.append((entry["path"], entry["kind"], entry["sha256"]))
        digest = sha256_hex(canonical_json(sorted(records)))
        if digest != inventory.get("snapshot_digest"):
            raise FreezeRefused("frozen candidate does not reproduce the inspected snapshot digest")
    except BaseException:
        _abandon(dst)
        raise
    return FrozenTree(path=dst, digest=digest, file_count=len(records), total_bytes=total)


# ------------------------------------------------------------------------ the entry bundle

_ASSETS = Path(__file__).resolve().parent / "sandbox_assets"
_ENTRY_FILES = ("collect.py", "probe.py")


def entry_digest() -> str:
    """Identity of the in-container collector bundle (same formula as a frozen directory)."""
    files = []
    for name in _ENTRY_FILES:
        digest, size = _hash_file(_ASSETS / name)
        files.append((name, digest, size))
    return _digest_of(sorted(files), [])


def freeze_entry(dst: Path) -> FrozenTree:
    """Place the collector bundle (collect.py + probe.py) in a new private tree."""
    dst = Path(dst)
    _begin(dst)
    try:
        total = 0
        for name in _ENTRY_FILES:
            data = _read_source(_ASSETS / name)
            _write_new(dst / name, data)
            total += len(data)
        digest = tree_digest(dst)
        if digest != entry_digest():
            raise FreezeRefused("frozen collector bundle does not match the shipped bundle")
    except BaseException:
        _abandon(dst)
        raise
    return FrozenTree(path=dst, digest=digest, file_count=len(_ENTRY_FILES), total_bytes=total)
