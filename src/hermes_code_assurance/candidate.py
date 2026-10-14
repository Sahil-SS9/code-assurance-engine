"""Frozen byte-level candidate reading through controlled git plumbing.

The reader never executes repository code: external diffs, textconv filters and fs monitors are
disabled per invocation, host/overlay git config is scrubbed via env, git is invoked as an argv
list (never a shell string), and only read-only plumbing commands are used (hooks cannot fire).
Ignored files and policy inputs (symlink/LFS) are recorded as data, never executed.
"""

from __future__ import annotations

import os
import subprocess
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from .jsonio import canonical_json, sha256_hex

DEFAULT_MAX_FILES = 5000
DEFAULT_MAX_FILE_BYTES = 2_000_000
GIT_TIMEOUT_SECONDS = 30


def scrubbed_git_env() -> dict[str, str]:
    """Env that strips every source of repo-config-driven code execution for our git calls."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(
        {
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_SYSTEM": "/dev/null",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "LC_ALL": "C",
        }
    )
    return env


# Per-command fences: pager off, fsmonitor off, hooks pointed at nothing hookable.
_INVOKE_FENCES = [
    "--no-pager",
    "-c", "core.fsmonitor=false",
    "-c", "core.hooksPath=/dev/null",
]


def _utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class CandidateInventory:
    repo_root: str
    base: str | None
    head: str | None
    committed_changes: list[dict]
    dirty_tracked: list[dict]
    untracked: list[str]
    ignored: list[str]
    entries: list[dict]
    toolchain: dict
    limits: dict
    inventory_state: str  # "complete" | "partial"
    policy_notes: str
    snapshot_digest: str
    created_at: str

    def as_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class GitCandidateReader:
    """Reads the candidate and returns the frozen inventory. Trusted collector; project read-only."""

    max_files: int = DEFAULT_MAX_FILES
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES

    def _git(self, repo: Path, *args: str) -> bytes:
        argv = ["git", *_INVOKE_FENCES, *args]
        proc = subprocess.run(
            argv,
            check=False,
            cwd=str(repo),
            shell=False,  # type: ignore[arg-type]
            capture_output=True,
            timeout=GIT_TIMEOUT_SECONDS,
            env=scrubbed_git_env(),
        )
        if proc.returncode != 0:
            raise RuntimeError(f"git {' '.join(args[:3])} failed: {proc.stderr.decode()[:200]}")
        return proc.stdout

    def _git_status_porcelain(self, repo: Path) -> list[tuple[str, str, str]]:
        """(status, path, old_path|'') triples from porcelain v1 with untracked+ignored."""
        out = self._git(
            repo, "status", "--porcelain=v1", "-z", "--untracked-files=all", "--ignored"
        ).decode("utf-8", errors="replace")
        rows: list[tuple[str, str, str]] = []
        tokens = out.split("\x00")
        i = 0
        while i < len(tokens):
            tok = tokens[i]
            if not tok:
                i += 1
                continue
            status, path = tok[:2], tok[3:].strip('"')
            old_path = ""
            if status[0] in ("R", "C") and i + 1 < len(tokens) and tokens[i + 1]:
                i += 1
                old_path = tokens[i].strip('"')
            rows.append((status, path, old_path))
            i += 1
        return rows

    def _committed_changes(self, repo: Path, base: str, head: str | None) -> list[dict]:
        common = [
            "diff", "--name-status", "--no-ext-diff", "--no-textconv", "--find-renames",
            "-r", "-z",
        ]
        refs = [base, head] if head else [base]
        out = self._git(repo, *common, *refs).decode("utf-8", errors="replace")
        tokens = [t for t in out.split("\x00") if t]
        changes: list[dict] = []
        i = 0
        while i < len(tokens):
            status = tokens[i]
            i += 1
            code = status[:1]
            if code in ("R", "C") and i + 2 <= len(tokens):
                old, new = tokens[i], tokens[i + 1]
                changes.append({"status": code, "path": new, "old_path": old})
                i += 2
                continue
            if i < len(tokens) and code in ("A", "D", "M", "T"):
                changes.append({"status": code, "path": tokens[i], "old_path": ""})
                i += 1
                continue
            break
        return changes

    def _toolchain_identity(self) -> dict:
        version = subprocess.run(
            ["git", "--version"], check=False, capture_output=True, timeout=GIT_TIMEOUT_SECONDS,
            env=scrubbed_git_env(),
        ).stdout.decode(errors="replace").strip()
        return {"git": version or "unknown", "env": "unknown", "python": sys.version.split()[0]}

    def read(self, repo_root: os.PathLike | str, *, base: str | None, head: str | None):
        repo = Path(repo_root).resolve()
        partial = False
        if not (repo / ".git").exists():
            return self._read_plain_dir(repo, base, head)

        committed = self._committed_changes(repo, base, head) if base else []
        status_rows = self._git_status_porcelain(repo)
        dirty = [{"status": s, "path": p} for s, p, _ in status_rows if s[0] not in "?!"]
        untracked = [p for s, p, _ in status_rows if s == "??"]
        ignored = [p for s, p, _ in status_rows if s == "!!"]

        listed = self._git(repo, "ls-files", "-z", "--cached", "--others", "--exclude-standard")
        files = [t for t in listed.decode("utf-8", errors="replace").split("\x00") if t]
        if len(files) > self.max_files:
            partial = True
        entries: list[dict] = []
        for rel in sorted(files)[: self.max_files]:
            path = repo / rel
            if os.path.islink(path):
                entries.append(
                    {"path": rel, "kind": "symlink", "mode": None, "size": None, "sha256": None,
                     "note": f"symlink -> {os.readlink(path)}"}
                )
                continue
            if not path.is_file():
                continue
            size = path.stat().st_size
            if size > self.max_file_bytes:
                entries.append(
                    {"path": rel, "kind": "file", "mode": None, "size": size, "sha256": None,
                     "note": "oversized-not-read"}
                )
                partial = True
                continue
            entries.append(
                {"path": rel, "kind": "file", "mode": None, "size": size,
                 "sha256": sha256_hex(path.read_bytes()), "note": ""}
            )

        notes = ["file cap exceeded"] if len(files) > self.max_files else []
        if any(e["kind"] == "symlink" for e in entries):
            notes.append("symlink recorded (target bytes not dereferenced)")
        if _detect_lfs_attributes(repo):
            notes.append("lfs-detected")
        identity_records = sorted(
            (e["path"], e["kind"], e["sha256"]) for e in entries if e["sha256"] is not None
        )
        return CandidateInventory(
            repo_root=str(repo),
            base=base,
            head=head,
            committed_changes=committed,
            dirty_tracked=dirty,
            untracked=untracked,
            ignored=ignored,
            entries=entries,
            toolchain=self._toolchain_identity(),
            limits={"max_files": self.max_files, "max_file_bytes": self.max_file_bytes},
            inventory_state="partial" if partial else "complete",
            policy_notes="; ".join(notes),
            snapshot_digest=sha256_hex(canonical_json(identity_records)),
            created_at=_utc_now(),
        )

    def _read_plain_dir(self, repo: Path, base: str | None, head: str | None):
        """Non-git scope: honest read-only walk; gitignore semantics are NOT applied."""
        entries: list[dict] = []
        overshoot = False
        for root, _dirs, names in os.walk(repo):
            if ".git" in root.split(os.sep):
                continue
            for name in names:
                rel = os.path.relpath(os.path.join(root, name), repo)
                path = repo / rel
                if os.path.islink(path):
                    entries.append(
                        {"path": rel, "kind": "symlink", "size": None, "sha256": None,
                         "mode": None, "note": f"symlink -> {os.readlink(path)}"}
                    )
                    continue
                size = path.stat().st_size
                if size > self.max_file_bytes:
                    entries.append(
                        {"path": rel, "kind": "file", "size": size, "sha256": None,
                         "mode": None, "note": "oversized-not-read"}
                    )
                    overshoot = True
                    continue
                entries.append(
                    {"path": rel, "kind": "file", "size": size,
                     "sha256": sha256_hex(path.read_bytes()), "mode": None, "note": ""}
                )
        entries.sort(key=lambda e: e["path"])
        overshoot = overshoot or len(entries) > self.max_files
        note = "plain directory (gitignore semantics not applied: no repo)"
        if any(e["kind"] == "symlink" for e in entries):
            note += "; symlink recorded (target bytes not dereferenced)"
        records = sorted(
            (e["path"], e["kind"], e["sha256"]) for e in entries if e["sha256"] is not None
        )
        return CandidateInventory(
            repo_root=str(repo),
            base=base,
            head=head,
            committed_changes=[],
            dirty_tracked=[],
            untracked=[e["path"] for e in entries],
            ignored=[],
            entries=entries,
            toolchain=self._toolchain_identity(),
            limits={"max_files": self.max_files, "max_file_bytes": self.max_file_bytes},
            inventory_state="partial" if overshoot else "complete",
            policy_notes=note,
            snapshot_digest=sha256_hex(canonical_json(records)),
            created_at=_utc_now(),
        )


def _detect_lfs_attributes(repo: Path) -> bool:
    p = repo / ".gitattributes"
    if p.is_file() and not os.path.islink(p):
        try:
            text = p.read_text(errors="replace")[:20000]
        except OSError:
            return False
        return "filter=lfs" in text
    return False
