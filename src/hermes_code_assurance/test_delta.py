"""Test-delta analysis: added/removed/renamed/modified test files and visible skips.

Honest limits, hard-coded: no universal semantic-weakening claim; per-file test adequacy is
unknown, never zero; assertion-count drift is not reported as detected.
"""

from __future__ import annotations

import ast

ADEQUACY_LIMIT = {
    "semantic_weakening": "not-claimed",
    "adequacy_per_file": "unknown",
    "skips": "visible-only",
}


def analyse(inv: dict, *, new_contents: dict[str, str], old_contents: dict[str, str]) -> dict:
    added, removed, renamed, modified = [], [], [], []
    for change in inv.get("committed_changes", []):
        status, path = change["status"], change["path"]
        if status == "A":
            added.append(path)
        elif status == "D":
            removed.append(path)
        elif status == "R":
            renamed.append({"path": path, "old_path": change.get("old_path", "")})
        elif status in ("M", "MM", "MT"):
            modified.append(path)

    skips: list[dict] = []
    unknown_reasons: list[dict] = []
    known_names: list[str] = []
    test_paths = [p for p in (*added, *modified, *(r["path"] for r in renamed))]
    for path in test_paths:
        if not _looks_like_test(path):
            continue
        source = new_contents.get(path)
        if source is None:
            unknown_reasons.append({"path": path, "reason": "new-content-not-provided"})
            continue
        try:
            tree = ast.parse(source)
        except SyntaxError as exc:
            unknown_reasons.append({"path": path, "reason": f"ast-parse-failed: {exc.msg}"})
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef):
                continue
            if node.name.startswith("test_"):
                known_names.append(f"{path}::{node.name}")
            for dec in node.decorator_list:
                mark = _mark_name(dec)
                if mark in ("skip", "xfail", "skipif"):
                    skips.append({"path": path, "name": node.name, "mark": mark})
        unknown_reasons.append({"path": path, "reason": "adequacy-unknown-not-detectable-here"})

    return {
        "added": added,
        "removed": removed,
        "renamed": renamed,
        "modified": modified,
        "skips": skips,
        "known_names": known_names,
        "unknown_reasons": unknown_reasons,
        "limits": dict(ADEQUACY_LIMIT),
    }


def _mark_name(dec: ast.expr) -> str | None:
    target = dec.func if isinstance(dec, ast.Call) else dec
    if isinstance(target, ast.Attribute):
        return target.attr
    if isinstance(target, ast.Name):
        return target.id
    return None


def _looks_like_test(path: str) -> bool:
    import os

    return os.path.basename(path).startswith("test_") or "/tests/" in path
