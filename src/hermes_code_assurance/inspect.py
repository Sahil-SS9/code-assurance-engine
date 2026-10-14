"""Inventory classification and read-only contract proposal.

Deterministic; cannot execute anything; injection-flavoured paths/labels stay inert data until
render-time escaping. Proposals start non-executable — execution is a separately gated decision.
"""

from __future__ import annotations

_SUFFIX_LANG = {
    ".py": "python", ".pyi": "python", ".js": "javascript", ".mjs": "javascript", ".ts": "typescript",
    ".rs": "rust", ".go": "go", ".sh": "shell", ".java": "java", ".cs": "csharp", ".rb": "ruby",
    ".kt": "kotlin", ".swift": "swift", ".c": "c", ".h": "c", ".cpp": "cpp", ".cc": "cpp",
}

_RISK_HINTS = (
    ("migrations/", "migration-risk"),
    ("auth/", "security-sensitive"),
    ("permissions/", "security-sensitive"),
    ("secrets/", "security-sensitive"),
    ("infra/", "infra-touching"),
    ("plugin", "plugin-boundary"),
)


def _language_of(path: str) -> str:
    suffix = path.rsplit(".", 1)[-1] if "." in path else ""
    return _SUFFIX_LANG.get(f".{suffix}", "unknown")


def classify_inventory(inv: dict) -> dict:
    """Pure classification over an already-read inventory dict. No project code runs."""
    paths: set[str] = set()
    for entry in inv.get("entries", []):
        paths.add(entry["path"])
    for change in inv.get("committed_changes", []):
        paths.add(change["path"])
    paths.update(inv.get("untracked", []))
    paths.update(inv.get("ignored", []))

    languages: dict[str, int] = {}
    risk_hints: set[str] = set()
    for path in sorted(paths):
        lang = _language_of(path)
        languages[lang] = languages.get(lang, 0) + 1
        for needle, hint in _RISK_HINTS:
            if needle in path:
                risk_hints.add(hint)

    supported = ["pytest-machine-readable"] if any(p.endswith(".py") for p in paths) else []
    return {
        "languages": languages,
        "risk_hints": sorted(risk_hints),
        "supported_runtimes": supported,
        "unsupported": ["javascript-test-runners"] if _language_of("x.js") == "javascript" and any(
            p.endswith((".js", ".mjs")) for p in paths
        ) else [],
    }


def propose_draft_contract(inv: dict) -> dict:
    """Propose (never approve, never execute) a CheckContract v1-shaped draft. Read-only."""
    classification = classify_inventory(inv)
    areas: list[str] = sorted(
        {*(c["path"] for c in inv.get("committed_changes", [])), *inv.get("untracked", [])}
    ) or ["<repository-root>"]
    required = []
    if "pytest-machine-readable" in classification["supported_runtimes"]:
        required.append(
            {
                "check_id": "runner-proposed-pytest",
                "label": "pytest run (proposed; executable only after approval gate)",
                "kind": "test-run",
                "argv": ["python", "-m", "pytest", "-q"],
                "cwd": ".",
                "parser_id": "pytest-terminal",
                "executable": False,
            }
        )
    return {
        "schema": "check-contract-v1",
        "goal": "assess the candidate change against proposed deterministic checks",
        "assessed_areas": areas,
        "required_checks": required,
        "optional_checks": [],
        "negative_checks": [],
        "env_allowlist": ["PATH"],
        "network_enabled": False,
        "model_enabled": False,
        "supported_platforms": ["linux"],
        "proposed_by": "review",
    }
