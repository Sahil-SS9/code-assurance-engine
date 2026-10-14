"""Report rendering: bounded Markdown (and JSON) with escaping + correct status wording.

Rules: exact totals, escaped paths/tokens, claimed-by-grade wording, 'empty findings is not a
safe claim', failed/unknown required checks never read as clear.
"""

from __future__ import annotations

import html
import json

_STATUS_LABELS = {
    "PASSED": "passed (own observation, oracle-allowed)",
    "FAILED": "failed",
    "UNKNOWN": "unknown",
    "NOT_RUN": "not run (gaps remain)",
    "INTERRUPTED": "interrupted",
    "UNSUPPORTED": "unsupported",
}

_INCOMPLETE_ALWAYS_THRESHOLD = 0


def render_assessment(assessment: dict, *, candidate_summary: dict, contract=None) -> str:
    overall = assessment.get("overall_status", "INCOMPLETE")
    findings = assessment.get("findings") or []
    checks = assessment.get("checks") or []
    lines = ["# Code Assurance assessment", ""]
    repo_root = html.escape(str((assessment.get("candidate") or {}).get("repo_root", "")))
    if repo_root:
        lines.append(f"Candidate repository: {repo_root}")
        lines.append("")

    lines.append(f"Assessment status: **{overall}**")
    lines.append(
        "The check contract states allowed and disallowed areas; this report comments only within "
        "their scope."
    )
    lines.append(
        "An assurance report is not a release permission — no automatic apply/refuse/"
        "merge/deploy/follow-up behavior is derived from this report."
    )
    lines.append("")

    status_totals: dict[str, int] = {}
    for check in checks:
        status_totals[check["status"]] = status_totals.get(check["status"], 0) + 1
    if status_totals:
        lines.append(
            "Check results: " + ", ".join(f"{label}: {n}" for label, n in sorted(status_totals.items()))
        )
    else:
        lines.append("Check results: NOT_RUN: 0 checks were collected; the assessment segment stayed empty.")
    lines.append("")

    failed = [c for c in checks if c.get("status") in ("FAILED", "UNKNOWN", "NOT_RUN", "INTERRUPTED")]
    if failed:
        lines.append(f"Required-check gaps: {len(failed)} blocked or unknown — the assessment is not clean.")
        for check in failed:
            _label = _STATUS_LABELS.get(check.get("status"), check.get("status"))
            lines.append(f"- {check.get('check_id')}: {_label}")
        lines.append("")

    if not findings:
        lines.append(
            "No findings were produced. No findings is not a safe claim — it does not mean no "
            "defects exist elsewhere; it means the evaluator's checks saw no defects within the "
            "scoped, reviewed check contract."
        )
    else:
        lines.append(f"Findings: {len(findings)}")
        for finding in findings:
            summary = html.escape(str(finding.get("rationale", "")))
            lines.append(f"- {summary} (provenance: {finding.get('provenance', 'unknown')})")
        lines.append("")

    if candidate_summary.get("inventory_state") == "partial":
        lines.append("Candidate inventory is PARTIAL: some files could not be read or were capped.")

    lines.append("Proposed patches (if any) become a NEW candidate requiring a fresh assessment —")
    lines.append("they are never silently applied.")
    lines.append("")

    lines.append(
        "Proposed checks are never executed automatically. Running the evaluator's check suite "
        "against the current candidate requires explicit user approval in step 4 of the user "
        "journey, and only after the contract review (step 3) is complete."
    )
    lines.append(
        "Every executable check run records which surface (CLI, slash command, tool) requested it, "
        "and which surface requested each of the plan/verify/report calls; that mapping is bounded "
        "to this product's documented surfaces, not auto-sourced from detection heuristics."
    )
    lines.append("Report grade labels used: observed, reported, inferred, unknown.")
    return "\n".join(lines)


def render_assessment_json(assessment: dict, *, candidate_summary: dict, contract=None) -> str:
    export = {
        "assessment": assessment,
        "candidate_summary": candidate_summary,
        "scope_note": (
            "This JSON is a scope-qualified assessment within the reviewed check contract; "
            "no unconditional safe/ready-to-merge claim is conveyed."
        ),
    }
    if contract is not None:
        export["contract_id"] = getattr(contract, "contract_id", None)
    return json.dumps(export, sort_keys=True)
