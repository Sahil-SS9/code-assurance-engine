---
name: assure
description: How to use the Code Assurance Engine tools/CLI — read-only candidate assessment; execution requires verified authority and isolation gates.
version: 1
---

# assure — Code Assurance Engine usage

## What this does

Read-only candidate assessment of an immutable repository change against a reviewer-owned frozen
check contract. Outputs: inventory, classification, proposed (non-executable) contract, gated
check results (blocked by default), exact totals, findings with provenance labels, and a final
scoped report. Empty findings is NOT a safe claim.

## Surfaces

- Tools: `assure_inspect` (read-only), `assure_plan_checks`, `assure_status`, `assure_verify`,
  `assure_report`, `assure_run` (the SOLE repository-code-executing tool; blocked until the
  public owner-grant route AND verified OS isolation are demonstrated — C0.2/C0.3 blockers).
- Slash: `/assure <subcommand> [args]` mapping to the same service functions.
- CLI: `hermes assure inspect|plan|run|status|verify|report ...`
- CLI approval: review from step 3 of the user journey owner — from `APPROVED` state the owner
  may lead into `RUNNING` PLAN by feeding a real grant; with no grant route the tool stays
  EXECUTION_UNAVAILABLE.

## Boundaries

- NEVER executes repository code without BOTH a verified grant AND a verified OS isolation
  backend. Disposable worktrees are not sandboxes and are refused by name.
- Model-generated suggestions are advisory only; they never become execution, grant, receipt,
  or a frozen contract change.
- Proposed patches become a NEW candidate; they are never silently applied or auto-merged.
- A blocked run records `NOT_RUN` receipts with explicit reasons (`EXECUTION_UNAVAILABLE`,
  `authority denied`, etc.) — never a silent skip and never a downgrade to PASSED.

## Ordering (the only valid flow)

1. `assure_inspect` → produces INSPECTED assessment.
2. `assure_plan_checks` → freeze the reviewed contract (CONTRACT_REVIEW_REQUIRED).
3. Owner approval of contract → CLI `assure` (manual review; no automatic path).
4. `assure_run` → currently records EXECUTION_UNAVAILABLE as a visible gate-unmet state.
5. `assure_verify` → recomputed from receipts; same identity layers.
6. `assure_report` → markdown or JSON private copy.
