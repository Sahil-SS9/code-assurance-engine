# hermes-code-assurance-engine (Code Assurance Engine)

Change-assurance engine for Hermes: evaluates an immutable repository candidate against an
explicit, reviewer-approved check contract and returns machine-readable evidence, findings and
unverified gaps. This is neither a model-confidence score nor a promise that code is safe because
two models agree.

- Default operation: read-only analysis (inventory, proposed check contract, status, reverify,
  private report).
- Running repository code is a separately approved, isolated operation. It stays unavailable
  (`NOT_APPROVED` pre-approval, `EXECUTION_UNAVAILABLE` after) — no unsafe fallback.
- Assessment verdicts: `ASSESSED_WITHIN_DECLARED_SCOPE`, `FINDINGS_PRESENT`, `INCOMPLETE`,
  `INVALID_EVIDENCE`. Never unconditional SAFE/SECURE/READY_TO_MERGE. An empty findings list is
  never a "safe" claim.

## Status (post review-repair round 1, honest)

- PARTIAL read-only / evidence foundation. Execution is UNIMPLEMENTED: the sandbox always
  refuses by name and the runner's success path is deliberately unreachable; host/platform test
  lanes are skipped RECORDED BLOCKERS, not runnable tests waiting on one permission.
- The protected-host trust seam (C0.2) and verified native containment (C0.3) remain OPEN
  engineering tasks. Until they land, the public service cannot clear production acceptance at
  all (`overall_status` stays INCOMPLETE by design; receipts lack authenticated provenance).
- A live installation or deleting the recorded stray directory does NOT supply the missing
  implementation, and neither is approved. Next milestone (owner decision pending): one complete
  harmless fixture journey with authentic owner-granted execution and verified native OS
  containment, then a live-project assessment.

See docs/threat-model.md, docs/provenance.md, docs/compatibility.md, docs/check-recipes.md and
docs/research-decisions.md.
