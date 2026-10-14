# hermes-code-assurance-engine (Code Assurance Engine)

Change-assurance engine for Hermes: evaluates an immutable repository candidate against an
explicit, reviewer-approved check contract and returns machine-readable evidence, findings and
unverified gaps. This is neither a model-confidence score nor a promise that code is safe because
two models agree.

- Default operation: read-only analysis (inventory, proposed check contract, status, reverify,
  private report).
- Running repository code is a separately approved, isolated operation. It stays unavailable
  (`EXECUTION_UNAVAILABLE`) until the authority and isolation gates pass — no unsafe fallback.
- Assessment verdicts: `ASSESSED_WITHIN_DECLARED_SCOPE`, `FINDINGS_PRESENT`, `INCOMPLETE`,
  `INVALID_EVIDENCE`. Never unconditional SAFE/SECURE/READY_TO_MERGE. An empty findings list is
  never a "safe" claim.

Status: v0.1.0 in build; BUILD-gated work. INSTALL/DEPLOY/PUBLISH are separate owner gates and are
NOT granted — this repository has not been installed into any Hermes profile.

See docs/threat-model.md, docs/provenance.md, docs/compatibility.md, docs/check-recipes.md and
docs/research-decisions.md when they land.
