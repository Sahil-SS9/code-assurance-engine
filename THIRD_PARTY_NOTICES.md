# Third-party notices

This product (hermes-code-assurance-engine) is independently authored code under Apache-2.0.

## Conceptual sources actually used (Apache-2.0, anthropics/claude-plugins-official)

Used ONLY as conceptual/advisory inputs; no bytes, prompts, schemas or test fixtures were copied.

- `plugins/code-review` (Apache-2.0, own LICENSE) — informed the *idea* of multi-perspective
  advisory review lenses (error paths, test relevance, API/types) which was re-specified here as
  advisory recipes with explicit provenance labels.
- `plugins/pr-review-toolkit` (Apache-2.0, own LICENSE) — informed review-lens taxonomy only.
- `plugins/security-guidance` (Apache-2.0, own LICENSE) — informed the existence of pattern /
  test-discipline advisory lenses; no hook notification or network behaviour was adopted.
- `plugins/code-modernization/scripts` + tests (Apache-2.0, own LICENSE) — informed the *concept*
  of measured-result contracts and negative controls; re-specified independently.

Upstream pins for the above: see docs/provenance.md (immutably pinned commit 8bd00f08f0b04705e610cf132fbe2cf5ec44cfe3).

## Excluded (proprietary, not used)

- `plugins/claude-security` — proprietary license; forbids redistribution and non-Anthropic use.
  Its code, prompts, workflows, schemas and documentation are NOT used, translated or adapted in
  this product in any form. Referenced only to document the exclusion.

## Public standards referenced (not bundled)

- OASIS SARIF v2.1.0 specification (public standard) — optional later adapter target; not bundled
  in v0.1.0; redistribution terms to be reviewed before any bundling.
