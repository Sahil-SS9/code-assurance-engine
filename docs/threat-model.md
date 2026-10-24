# Threat model (v0.1.0)

## Guarantee boundaries
- A compromised host, plugin runtime or owner account is OUTSIDE the guarantee boundary. Digests
  bind content; they do not defeat a same-authority malicious collector.
- Imported third-party reports stay `reported` evidence until their collector/provenance is
  authenticated (not implemented in v0.1.0 — nothing imports yet by construction).
- No universal vulnerability discovery, no semantic-equivalence, no "two models agree" safety.

## False-success threats (primary coverage)
- Producer lying via totals attributes: observed-vs-reported reconciliation surfaces the
  contradiction (junit parser; pytest terminal parser) — never silently reconciled.
- Forged XML/log counts: counted children are observed truth; attribute totals are reported.
- Receipt tampering post-stamp: receipt_id recompute rejects edited receipts (integrity test).
- Cross-candidate/attempt/caller recycling: reverify rejects all three (identity layers).
- exit-0 shell shim: still requires collection counts > 0 and parser-clean; unknown stays.
- Prose "canary": verify has no prose-succes slot; canary has no effect.
- Scorer-gaming model: advisory lane is labelled, bounded, and cannot mint execution, receipts
  or change the frozen contract (advisory module design + tests).

## Execution authority
- Default: EXECUTION_UNAVAILABLE — no public owner-grant route demonstrated (Phase-0 blocker
  C0.2) and no verified OS containment (C0.3). Refuses BY NAME at the operation boundary.
- TrustedGrant requires: issuer `outside-candidate-workspace`, decision_id, full identity
  binding (caller/candidate/contract/check/argv/env digests, expiry). Any mismatch denies.
- JSON `approved: true` / markdown signatures / supplied hashes are NEVER authority.

## Privacy
- Scrub-before-persist at the store boundary (privacy.scrub_record); redact-before-egress on
  exports (refuse-before-publish on residue). Exact-sensitive-key matching (word-anchored) so
  linkage keys like `env_allowlist` survive; identifier-shaped values pass untouched.
- Known limitation: clean output means "no known shape matched", never "nothing sensitive
  captured". A secret inside a trusted id-shaped field is not caught by patterns.
- No network egress (model lane default-OFF; runner env allowlist scrubbed via GIT_CONFIG_*).

## Model-supplied git refs (upstream review hardening)

- `assure_inspect` base/head come from the model. Option-like values (leading `-`) are refused
  BEFORE any git call at the service boundary; argparse rejects them at the CLI too.
- Every ref is resolved to a full SHA first (`git rev-parse --verify --end-of-options
  <ref>^{commit}`) and `--end-of-options` precedes the refs in every ref-args call, so a dash
  value can never be parsed as an option (the historical `-oFile=` output redirect).
- Refusal paths and early-stop walk caps must not write: the negative control asserts the
  attacker-chosen output path stays absent (`tests/adversarial/test_ref_injection.py`).

## Scope words
- Assessment statuses: ASSESSED_WITHIN_DECLARED_SCOPE / FINDINGS_PRESENT / INCOMPLETE /
  INVALID_EVIDENCE. Never SAFE / SECURE / READY_TO_MERGE. HANDOFF_READY is never a permission.
