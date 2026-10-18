# TODO — Code Assurance Engine (pickup state)

Updated: 2026-10-18 · Accepted HEAD `30030af` · M1 execution slice + wiring: ON TOPOF `6a52add`,
uncommitted until owner review · Plan source of truth:
`/home/kensei/handoff/agent-plugin-plans/.hermes/plans/2026-10-14-code-assurance-engine.md`

## What this is

A change-assurance engine for Hermes: evaluates an immutable repository candidate against a
frozen reviewer-approved check contract and returns machine-readable evidence, findings and
unverified gaps. Verdicts are `ASSESSED_WITHIN_DECLARED_SCOPE` / `FINDINGS_PRESENT` /
`INCOMPLETE` / `INVALID_EVIDENCE` — never SAFE/READY_TO_MERGE. Empty findings is never a safe
claim.

## Current accepted state (Correction round CLOSED, independently verified)

- Accepted HEAD `30030afa6b0890c8a66df04051c0b0669ba6bb30` — see
  `ACCEPTANCE-2026-10-15-code-assurance-engine-30030af.md` in the handoff directory.
- Status: **PARTIAL READ-ONLY / EVIDENCE FOUNDATION**. Execution is unimplemented by design:
  the sandbox refuses by name, no public owner-grant route exists, and a receipt's own
  fields (grant_ref/collector, any spelling) cannot mint provenance — public verify keeps
  unauthenticated observations UNKNOWN with an explicit note and overall INCOMPLETE.
- Independent verification chain: Quan + KENSEI round-2/round-3 rechecks; reviewer probes
  green (`evidence/kensei-code-assurance-bd13be6/`
  and `evidence/kensei-code-assurance-be462d7-recheck/`); full owned suite 128 passed,
  0 failed/errors; 4 host/platform placeholders RECORD skip-blockers (never counted as passes).
- Provenance/licence: 100% independently authored; Apache-2.0; proprietary claude-security
  EXCLUDED. See `docs/provenance.md`, `NOTICE`, `THIRD_PARTY_NOTICES.md`.

## What exists (all verified)

- Schemas + bounded JSON: `jsonio.py`, `validators.py`, `contracts.py`,
  `schemas/check-contract-v1.json` (+ receipt/assessment to extend in C tasks below).
- Frozen candidate reader: `candidate.py` (argv-list git plumbing, config-bomb fences,
  symlink/LFS/ignore policies, partial-inventory honesty), `inspect.py` (inert classification,
  non-executable proposals), `test_delta.py` (no semantic-weakening claim).
- State machine `state.py` (restricted graph) + `store.py` (SQLite WAL, flock fence,
  SAVEPOINT nesting, CAS, scrub-before-persist), privacy `privacy.py` (exact-key redaction,
  refuse-before-publish, identifier preservation).
- Parsers (frozen v1): `parsers/junit_xml.py` (primary oracle, observed-vs-reported
  reconciliation) + `parsers/pytest_terminal.py` (best-effort, summary-vs-lines). **NO JS
  runner — recorded decision.**
- Execution gating: `authority.py` (full-binding TrustedGrant, deny-all default),
  `sandbox.py` (refuse-by-name), `runner.py` (both gates required; receipts stamped).
- Evidence: `evidence.py`, `verify.py` (tamper/cross/attempt/caller/canary rejection,
  all-skip + expected-collection + missing-required gates), `findings.py` (observed-only),
  `advisory.py` (factory-validated, OFF by default), `report.py` (escaped, honest wording).
- Surfaces: `service.py` (single facade), `cli.py`, `adapters/hermes.py` (per-call state-root
  ladder with refusals — no bare-home fallback), `skills/assure/SKILL.md`; host-validated
  manifest (`hermes plugins validate` OK).
- Tests: 17 files across unit/integration/adversarial + recorded-blocker host/platform
  stubs. Gate: `scripts/checks.sh` (includes uv + global hermes launcher; not a harmless
  read-only check).

## Current engineering state (18/10/2026 — M1 slice COMPLETE, awaiting the owner signature)

- M1 execution slice (Docker isolation + owner Ed25519 authority + freeze + protected
  collector + hostile-code batteries): 364 passed/4 skipped (see FINAL-IMPLEMENTATION-EVIDENCE).
- M1 step 3 WIRING (Kensei, 18 Oct): the public CLI route now consumes a real owner-signed
  bundle end to end — `assure approve` (owner-gated review completion: CONTRACT_REVIEW_REQUIRED
  -> APPROVED requires owner-class authority) and `assure run --owner-keys/--owner-request/
  --owner-signature` (authorize -> one-use ledger claim -> freeze -> attestation -> run ->
  protected collection -> recorded receipt), plus the verify seam: receipts clear ONLY on
  owner-class provenance in the private authority ledger; fixture-class provenance never
  clears (C5 preserved rigidly — no receipt field mints trust).
- New wiring suite: tests/integration/test_owner_journey_service.py (12 tests) — staging is
  exclusive, wrong-scope/edited/expired bundles refuse before ANY mutation, one-use replay
  refused, failing candidates honest, unauthenticated collect interrupts, scope-complete only
  with owner provenance.
- Suite at wiring head: 376 passed / 3 skipped (CT18 matrix placeholder retired to its honest
  blocker label; CT10 now runs for real). Ruff clean.
- Wiring evidence: evidence/code-assurance-first-check/run-20261018T-wiring-greenhead/.
- Remaining M1 finishing move (owner action then agent): Sahil runs the amended
  prepare-owner-approved-check.sh (fresh data_root ...engine-j1; exact journey argv + real
  digests supplied), then: verify bundle -> wired run on the real backend -> report -> owner
  review packet. CT17/CT18 remain recorded blockers (need a live host / other OSes).

**M2 (after the signed journey):** first REAL candidate assessment + value benchmark
(CT21: seeded defects, clean negatives, false-assurance rate) — needs owner-selected
candidate repo/goals.

**Later/optional:** more language parsers, OASIS SARIF adapter, SDK UI, policy integration
(each separately gated). Research leads in plan §8 (arXiv refs) remain unread/unadopted.

## Owner decisions pending (before the signed journey / M2)

- The one signature: Sahil runs prepare-owner-approved-check.sh with the real staged digest
  values (engine prints them; nothing else needed from him).
- M2 candidate repo + goals.
- Cleanup approval for the stray `~/.hermes/plugin-data/code-assurance-engine` (76K, engine-
  created test residue; preserved untouched; must NOT be deleted without named approval).
- Model lane stays factory-OFF (no egress spend approved).

## Constraints carried from the plan (still binding)

- BUILD/INSTALL/DEPLOY/PUBLISH are separate owner gates; nothing is installed anywhere yet.
- No delegation for implementation; agents leave unpushed commits — rule: push only on owner
  instruction (this push to the private GitHub remote was owner-instructed).
- Keep private persona builders/benchmarks/corpus/fleet config OUT of anything public.
- Future source drift may invalidate API pins (hermes-agent @ 0e427d78) — re-pin + rerun
  Phase-0 rather than patching drift silently.

## Quick commands

```sh
uv sync --extra dev
uv run python -m pytest tests/unit tests/integration tests/adversarial -q   # expect: 128 passed
uv run ruff check .
scripts/checks.sh   # full gate incl. read-only `hermes plugins validate`
# reviewer probes (GREEN expectations):
uv run python /home/kensei/handoff/agent-plugin-plans/evidence/kensei-code-assurance-be462d7-recheck/probe_c5_grant_correlation.py
```

Evidence + handoff trail lives under
`/home/kensei/handoff/agent-plugin-plans/` (plan, reviews, rechecks, acceptance, probes).
