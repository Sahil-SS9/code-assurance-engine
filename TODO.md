# TODO — Code Assurance Engine (pickup state)

Updated: 2026-10-15 · Accepted HEAD: `30030af` · Plan source of truth:
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

## Remaining work — next engineering milestone (owner-scoped, NOT yet authorised)

**M1 (recommended): one harmless check end-to-end (C0.2/C0.3 vertical slice).**

1. C0.2 authority path: implement the trusted host-side grant issuance (owner-run CLI writing
   a decision record OUTSIDE the candidate workspace) + runner consumption with full binding
   verification. Kernel/fixture unit seams exist; the protected-host route does not.
2. C0.3 isolation: pick and VERIFY a native containment backend (recommend bwrap spike first,
   fallback landlock/unshare). Gate = CT10 escape battery (network-off, read-only source/
   oracle, candidate-only writes, no credential/proc escape). Worktree/tmp is NOT a sandbox.
3. The journey: disposable scratch fixture repo → owner-approve contract → gated run with
   verified grant+isolation → trusted collector receipt → public verify (preserves C5 hold)
   → private JSON/Markdown report. No live profile writes; no install.
4. Convert the four skip-marked host/platform placeholder tests into runnable versions:
   CT09 (authority routes), CT10 (containment), CT17 (lifecycle on a real host), CT18 (matrix).

**M2 (after M1):** first REAL candidate assessment + value benchmark (CT21: seeded defects,
clean negatives, false-assurance rate) — needs owner-selected candidate repo/goals.

**Later/optional:** more language parsers, OASIS SARIF adapter, SDK UI, policy integration
(each separately gated). Research leads in plan §8 (arXiv refs) remain unread/unadopted.

## Owner decisions pending (before/during M1)

- Authority record format + issuance command + who signs what (C0.2).
- Isolation backend choice + acceptance evidence for CT10 (C0.3).
- Scope/permission set for M1 (it is engineering, not an INSTALL/DEPLOY/PUBLISH approval).
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
