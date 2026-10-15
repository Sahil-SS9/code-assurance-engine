# Research decisions (recorded)

## Round-3 (C5 residual correction, recheck be462d7 → repair 10614d9)
10. Recheck reproduced the fabricated-grant residual: any non-null grant_ref (made-up or empty)
    moved an unauthenticated receipt from UNKNOWN to PASSED and emptied missing_required.
    Root cause: the round-2 downgrade keyed on `grant_ref is None` — spelling-affected.
    Repair: provenance cannot derive from receipt content in ANY spelling; at the public seam
    every otherwise-passing observation stays UNKNOWN with an explicit provenance note, and
    required coverage remains unresolved until the protected-host authority/collector seam
    exists (C0.2/C0.3 unchanged, open). Parameterised RED-first regressions (absent / null /
    empty / made-up / invented) plus a separately labelled test-owned kernel positive control
    document the boundary. Overall INCOMPLETE cap retained exactly as reviewed.

## Round-2 (review-repair round, 2026-10-15)
8. Review round 1 REPRODUCED five defect classes; repairs C1–C5 are recorded here:
   - C1: verdict gates added (all-skipped ≠ pass; expected-collection mismatch ≠ pass; missing
     required check ids named explicitly; duplicates/optional receipts cannot cover).
   - C2: the COMPLETE canonical contract persists under payload["contract"]; every consumer
     re-parses THAT dict; any contract-id drift or identity-stamp failure REFUSES (no rebuild
     from draft+defaults anywhere).
   - C3: run requires APPROVED and refuses BEFORE mutation; whole run = one fenced transaction
     (interrupted run rolls back receipts AND state together); verify is idempotent and refuses
     new-receipt drift without writing (restricted graph preserved, not opened up).
   - C4: per-call state-root ladder: trusted registered override → args override only when
     inside permitted roots → host-active plugin-data → REFUSE with no write. No bare
     Path.home() fallback exists any more. Reviewed stray directory left untouched pending
     separate owner cleanup approval.
   - C5: production provenance is strict: the collector identity layer cannot clear from
     receipt content; receipts without authenticated grant correlation stay UNKNOWN with an
     explicit note; scope-complete overall is unreachable from the public service until the
     protected-host trust seam lands. The product is labelled PARTIAL read-only / evidence
     foundation; execution remains unimplemented.
9. skip-marked host/platform tests remain open C0.2/C0.3 tasks (NotImplementedError bodies) —
   they are NOT runnable-pending-one-permission tests and are never counted as passing.

Reference papers (pin list from plan §8) were NOT re-read; NO performance claim is adopted
without its primary read.

## Decisions actually made this build
1. NO JavaScript runner — the plan's "one explicitly supported JS runner" was NOT frozen in
   v0.1.0 (Scope: pytest/JUnit only). Explicit refusal of a half-supported surface.
2. Execution model: default DENY-ALL. Runner reaches a real subprocess only via verified grant
   AND verified OS backend; neither exists in-tree, so the "stub collector" plan lane is
   deferred rather than faked.
3. Status vocabulary used: the plan's five per-check statuses (PASSED / FAILED / UNKNOWN /
   NOT_RUN / INTERRUPTED / UNSUPPORTED) with zero synthesized "GREEN"-style vocabulary. No
   unconditional SAFE-like verdicts anywhere in code (test-enforced).
4. Advisory model lane: persisted OFF by default; ctx.llm exists (verified at H) solely as the
   hook point; failures/unavailability always visible; refusal never hides. No consensus proof.
5. JSON Schema subset validator implemented in-tree (not a jsonschema dependency). Advantages:
   bounded, refuse-on-unknown-keyword; no silent misvalidation. Recorded as deviation from
   "use jsonschema" convenience; ablation not performed.
6. Redaction: exact-key anchoring after a REAL overreach catch (env_allowlist dropped because
   the prefix matcher matched). Lesson learned: exact name anchoring; deterministic refusal.
   No per-install salt opaque refs yet (CT14 keeps baseline redaction; salted refs deferred).
7. SQLite store with flock + SAVEPOINT nesting (one-writer). flock reentrancy keyed per-store
   instance; deadlock beat (30s→0.05s poll) demonstrated in a test.

## Rejected ideas
- "Safe if two models agree" — rejected (plan §Product decision).
- Allowlist shortcuts for the residue guard ("policy can disable the guard") — refused by design.
- Homegrown .gitignore parser for non-git cwd (approximation risk) — refused; non-git scope
  records "gitignore semantics not applied" instead.
