# Research decisions (recorded)

Reference papers (pin list from plan §8) were NOT re-read this build; single-method ablation,
input honesty: NO performance claim from a paper is adopted without its primary read. Marked
here so nothing below can be misread as literature-backed:

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
