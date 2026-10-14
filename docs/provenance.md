# Provenance

## Upstream pins (retrieved / verified this build)
- Anthropic plugin marketplace tree pin: commit `8bd00f08f0b04705e610cf132fbe2cf5ec44cfe3`
  (scratch mirror `~/.hermes/cache/scratch/claude-plugins-review-6dnkv47q/source`) — READ-ONLY
  conceptual reference; no bytes copied into this codebase.
- Hermes pin H: NousResearch/hermes-agent @ `0e427d788d253630d38a3a51cd76849e73cd6925`; objects
  verified in the local vanilla checkout (read via `git show 0e427d78:<path>`). No edits made to
  any Hermes checkout.

## Component licence walk (allowed sources only)
| Source | Own license | Used as |
|---|---|---|
| plugins/code-review | Apache-2.0 (its own LICENSE) | conceptual: reviewer-lens taxonomy |
| plugins/pr-review-toolkit | Apache-2.0 (its own LICENSE) | conceptual: review lens list |
| plugins/security-guidance | Apache-2.0 (its own LICENSE) | conceptual only; no hook/network reuse |
| plugins/code-modernization/scripts+tests | Apache-2.0 (their own LICENSE) | conceptual only; no cross-plugin imports |
| plugins/claude-security | PROPRIETARY | EXCLUDED completely: no port, no translation, no schemas |
| OASIS SARIF v2.1.0 spec | public standard | not bundled in v0.1.0 |

## Code origin honesty
- 100% of src/hermes_code_assurance is INDEPENDENTLY authored this build. No file is a byte-port
  or translation of any upstream file. Pure-concept influence only; negative-control ideas
  (planted defects, forged-totals fixtures, canary-counters) were re-specified from first
  principles for this engine.

## Prior-art pointers
- plugin-catalog references pinned in the planning document were NOT adversarially verified this
  build beyond a catalog collision check (empty result) — documented, not claimed.
