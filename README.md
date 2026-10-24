# Code Assurance Engine

**Change assurance with receipts, not confidence scores.**

Code Assurance Engine evaluates an immutable repository candidate against an explicit, reviewer-approved check contract. It returns machine-readable evidence, concrete findings and the gaps that remain unverified — so a green result has a defined scope.

**Status:** v0.1 evidence foundation. The read-only assessment, contract, evidence and reporting workflow is implemented and tested. Execution is a separate deployment track, enabled only after the trusted-host and native-containment prerequisites are approved.

## At a glance

| Area | What it gives you |
|---|---|
| Candidate evaluation | One immutable candidate, identified by content |
| Check contract | Reviewer-approved checks, expected evidence and failure conditions |
| Evidence | Machine-readable observations, findings and unverified gaps |
| Verdicts | A bounded result that never collapses into an unconditional “safe” |
| Privacy | Read-only defaults, redaction and private local reports |
| Authority | Owner-controlled approvals, separate from model output |

## Why it exists

A passing test suite answers a narrow question. It does not say what was checked, what was skipped, what the candidate actually did, or which claims remain unsupported.

Code Assurance makes those boundaries explicit:

- the candidate is frozen and identifiable;
- the checks are agreed before evaluation;
- the evidence is recorded and re-verifiable;
- missing proof is reported as missing, not rounded up to success.

## How it works

1. **Freeze** an immutable repository candidate and record its identity.
2. **Agree** a reviewer-approved check contract covering commands, expected evidence and failure conditions.
3. **Assess** the candidate through the public service and produce findings, observations and gaps.
4. **Reverify** the recorded evidence and produce a private report.
5. **Extend to execution only when approved** through the isolated, owner-controlled lane.

## Verdicts

| Verdict | Meaning |
|---|---|
| `ASSESSED_WITHIN_DECLARED_SCOPE` | The declared checks completed and the evidence supports the stated scope |
| `FINDINGS_PRESENT` | The assessment found issues that need attention |
| `INCOMPLETE` | Required evidence or scope is missing |
| `INVALID_EVIDENCE` | The evidence failed integrity or consistency checks |

The engine never returns an unconditional `SAFE`, `SECURE` or `READY_TO_MERGE`. An empty findings list is not a safety claim.

## Safety model

- Read-only analysis is the default.
- Candidate code execution is a separate, explicitly approved operation.
- Public verification does not promote unauthenticated observations into proof.
- Owner authority is external to the model and the candidate.
- Reports are private by default and can be rendered without external assets.
- Missing evidence stays visible in the output.

**Trust boundary for gateway use:** owner approval is bounded by whoever can reach
`/assure approve`. `--owner-keys` names the trust root the CLI reads, so the approval is as
strong as access to that surface. In a gateway session the approval gates on the session
decide; keep the trust root outside the model-reachable workspace, and run the approval from
an operator shell when that gate is not trusted.

## What you can do today

- Inspect a repository candidate and produce a proposed check contract.
- Run the read-only assessment and status workflow.
- Reverify evidence and generate a private report.
- Integrate through the public service, CLI and native plugin surfaces.
- Use the recorded verification harness to validate the evidence chain.

## Roadmap

- Complete the trusted-host and native-containment execution path.
- Add the approved end-to-end owner-signed journey as a production lane.
- Broaden check recipes and evidence adapters.
- Publish stable compatibility and deployment guidance.

## Documentation

- [Documentation index](docs/README.md)
- [Threat model](docs/threat-model.md)
- [Provenance](docs/provenance.md)
- [Compatibility](docs/compatibility.md)
- [Check recipes](docs/check-recipes.md)
- [Research decisions](docs/research-decisions.md)
- [Current pickup state](TODO.md)

Licensed under Apache-2.0. See [NOTICE](NOTICE) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

Repository: https://github.com/Sahil-SS9/code-assurance-engine
