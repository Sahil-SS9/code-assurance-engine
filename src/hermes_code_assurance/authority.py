"""Execution authority: trusted grants with full-identity binding, deny-by-default.

A grant is constructed ONLY from a trusted host decision whose issuer lives outside the
candidate-writable workspace. A JSON ``approved: true``, a markdown signature or a supplied hash
is never sufficient: every field mismatch denies, an expired grant denies, and a decision
without the trusted issuer marker denies. DenyAllAuthority is the v1 default until a public
owner-grant route is demonstrated (Phase-0 blocker C0.2).
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from .jsonio import canonical_json, sha256_hex

TRUSTED_ISSUER = "outside-candidate-workspace"


def argv_digest(argv) -> str:
    return sha256_hex(canonical_json([str(a) for a in argv]))


def env_digest(env_allowlist) -> str:
    return sha256_hex(canonical_json(sorted(str(e) for e in env_allowlist)))


def now_epoch() -> int:
    return int(time.time())


@dataclass(frozen=True)
class TrustedGrant:
    grant_id: str
    requester: str
    candidate_digest: str
    contract_id: str
    check_id: str
    argv_sha256: str
    env_sha256: str
    expires_epoch_seconds: int


@dataclass(frozen=True)
class RunRequest:
    caller: str
    candidate_digest: str
    contract_id: str
    check_id: str
    argv: tuple[str, ...]
    env_digest: str
    now_epoch_seconds: int


@dataclass
class AuthorityDecision:
    granted: bool
    refusals: list[str]


def _deny(refusals: list[str]) -> AuthorityDecision:
    return AuthorityDecision(False, refusals)


def verify_grant(
    grant: TrustedGrant, request: RunRequest, trusted_decision: dict | None
) -> AuthorityDecision:
    """Full binding check. Any mismatch or untrusted origin denies — accumulates all reasons."""
    refusals: list[str] = []
    if trusted_decision is None:
        refusals.append("no trusted decision supplied")
    else:
        issuer = trusted_decision.get("issuer")
        if issuer != TRUSTED_ISSUER:
            refusals.append(
                f"trusted decision issuer {issuer!r} is not {TRUSTED_ISSUER!r}"
            )
        if not trusted_decision.get("decision_id"):
            refusals.append("trusted decision has no decision_id")
    if request.caller != grant.requester:
        refusals.append(f"caller identity {request.caller!r} != requester {grant.requester!r}")
    if request.candidate_digest != grant.candidate_digest:
        refusals.append("candidate digest mismatch")
    if request.contract_id != grant.contract_id:
        refusals.append("contract id mismatch")
    if request.check_id != grant.check_id:
        refusals.append("check id mismatch")
    if argv_digest(request.argv) != grant.argv_sha256:
        refusals.append("argv digest mismatch")
    if request.env_digest != grant.env_sha256:
        refusals.append("env allowlist digest mismatch")
    if request.now_epoch_seconds >= grant.expires_epoch_seconds:
        refusals.append(f"grant expired at {grant.expires_epoch_seconds}")
    if refusals:
        return _deny(refusals)
    return AuthorityDecision(True, [])


class DenyAllAuthority:
    """v1 default: no public owner-grant route has been demonstrated, so nobody may execute."""

    def decision(self, anything: object) -> AuthorityDecision:
        return _deny(
            [
                ("EXECUTION_UNAVAILABLE: no public owner-grant route is demonstrated "
                "(Phase-0 blocker C0.2); refusing every execution request")
            ]
        )
