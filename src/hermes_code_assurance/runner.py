"""CheckRunner: attempt contract checks; execution requires BOTH a verified grant AND a verified
OS isolation backend. With either missing every check records NOT_RUN / EXECUTION_UNAVAILABLE with
an explicit reason — never a silent skip, never a fallback. Advisory (model) input is ignored by
construction: it cannot create execution, grants or receipts.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime

from .authority import DenyAllAuthority, RunRequest, env_digest, verify_grant
from .jsonio import canonical_json, sha256_hex
from .sandbox import IsolationBackend, SandboxUnavailable


def _utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class CheckRunner:
    authority: object = field(default_factory=DenyAllAuthority)
    isolation: IsolationBackend = field(default_factory=IsolationBackend)
    collector: Callable | None = None
    # The gated execution seam: an adapter with execute_check(*, spec, base_receipt) that claims,
    # isolates and collects ONE verified grant. None keeps the legacy refusal path exactly.
    execution_adapter: object | None = None

    def attempt_checks(
        self,
        contract,
        *,
        candidate_digest: str,
        caller: str,
        grants: dict | None = None,
        trusted_decisions: dict | None = None,
        advisory: object | None = None,
        now_epoch_seconds: int | None = None,
    ) -> list[dict]:
        """Run the gated check pipeline for every required/optional check. Reads only the frozen
        contract; advisory suggestions are never inputs to any decision."""
        del advisory  # model output may not mint execution
        grants = grants or {}
        trusted_decisions = trusted_decisions or {}
        receipts: list[dict] = []
        for position, spec in enumerate(
            (*contract.required_checks, *contract.optional_checks), start=1
        ):
            receipts.append(
                self._attempt_one(
                    contract, spec, position,
                    candidate_digest=candidate_digest,
                    caller=caller,
                    grant=grants.get(spec.check_id),
                    trusted_decision=trusted_decisions.get(spec.check_id),
                    now_epoch_seconds=now_epoch_seconds,
                )
            )
        return receipts

    def _attempt_one(
        self,
        contract,
        spec,
        attempt: int,
        *,
        candidate_digest: str,
        caller: str,
        grant,
        trusted_decision,
        now_epoch_seconds: int | None,
    ) -> dict:
        base = {
            "check_id": spec.check_id,
            "attempt": attempt,
            "candidate_digest": candidate_digest,
            "contract_id": contract.contract_id,
            "argv_digest": sha256_hex(canonical_json(list(spec.argv))),
            "env_digest": env_digest(contract.env_allowlist),
            "grant_ref": grant.grant_id if grant is not None else None,
            "collector": "none",
            "observation_origin": None,
            "counts": None,
            "parser": {"id": spec.parser_id, "version_stamp": None},
            "observed": None,
            "artifacts": [],
            "flags": [],
            "created_at": _utc_now(),
        }

        if not spec.executable:
            return self._not_run(
                base,
                "EXECUTION_UNAVAILABLE",
                "proposed check is non-executable until contract approval",
            )

        if grant is None:
            return self._not_run(
                base,
                "EXECUTION_UNAVAILABLE",
                "no trusted grant available: no public owner-grant route demonstrated (C0.2)",
            )

        request = RunRequest(
            caller=caller,
            candidate_digest=candidate_digest,
            contract_id=contract.contract_id,
            check_id=spec.check_id,
            argv=tuple(spec.argv),
            env_digest=env_digest(contract.env_allowlist),
            now_epoch_seconds=now_epoch_seconds
            if now_epoch_seconds is not None
            else __import__("time").time() if False else int(datetime.now(UTC).timestamp())
        )
        decision = verify_grant(grant, request, trusted_decision)
        if not decision.granted:
            return self._not_run(
                base,
                "EXECUTION_UNAVAILABLE",
                f"authority denied: {'; '.join(decision.refusals)}",
            )

        if self.execution_adapter is not None:
            return self.execution_adapter.execute_check(spec=spec, base_receipt=base)

        try:
            self.isolation.request_run(
                check_id=spec.check_id, argv=list(spec.argv), cwd=spec.cwd,
                env=list(contract.env_allowlist),
            )
        except SandboxUnavailable as exc:
            return self._not_run(base, "EXECUTION_UNAVAILABLE", f"isolation refused: {exc}")

        # Only a verified backend plus a collector reaches here; v0.1.0 has neither in-tree,
        # so this branch is deliberately unreachable until Phase-0 gates pass (recorded blocker).
        raise RuntimeError(
            "verified isolation reached without an attested backend: refuse and investigate"
        )

    def _not_run(self, base: dict, reason: str, detail: str) -> dict:
        from .evidence import receipt_id

        receipt = {**base, "status": "NOT_RUN", "reason": reason, "detail": detail}
        receipt["receipt_id"] = receipt_id(receipt)
        return receipt
