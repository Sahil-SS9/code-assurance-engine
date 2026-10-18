"""The owner-approved journey executor: binds a verified owner signature to exactly one real,
isolated collection of one frozen contract check.

Nothing here runs without (1) an OwnerAuthorization evaluated against that exact run, and
(2) an isolation backend that attests the exact policy for it. The claim is durable in the
AuthorityLedger BEFORE execution and the execution is recorded after — one-use forever.

This module owns the journey's concrete configuration (pinned image, check argv, environment
names, toolchain selection) so the staging helper, the operator script and the executor cannot
drift apart.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path

from .authority import env_digest
from .collector import parse_collect_output
from .evidence import parser_of, receipt_id
from .freeze import (
    FreezeRefused,
    entry_digest,
    freeze_candidate,
    freeze_directory,
    freeze_entry,
    tree_digest,
)
from .jsonio import load_json_bytes
from .owner_authority import (
    AuthorityDenied,
    Authorization,
    EffectiveIdentity,
    TrustRoot,
)
from .sandbox import SandboxInputs, SandboxPolicy, SandboxUnavailable

# The evaluator-owned oracle check id and the exact in-container command the check runs.
# The owner signs THIS argv; the frozen contract must carry the identical tuple.
JOURNEY_CHECK_ID = "calc-oracle"
JOURNEY_IMAGE = "python@sha256:48b13b003dda20b16f9442b8475aa05fe21bf6579a8c881db92ffb4d8fd20f83"
JOURNEY_CHECK_ARGV = (
    "python", "-B", "-m", "pytest", "/oracle/tests", "-p", "no:cacheprovider",
    "-o", "addopts=", "-o", "console_output_style=classic", "-v", "--junitxml=/tmp/result.xml",
)
JOURNEY_ENV = (
    "HOME", "LANG", "PYTEST_DISABLE_PLUGIN_AUTOLOAD", "PYTHONDONTWRITEBYTECODE",
    "PYTHONHASHSEED", "PYTHONPATH", "PYTHONUNBUFFERED", "TMPDIR", "PATH",
)
TOOLCHAIN_PACKAGES = ("pytest", "_pytest", "pluggy", "iniconfig", "packaging", "pygments", "py.py")

_DEFAULT_LIMITS = {
    "timeout_seconds": 60, "output_limit_bytes": 2 * 1024 * 1024, "memory_mb": 512,
    "pids": 64, "cpus": 1,
}


def toolchain_source() -> Path:
    """The executing interpreter's site-packages: the toolchain that will be frozen."""
    import pytest  # local import: the executing interpreter owns this

    return Path(pytest.__file__).resolve().parent.parent


def load_trust_root(path):
    """Production trust loading: the ONLY owner class comes from a foreign-controlled file."""
    return TrustRoot.load_owner(path, EffectiveIdentity.current())


def read_bundle(request_path, signature_path) -> tuple[bytes, bytes]:
    """Bounded reads of the owner's signed request and signature. No JSON parsing here."""
    from .owner_authority import MAX_REQUEST_BYTES

    parts: list[bytes] = []
    for raw_path, label in ((request_path, "request"), (signature_path, "signature")):
        path = Path(raw_path)
        if not path.is_file() or path.is_symlink():
            raise AuthorityDenied([f"the owner {label} file is missing or not a regular file"])
        size = path.stat().st_size
        if size > MAX_REQUEST_BYTES:
            raise AuthorityDenied([f"the owner {label} file is larger than the allowed size"])
        parts.append(path.read_bytes())
    request, signature = parts
    if not request or not signature:
        raise AuthorityDenied(["both a request and a signature file are required"])
    return request, signature


def peek_owner_operation(request_bytes: bytes) -> dict:
    """Read the signed operation for the fields the store cannot know (owner label, attempt id).

    Everything read here is UNTRUSTED and only shapes the comparison: every operation field is
    still bound against the frozen store state in OwnerAuthority.evaluate.
    """
    from .owner_authority import OPERATION_FIELDS

    try:
        body = load_json_bytes(request_bytes, max_bytes=64 * 1024)
    except Exception as exc:
        raise AuthorityDenied([f"the request is not strict bounded JSON: {exc}"]) from exc
    if not isinstance(body, dict) or not isinstance(body.get("operation"), dict):
        raise AuthorityDenied(["request does not carry an operation object"])
    operation = body["operation"]
    missing = [field for field in OPERATION_FIELDS if field not in operation]
    if missing:
        raise AuthorityDenied([f"operation is missing field(s): {sorted(missing)}"])
    owner = operation.get("owner")
    attempt_id = operation.get("attempt_id")
    attempt = operation.get("attempt")
    return {"owner": owner, "attempt_id": attempt_id, "attempt": attempt}



def journey_policy(image: str, limits: dict) -> SandboxPolicy:
    """The policy every run in this build uses: image + the five signed limits, rest defaults."""
    return SandboxPolicy(
        image=image,
        timeout_seconds=int(limits["timeout_seconds"]),
        output_limit_bytes=int(limits["output_limit_bytes"]),
        memory_mb=int(limits["memory_mb"]),
        pids=int(limits["pids"]),
        cpus=int(limits["cpus"]),
    )


def journey_default_limits() -> dict:
    return journey_policy(JOURNEY_IMAGE, _DEFAULT_LIMITS).limits()


@dataclass(frozen=True)
class JourneySpecs:
    """The exact scope values the owner signs. Derived from store + engine constants only."""

    check_id: str
    argv: tuple[str, ...]
    image: str
    limits: dict
    candidate_digest: str
    contract_id: str
    assessment_id: str
    env_digest: str
    oracle_digest: str
    toolchain_digest: str
    collector_digest: str
    isolation_policy_digest: str

    def policy(self) -> SandboxPolicy:
        return journey_policy(self.image, self.limits)


def journey_specs_from(
    *, assessment: dict, contract, staged_oracle: Path
) -> JourneySpecs:
    """Re-derive the full signed scope from the FROZEN store state. Read-only; never executes."""
    executable_required = [check for check in contract.required_checks if check.executable]
    if len(contract.required_checks) != 1 or len(executable_required) != 1:
        reason = ("the owner journey authorises exactly one executable required check; "
                  "this contract does not describe one")
        raise AuthorityDenied([reason])
    spec = executable_required[0]
    payload = assessment["payload"]
    policy = journey_policy(JOURNEY_IMAGE, journey_default_limits())
    return JourneySpecs(
        check_id=spec.check_id,
        argv=tuple(str(a) for a in spec.argv),
        image=JOURNEY_IMAGE,
        limits=policy.limits(),
        candidate_digest=str(payload.get("inventory_digest")),
        contract_id=contract.contract_id,
        assessment_id=str(assessment["id"]),
        env_digest=env_digest(contract.env_allowlist),
        oracle_digest=tree_digest(Path(staged_oracle)),
        toolchain_digest=tree_digest(toolchain_source(), names=TOOLCHAIN_PACKAGES),
        collector_digest=entry_digest(),
        isolation_policy_digest=policy.digest(),
    )


def stage_digest_bundle(specs: JourneySpecs) -> dict:
    """The exact values an owner script must place in the request it signs."""
    return {
        "assessment_id": specs.assessment_id,
        "contract_id": specs.contract_id,
        "check_id": specs.check_id,
        "candidate_digest": specs.candidate_digest,
        "oracle_digest": specs.oracle_digest,
        "toolchain_digest": specs.toolchain_digest,
        "collector_digest": specs.collector_digest,
        "policy_digest": specs.isolation_policy_digest,
        "env_digest": specs.env_digest,
        "argv": list(specs.argv),
        "image": specs.image,
        "limits": dict(specs.limits),
    }


# -------------------------------------------------------------------------- the executor


class OwnerJourneyExecutor:
    """Executes one authorized check: claim -> freeze -> attest -> run -> collect -> record."""

    def __init__(
        self,
        *,
        backend,
        ledger,
        authorization: Authorization,
        state_dir: Path,
        contract,
        candidate_source: Path,
        candidate_base,
        candidate_head,
        expected_candidate_digest: str,
        staged_oracle: Path,
        caller: str,
        now_epoch_seconds: int | None = None,
    ):
        self.backend = backend
        self.ledger = ledger
        self.authorization = authorization
        self.operation = authorization.operation
        self.state_dir = Path(state_dir)
        self.contract = contract
        self.candidate_source = Path(candidate_source)
        self.candidate_base = candidate_base
        self.candidate_head = candidate_head
        self.expected_candidate_digest = str(expected_candidate_digest)
        self.staged_oracle = Path(staged_oracle)
        self.caller = caller
        self._now = int(time.time()) if now_epoch_seconds is None else now_epoch_seconds
        self._claimed = False

    # -- claims -------------------------------------------------------------------
    def _claim(self) -> None:
        if self._claimed:
            return
        self.ledger.claim(self.authorization)
        self._claimed = True

    # -- runner seam ----------------------------------------------------------------
    def execute_check(self, *, spec, base_receipt: dict) -> dict:
        """Runner adapter: claim, freeze, attest, run, collect, record. Never raises."""
        if spec.check_id != self.operation.get("check_id"):
            return _not_run(base_receipt, "EXECUTION_UNAVAILABLE",
                            "the signed request binds a different check id")
        base_receipt = {**base_receipt, "caller": self.caller}
        try:
            self._claim()
        except AuthorityDenied as exc:
            return _not_run(base_receipt, "EXECUTION_UNAVAILABLE",
                            f"authority refused: {exc}")

        attempt_id = str(self.operation.get("attempt_id"))
        attempt_dir = self.state_dir / "journey" / f"attempt-{attempt_id}"
        try:
            # One-shot: an attempt directory exists already -> earlier ambiguous attempt.
            if attempt_dir.exists():
                return _not_run(base_receipt, "EXECUTION_UNAVAILABLE",
                                f"attempt directory already exists: {attempt_dir}")
            attempt_dir.mkdir(mode=0o700)

            policy = journey_policy(self.operation["image"], self.operation["limits"])
            if policy.digest() != self.operation.get("isolation_policy_digest"):
                return _not_run(base_receipt, "EXECUTION_UNAVAILABLE",
                                "signed isolation policy digest does not match the run policy")

            from .candidate import GitCandidateReader

            inventory = GitCandidateReader().read(
                self.candidate_source, base=self.candidate_base, head=self.candidate_head
            ).as_dict()
            if inventory.get("snapshot_digest") != self.expected_candidate_digest:
                return _not_run(base_receipt, "EXECUTION_UNAVAILABLE",
                                "candidate changed after inspection (snapshot digest differs)")
            if inventory.get("inventory_state") != "complete":
                return _not_run(base_receipt, "EXECUTION_UNAVAILABLE",
                                "candidate inventory is partial; refusing to freeze for execution")

            candidate_tree = freeze_candidate(inventory, self.candidate_source,
                                              attempt_dir / "candidate")
            oracle_tree = freeze_directory(self.staged_oracle, attempt_dir / "oracle")
            toolchain_tree = freeze_directory(
                toolchain_source(), attempt_dir / "toolchain", names=TOOLCHAIN_PACKAGES
            )
            entry_tree = freeze_entry(attempt_dir / "entry")
            for label, tree, signed in (
                ("candidate", candidate_tree, self.expected_candidate_digest),
                ("oracle", oracle_tree, self.operation.get("oracle_digest")),
                ("toolchain", toolchain_tree, self.operation.get("toolchain_digest")),
                ("collector", entry_tree, self.operation.get("collector_digest")),
            ):
                if str(getattr(tree, "digest", "")) != str(signed):
                    return _not_run(base_receipt, "EXECUTION_UNAVAILABLE",
                                    f"{label} digest does not match the signed scope")

            inputs = SandboxInputs(
                candidate=candidate_tree.path, oracle=oracle_tree.path,
                toolchain=toolchain_tree.path, entry=entry_tree.path,
            )
            inputs.validate()
            attestation = self.backend.attest(policy, inputs)
            observation = self.backend.run_check(
                policy=policy, inputs=inputs, check_argv=[str(a) for a in spec.argv],
                attempt_id=attempt_id, attestation=attestation,
            )
        except (FreezeRefused, SandboxUnavailable) as exc:
            _discard_dir(attempt_dir)
            return _not_run(base_receipt, "EXECUTION_UNAVAILABLE", f"isolation refused: {exc}")
        except AuthorityDenied as exc:
            _discard_dir(attempt_dir)
            return _not_run(base_receipt, "EXECUTION_UNAVAILABLE", f"authority refused: {exc}")
        except Exception as exc:  # noqa: BLE001 - deliberate: any failure is an honest interrupt
            _discard_dir(attempt_dir)
            return _interrupt(base_receipt, [f"execution adapter failure: {exc!r}"],
                              collector=self.backend.collector_id)

        collected = parse_collect_output(observation.output)
        execution = {
            "nonce": self.authorization.nonce,
            "assessment_id": str(self.operation.get("assessment_id")),
            "attempt_id": attempt_id,
            "check_id": spec.check_id,
            "collector": self.backend.collector_id,
            "attestation_sha256": attestation.sha256,
            "launch_digest": observation.launch_digest,
            "container_id": observation.container_id,
        }
        receipt = self._final_receipt(base_receipt, spec, observation, collected)
        try:
            self.ledger.record_execution(**execution, receipt_id=receipt["receipt_id"])
        except AuthorityDenied as exc:
            # The execution happened but cannot be bound to the claim: the receipt must never
            # promote itself, so it is demoted to INTERRUPTED with the binding refusal.
            receipt["status"] = "INTERRUPTED"
            receipt["reason"] = "EXECUTION_BINDING_REFUSED"
            receipt["detail"] = f"execution provenance could not be recorded: {exc}"
            receipt["receipt_id"] = _restamp(receipt)
        return receipt

    # -- receipt assembly ----------------------------------------------------------
    def _final_receipt(self, base: dict, spec, observation, collected) -> dict:
        extra: dict = {
            "collector": self.backend.collector_id,
            "observation_origin": "protected-collector-nonce-v1",
            "counts": None,
            "observed": {
                "exit_code": observation.exit_code,
                "signal": collected.signal if collected.authenticated else None,
                "timed_out": observation.timed_out, "oom_killed": observation.oom_killed,
                "truncated": observation.truncated,
                "output_sha256": observation.output_sha256,
                "started_at": observation.started_at, "finished_at": observation.finished_at,
                "duration_seconds": observation.duration_seconds,
                "deadline_exceeded": (
                    collected.deadline_exceeded if collected.authenticated else None
                ),
                "authenticated": bool(collected.authenticated),
            },
            "artifacts": [],
            "flags": ["isolation-attested"],
            "reason": None,
            "detail": None,
        }
        if not collected.authenticated or observation.problems or not observation.cleanup_verified:
            detail = " or ".join(filter(None, [
                *_looks(observation.problems), *_looks(collected.problems),
            ]))
            extra["detail"] = detail or (
                "the collector stream did not authenticate; no assumption about the result"
            )
            extra["flags"].append("unauthenticated-collection")
            if observation.problems or not observation.cleanup_verified:
                extra["flags"].append("container-cleanup-unverified")
            return _finish({**base, **extra, "status": "INTERRUPTED"})
        if collected.deadline_exceeded or observation.timed_out:
            extra["detail"] = "the check exceeded its bounded deadline; the container was removed"
            extra["flags"].append("deadline-exceeded")
            return _finish({**base, **extra, "status": "INTERRUPTED"})

        outcome = parser_of(collected.junit.decode("utf-8", errors="replace"), spec.parser_id)
        extra["counts"] = dict(outcome.counts or {})
        extra["artifacts"] = [
            {"format": "junit-xml", "sha256": collected.junit_sha256, "bytes": len(collected.junit)}
        ]
        extra["parser"] = {
            "id": outcome.parser_id, "version_stamp": None, "status_hint": outcome.status_hint,
            "reasons": list(outcome.reasons or []),
            "discrepancies": list(outcome.discrepancies or []),
        }
        exit_code = observation.exit_code
        extra["observed"] = {**extra["observed"], "exit_code": exit_code}
        counts = extra["counts"]
        failed = (counts.get("failed") or 0) + (counts.get("errors") or 0)
        skipped = counts.get("skipped") or 0
        collected_count = counts.get("collected") or 0
        if outcome.status_hint == "unknown" or outcome.discrepancies or collected_count == 0:
            extra["detail"] = "; ".join(
                [*(outcome.reasons or []), *(outcome.discrepancies or [])]
            ) or "the observation does not reconcile; it does not assert anything"
            extra["flags"].append("non-reconciled-observation")
            return _finish({**base, **extra, "status": "UNKNOWN"})
        if exit_code != 0 or failed > 0:
            extra["detail"] = f"observed failures/errors: {failed}; process exit: {exit_code}"
            return _finish({**base, **extra, "status": "FAILED"})
        if skipped:
            extra["detail"] = f"{skipped} collected test(s) skipped; skips are never a pass"
            extra["flags"].append("skips-present")
            return _finish({**base, **extra, "status": "UNKNOWN"})
        return _finish({**base, **extra, "status": "PASSED"})


# ------------------------------------------------------------------------ helpers


def _looks(values) -> list[str]:
    return [str(value) for value in (values or []) if value]


def _discard_dir(directory: Path) -> None:
    """Remove a partial attempt directory: execution never started under it."""
    import shutil

    shutil.rmtree(directory, ignore_errors=True)


def _not_run(base: dict, reason: str, detail: str) -> dict:
    receipt = {
        **base, "status": "NOT_RUN", "reason": reason, "detail": detail,
        "collector": base.get("collector") or "none",
        "observation_origin": None, "counts": None, "observed": None,
        "artifacts": [], "flags": ["refused-before-execution"],
    }
    return _finish(receipt)


def _interrupt(base: dict, details: list[str], *, collector: str) -> dict:
    receipt = {
        **base, "status": "INTERRUPTED", "reason": "EXECUTION_INTERRUPTED",
        "detail": " or ".join(_looks(details)) or "execution interrupted before a trusted result",
        "collector": collector, "observation_origin": None, "counts": None,
        "observed": None, "artifacts": [], "flags": ["interrupted-before-collection"],
    }
    return _finish(receipt)


def _finish(receipt: dict) -> dict:
    receipt["receipt_id"] = receipt_id(receipt)
    return receipt


def _restamp(receipt: dict) -> str:
    receipt.pop("receipt_id", None)
    return receipt_id(receipt)
