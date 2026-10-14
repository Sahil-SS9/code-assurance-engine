"""Execution isolation backend: refuse-by-name until a verified OS containment exists.

A disposable worktree or temporary directory is NOT a sandbox. v0.1.0 ships NO verified
backend: every execution request raises SandboxUnavailable, so the runner can never reach a
subprocess through this path. The Linux-native backend design lives in docs/threat-model.md.
"""

from __future__ import annotations


class SandboxUnavailable(RuntimeError):
    """Execution was requested but no verified OS isolation backend is configured."""


class IsolationBackend:
    verified: bool = False

    def request_run(self, *, check_id: str, argv: list[str], cwd: str, env: list[str]):
        raise SandboxUnavailable(
            "no verified OS isolation backend is configured: execution refused "
            "(Phase-0 blocker: native containment not attested)"
        )


def refundless_stub_backend() -> IsolationBackend:
    """Stdlib-only default backend — always unverified, always refuses."""
    return IsolationBackend()
