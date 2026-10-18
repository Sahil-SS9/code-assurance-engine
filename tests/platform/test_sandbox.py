"""Platform-lane test placeholders (CT18 + lifecycle matrix).

Status after the M1 execution slice (rootless-Docker backend landed):

- CT10 (OS-level containment + escape battery) is IMPLEMENTED for the supported host: the real
  rootless-Docker platform suite runs it now — see ``test_rootless_docker_backend.py``
  (network-off, read-only inputs, output flood, pids/memory bounds, hostile candidates,
  descendant cleanup, cancellation, forgery). No placeholder remains for CT10 on this host.
- CT18 (full surface matrix incl. Windows/macOS read-only-feature verification) still needs
  hosts this build does not touch; it remains a recorded blocker, never a pass.

Legacy CT10 placeholder retired 2026-10-18 M1 wiring (replaced by the running platform suite).
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.skip(reason=(
    "BLOCKED: the CT18 surface matrix needs Windows/macOS hosts this build does not touch "
    "(recorded blocker, never a pass); CT10 containment is covered by the rootless-Docker "
    "platform suite"
))


def test_matrix_clean_profile_install_rollback():  # pragma: no cover
    raise NotImplementedError
