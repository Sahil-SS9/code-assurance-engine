"""Platform-lane tests (CT10/CT18): OS-level containment and the full surface matrix.

BLOCKED BY OWNER GATE (recorded):
  - v0.1.0 ships NO verified OS isolation backend (Phase-0 blocker C0.3); execution is refused
    by name ({sandbox.SandboxUnavailable}).
  - Windows/macOS read-only-feature verification needs hosts this build does not touch.
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.skip(reason=(
    "BLOCKED: native containment backend is not attested (C0.3); execution remains refused "
    "by name until a verified isolated backend lands"
))


def test_native_containment_and_escapes():  # pragma: no cover
    raise NotImplementedError


def test_matrix_clean_profile_install_rollback():  # pragma: no cover
    raise NotImplementedError
