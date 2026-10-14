"""Host-lane tests (CT09/CT17): REAL load/register/unload on an installed Hermes host.

BLOCKED BY OWNER GATE (recorded, not silently skipped-as-passed):
  - SAHIL's build constraint for this run: do NOT install the plugin into any Hermes profile,
    so lifecycle/authority-route/route-parity evidence cannot be gathered on this machine.
  - These tests require a disposable isolated Hermes home on a vetted host.
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.skip(reason=(
    "BLOCKED: requires an installed plugin on an isolated Hermes host — "
    "no-install constraint honored this build (recorded blocker, not silent skip)"
))


def test_host_lifecycle_load_register_unload():  # pragma: no cover
    raise NotImplementedError


def test_cli_agent_slash_gateway_authentic_grant_and_denial():  # pragma: no cover
    raise NotImplementedError
