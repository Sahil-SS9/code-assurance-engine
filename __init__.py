"""Code Assurance Engine — native Hermes plugin entrypoint.

Thin ``register(ctx)`` shim only: no scanning, no model calls, no tool dispatch at load time.
The domain package lives in ``src/hermes_code_assurance``; for directory-plugin installs the
package is importable either because the repo was pip-installed (``uv sync``/``pip install -e .``)
or via the versioned src-path fallback below.
"""

from __future__ import annotations

import sys
from pathlib import Path


def _ensure_package_importable() -> None:
    try:
        import hermes_code_assurance  # noqa: F401
    except ImportError:
        src = (Path(__file__).resolve().parent / "src").resolve()
        if (src / "hermes_code_assurance").is_dir() and str(src) not in sys.path:
            sys.path.insert(0, str(src))


def register(ctx) -> None:
    """Register tools, the ``/assure`` slash command, the ``hermes assure`` CLI subcommand and the
    shipped skill with the Hermes host. Fails closed: any surface the host does not offer
    (probed via ``hasattr``) is skipped and recorded in the returned registration report."""
    _ensure_package_importable()
    from hermes_code_assurance.adapters.hermes import register_plugin

    register_plugin(ctx)
