"""Data-dir scoping refusals for the Hermes adapter (C4).

Refuse by name, never fall back silently: StateRootUnavailable (no trusted host resolution) and
SecurityRefusal (model-supplied path outside permitted roots). No bare-home fallback exists.
"""


class StateRootUnavailable(RuntimeError):
    """No trusted host path can be resolved for the plugin state root: refuse, no write."""


class SecurityRefusal(RuntimeError):
    """A supplied state_dir escapes every permitted root: refuse, no write."""
