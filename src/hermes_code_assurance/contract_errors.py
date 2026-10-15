"""Contract integrity refusals."""

from __future__ import annotations


class ContractIntegrityRefusal(RuntimeError):
    """A stored contract is absent, mismatched or fails its own identity stamp: refuse."""
