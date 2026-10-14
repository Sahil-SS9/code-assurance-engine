"""Evidence plumbing: trusted-collector identity, receipt id stamping, integrity assertion, and
digest helpers re-exported for the runner contract (single digest algorithm source of truth).
"""

from __future__ import annotations

from .authority import argv_digest as argv_digest_for  # noqa: F401 (re-export)
from .authority import env_digest as env_digest_for  # noqa: F401 (re-export)
from .jsonio import canonical_json, sha256_hex

TRUSTED_ID = "evaluator-owned-collector-boxed"


class EvidenceTampered(RuntimeError):
    """A persisted receipt no longer matches its stamped identity."""


def aspect_of_output(bits: bytes, box: str | None = None) -> str:
    """Digest of captured output bytes; optionally boxed to a collector instance identity."""
    return sha256_hex(canonical_json({"box": box, "output": sha256_hex(bytes(bits))}))


def parser_of(text: str, parser_id: str):
    """Parse producer output through the owned parser registry (bounded, no guessing)."""
    from . import parsers

    registry = parsers.registry()
    module = registry.get(parser_id)
    if module is None:
        raise ValueError(f"unsupported parser: {parser_id!r} — refuse, never guess")
    return module.parse_text(text)


def receipt_id(receipt: dict) -> str:
    """Deterministic receipt identity: sha256 over the canonical body minus the id itself."""
    body = {k: v for k, v in receipt.items() if k != "receipt_id"}
    return sha256_hex(canonical_json(body))


def assert_receipt_integrity(receipt: dict) -> None:
    stamped = receipt.get("receipt_id")
    if not stamped:
        raise EvidenceTampered("receipt has no receipt_id: unstampable evidence")
    if stamped != receipt_id(receipt):
        raise EvidenceTampered(
            "receipt id mismatch after recompute: contents changed post-stamping"
        )
