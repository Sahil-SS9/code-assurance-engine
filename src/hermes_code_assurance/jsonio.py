"""Bounded, duplicate-resistant JSON loading and canonical serialisation.

Guarantees: size, depth and node-count caps are enforced; duplicate object keys are refused
(never silently last-wins); NaN/Infinity are refused both at parse and post-load; canonical
serialisation is deterministic and refuses non-finite data.
"""

from __future__ import annotations

import hashlib
import json
import math
from typing import Any


class JSONIOError(ValueError):
    """Base error for bounded JSON operations."""


class TooLarge(JSONIOError):
    """Payload exceeds the byte cap."""


class TooDeep(JSONIOError):
    """Loaded structure exceeds the container-depth cap."""


class TooManyNodes(JSONIOError):
    """Loaded structure exceeds the node-count cap."""


class DuplicateKey(JSONIOError):
    """An object contained the same key twice."""


class NonFiniteNumber(JSONIOError):
    """NaN or Infinity appeared (as a literal, or via an overflowing exponent)."""


class JSONSyntaxError(JSONIOError):
    """Malformed JSON bytes."""


DEFAULT_MAX_BYTES = 1_000_000
DEFAULT_MAX_DEPTH = 32
DEFAULT_MAX_NODES = 10_000


def _refuse_constant(name: str):
    raise NonFiniteNumber(f"non-finite JSON constant: {name}")


def _walk_limit(value: Any, max_depth: int, max_nodes: int, *, depth: int = 0) -> None:
    """Enforce depth/node caps with eager raising."""
    if depth > max_depth:
        raise TooDeep(f"JSON nesting deeper than {max_depth}")
    if isinstance(value, float) and not math.isfinite(value):
        raise NonFiniteNumber("non-finite float in loaded document")
    if isinstance(value, dict):
        if len(value) > max_nodes:
            raise TooManyNodes(f"JSON document exceeds {max_nodes} nodes")
        for child in value.values():
            _walk_limit(child, max_depth, max_nodes, depth=depth + 1)
    elif isinstance(value, list):
        if len(value) > max_nodes:
            raise TooManyNodes(f"JSON document exceeds {max_nodes} nodes")
        for child in value:
            _walk_limit(child, max_depth, max_nodes, depth=depth + 1)


def _no_duplicate_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise DuplicateKey(f"duplicate JSON object key: {key!r}")
        out[key] = value
    return out


def load_json_bytes(
    data: bytes | bytearray | str,
    *,
    max_bytes: int = DEFAULT_MAX_BYTES,
    max_depth: int = DEFAULT_MAX_DEPTH,
    max_nodes: int = DEFAULT_MAX_NODES,
) -> Any:
    """Parse bytes (or str) to Python structures under hard caps.

    Order of checks: size → syntax → duplicates → finite → depth → nodes.
    """
    if isinstance(data, str):
        data = data.encode("utf-8")
    if not isinstance(data, (bytes, bytearray)):
        raise JSONIOError("load_json_bytes expects bytes or str")
    if len(data) > max_bytes:
        raise TooLarge(f"JSON payload is {len(data)} bytes; cap is {max_bytes}")
    try:
        loaded = json.loads(
            bytes(data),
            object_pairs_hook=_no_duplicate_object,
            parse_constant=_refuse_constant,
        )
    except NonFiniteNumber:
        raise
    except (DuplicateKey, TooLarge, TooDeep, TooManyNodes):
        raise
    except ValueError as exc:
        raise JSONSyntaxError(f"malformed JSON: {exc}") from exc
    _walk_limit(loaded, max_depth, max_nodes)
    return loaded


def canonical_json(value: Any) -> bytes:
    """Deterministic UTF-8 serialisation (sorted keys, tight separators, ASCII-escaped,
    non-finite refused). The identity primitive for every digest in this engine."""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    """Lowercase hex sha256 — the only hash algorithm used for stored identities."""
    return hashlib.sha256(data).hexdigest()
