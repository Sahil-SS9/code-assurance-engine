"""Redaction-before-persistence and refuse-before-publish.

Pattern sets are anchored (non-word boundaries around label-style matches; prefix-literal
token styles) so identifier-shaped values (sha256 hex, uuids) pass through untouched.
Identifier FIELDS are never rewritten — whole sensitive keys are DROPPED, not truncated.
The second guard refuses to publish when residue from an unmatched secret *shape* remains.

Known limitation (stated, not hidden): "clean output" means "no known shape matched", never
"nothing sensitive was captured". A credential embedded inside a trusted id-shaped field is not
caught by the pattern filter.
"""

from __future__ import annotations

import re

DROPPED = "[DROPPED]"

# Token shapes with typed prefixes: literal anchors make hex-id false positives impossible.
_TOKEN_PATTERNS = [
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED-AWS-KEY]"),
    (re.compile(r"\bghp_[A-Za-z0-9]{20,}\b"), "[REDACTED-GITHUB-TOKEN]"),
    (re.compile(r"\bsk-(?:ant|proj)?[A-Za-z0-9-]{16,}\b"), "[REDACTED-API-KEY]"),
    (
        re.compile(
            r"\b(?i:bearer|authorization|api[-_]?key|secret|password|token)\b\s*[:=]\s*"
            r"(?i:(?:bearer\s+)?[^\s;,]{8,})"
        ),
        "[REDACTED-ASSIGNMENT]",
    ),
    (re.compile(r"[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}"), "[REDACTED-EMAIL]"),
]

# Residue detector: any remaining typed-prefix fragment means the scrub could not clean this
# document — the export/store path must refuse, never publish partial secrets.
_RESIDUE = re.compile(r"(?i:\b(?:akia|ghp_|sk-(?:ant|proj)))")

# Exact sensitive KEY NAMES (case-insensitive). Prefix matching must never be allowed: keys like
# "env_allowlist" carry linkage, not credentials — dropping them corrupts the record.
_SENSITIVE_KEY_RE = re.compile(
    r"^(?i:api[-_]?key|authorization|bearer|cookie|credential|credentials|passwd|password|"
    r"secret|token|env|headers|prompt|raw)$"
)


class RedactionFailure(ValueError):
    """A scrubbed document still shows secret-shaped residue: refuse, don't publish."""


def redact(text: str) -> str:
    """Scrub every known secret shape from free text."""
    out = str(text)
    for pattern, marker in _TOKEN_PATTERNS:
        out = pattern.sub(marker, out)
    return out


def redact_or_refuse(text: str) -> str:
    """redact(), then refuse when residue persists."""
    scrubbed = redact(text)
    if _RESIDUE.search(scrubbed):
        raise RedactionFailure("secret-shaped residue survived redaction: refusing output")
    return scrubbed


def _drop(value, key=""):
    """Sensitive KEY semantics: the value is dropped whole, never truncated or rewritten."""
    return DROPPED


def scrub_record(value):
    """Recursive scrubber for JSON-shaped records: redact free text, drop sensitive keys."""
    if isinstance(value, dict):
        return {
            k: (_drop(v, k) if _SENSITIVE_KEY_RE.search(str(k)) else scrub_record(v))
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [scrub_record(v) for v in value]
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return redact(str(value))
