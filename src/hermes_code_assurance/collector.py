"""Protected-collector wire protocol: the host trusts ONE authenticated result line.

The in-container entry script (sandbox_assets/collect.py) prints a fresh random nonce as its very
first output, runs the check as a child whose output it captures, and finally prints a single
result line carrying that nonce. Everything else on the stream is untrusted noise and is never
interpreted. The check cannot write the result line itself: it does not know the nonce (it exists
only in the entry script's memory and on the host's side of the stream).

Honest limit: code running INSIDE the same process as the test runner can still forge the numbers
the runner reports. This protocol authenticates *who produced the result block*, not the honesty of
a hostile candidate; see docs/threat-model.md.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from dataclasses import dataclass, field

NONCE_PREFIX = b"::ASSURE-NONCE-v1 "
RESULT_PREFIX = b"::ASSURE-RESULT-v1 "
PROBE_PREFIX = b"::ASSURE-PROBE-v1 "

MAX_STREAM_BYTES = 4 * 1024 * 1024
MAX_JUNIT_BYTES = 1024 * 1024
MAX_CHILD_OUTPUT_BYTES = 640 * 1024
_NONCE_RE = re.compile(rb"^[0-9a-f]{32}$")
_HEADER_FIELDS = {
    "v", "exit_code", "signal", "child_output_b64", "child_output_bytes", "child_output_sha256",
    "child_output_truncated", "junit_present", "junit_b64", "junit_bytes", "junit_sha256",
    "junit_problem", "deadline_exceeded",
}


@dataclass(frozen=True)
class CollectedResult:
    authenticated: bool
    exit_code: int | None = None
    signal: int | None = None
    child_output: bytes = b""
    child_output_bytes: int = 0
    child_output_sha256: str = ""
    child_output_truncated: bool = False
    junit_present: bool = False
    junit: bytes = b""
    junit_sha256: str = ""
    junit_problem: str | None = None
    deadline_exceeded: bool = False
    problems: list[str] = field(default_factory=list)


def _refused(problems: list[str]) -> CollectedResult:
    return CollectedResult(authenticated=False, problems=problems)


def _is_int(value) -> bool:
    return type(value) is int


def _decode(label: str, value, limit: int, problems: list[str]) -> bytes | None:
    if not isinstance(value, str):
        problems.append(f"malformed {label}: not text")
        return None
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        problems.append(f"malformed {label}: not valid base64")
        return None
    if len(raw) > limit:
        problems.append(f"{label} too large ({len(raw)} bytes)")
        return None
    return raw


def parse_collect_output(output: bytes) -> CollectedResult:
    """Return the authenticated result, or a refusal naming every problem found."""
    problems: list[str] = []
    if not isinstance(output, (bytes, bytearray)) or not output:
        return _refused(["no nonce line: the collector produced no output"])
    output = bytes(output)
    if len(output) > MAX_STREAM_BYTES:
        return _refused(["collector stream too large to interpret"])
    lines = output.split(b"\n")
    if not lines[0].startswith(NONCE_PREFIX):
        return _refused(["no nonce line first: the stream does not begin with the collector nonce"])
    nonce = lines[0][len(NONCE_PREFIX):].strip()
    if not _NONCE_RE.fullmatch(nonce):
        return _refused(["nonce line is malformed"])

    authentic: list[bytes] = []
    for line in lines[1:]:
        if line.startswith(NONCE_PREFIX):
            problems.append("decoy nonce line ignored")
        elif line.startswith(RESULT_PREFIX):
            rest = line[len(RESULT_PREFIX):]
            claimed, _, body = rest.partition(b" ")
            if claimed == nonce:
                authentic.append(body)
            else:
                problems.append("decoy result line carrying another nonce ignored")
    if not authentic:
        return _refused([*problems, "no authentic result line carries the collector nonce"])
    if len(authentic) > 1:
        return _refused([*problems, "more than one authentic result line (ambiguous)"])

    try:
        header = json.loads(authentic[0])
    except (ValueError, UnicodeDecodeError):
        return _refused([*problems, "malformed result header (not JSON)"])
    if not isinstance(header, dict):
        return _refused([*problems, "malformed result header (not an object)"])
    if set(header) != _HEADER_FIELDS:
        return _refused([*problems, "result header has missing or unexpected field(s)"])
    if header["v"] != 1 or not _is_int(header["v"]):
        return _refused([*problems, "unsupported protocol version"])

    bad = []
    for name in ("exit_code", "signal"):
        if header[name] is not None and not _is_int(header[name]):
            bad.append(name)
    for name in ("child_output_truncated", "junit_present", "deadline_exceeded"):
        if type(header[name]) is not bool:
            bad.append(name)
    for name in ("child_output_bytes", "junit_bytes"):
        if not _is_int(header[name]) or header[name] < 0:
            bad.append(name)
    for name in ("child_output_sha256", "junit_sha256"):
        if not isinstance(header[name], str) or not re.fullmatch(r"[0-9a-f]{64}", header[name]):
            bad.append(name)
    if header["junit_problem"] is not None and not isinstance(header["junit_problem"], str):
        bad.append("junit_problem")
    if (header["exit_code"] is None) == (header["signal"] is None):
        bad.append("exit_code/signal (exactly one must be set)")
    if bad:
        return _refused([*problems, f"result header has inconsistent field(s): {bad}"])

    child = _decode("child output", header["child_output_b64"], MAX_CHILD_OUTPUT_BYTES, problems)
    junit = _decode("junit", header["junit_b64"], MAX_JUNIT_BYTES, problems)
    if child is None or junit is None:
        return _refused(problems)
    if hashlib.sha256(child).hexdigest() != header["child_output_sha256"]:
        problems.append("child output digest does not match its content")
    if hashlib.sha256(junit).hexdigest() != header["junit_sha256"]:
        problems.append("junit digest does not match its content")
    if header["junit_bytes"] != len(junit):
        problems.append("junit byte count does not match its content")
    if header["child_output_bytes"] < len(child):
        problems.append("child output byte count is smaller than the captured content")
    if not header["junit_present"] and junit:
        problems.append("junit content supplied although no junit file was reported present")
    if any(not p.startswith("decoy") for p in problems):
        return _refused(problems)
    return CollectedResult(
        authenticated=True, exit_code=header["exit_code"], signal=header["signal"],
        child_output=child, child_output_bytes=header["child_output_bytes"],
        child_output_sha256=header["child_output_sha256"],
        child_output_truncated=header["child_output_truncated"],
        junit_present=header["junit_present"], junit=junit, junit_sha256=header["junit_sha256"],
        junit_problem=header["junit_problem"], deadline_exceeded=header["deadline_exceeded"],
        problems=problems,
    )


def parse_probe_output(output: bytes) -> dict | None:
    """The isolation probe prints exactly one JSON object line; anything else is refused."""
    found = [line for line in bytes(output).split(b"\n") if line.startswith(PROBE_PREFIX)]
    if len(found) != 1:
        return None
    try:
        value = json.loads(found[0][len(PROBE_PREFIX):])
    except (ValueError, UnicodeDecodeError):
        return None
    return value if isinstance(value, dict) else None
