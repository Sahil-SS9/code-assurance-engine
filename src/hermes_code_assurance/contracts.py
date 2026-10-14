"""CheckContract v1 — the immutable, reviewer-owned check contract.

The contract is frozen on construction; its identity is the sha256 of the canonical JSON of
every field except ``contract_id``. Model output may *propose* a contract; only the evaluator
constructs, freezes and stores it. Validation is deliberately stricter than the shape schema:
unknown fields, unsafe argv elements, slug violations and duplicate check ids are refused.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from .jsonio import canonical_json, sha256_hex

SCHEMA_NAME = "check-contract-v1"

_ORIGINS = {"review", "human", "model", "automation"}
_KINDS = {"collect-only", "test-run", "static-tool", "other"}
_PARSERS = {None, "junit-xml", "pytest-terminal"}
_PLATFORMS = {"linux", "macos", "windows"}

_CHECK_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
_SUGGESTED_TOP_KEYS = frozenset(
    {
        "schema", "goal", "assessed_areas", "required_checks", "optional_checks",
        "negative_checks", "env_allowlist", "network_enabled", "model_enabled",
        "supported_platforms", "timeouts", "proposed_by", "created_at", "contract_id",
    }
)
_SUGGESTED_CHECK_KEYS = frozenset(
    {
        "check_id", "label", "kind", "argv", "cwd", "parser_id", "expected_collection",
        "oracle", "executable",
    }
)


class ContractError(ValueError):
    """The data is not a valid CheckContract v1."""


def _err(msg: str):
    raise ContractError(msg)


def _clean_str(value: Any, what: str, *, lo: int = 1, hi: int = 512) -> str:
    if not isinstance(value, str) or value == "":
        _err(f"{what}: must be a non-empty string")
    value = value.strip()
    if not lo <= len(value) <= hi:
        _err(f"{what}: length must be {lo}..{hi}")
    if "\x00" in value or "\n" in value or "\r" in value:
        _err(f"{what}: contains NUL or newline")
    return value


@dataclass(frozen=True)
class CheckSpec:
    """One reviewed check inside a contract."""

    check_id: str
    label: str
    kind: str
    argv: tuple[str, ...]
    cwd: str
    parser_id: str | None
    expected_collection: tuple[int, ...] | None  # ("tests",) or None
    oracle_allowed_failures: int
    oracle_description: str | None
    executable: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "label": self.label,
            "kind": self.kind,
            "argv": list(self.argv),
            "cwd": self.cwd,
            "parser_id": self.parser_id,
            "expected_collection": (
                {"tests": self.expected_collection[0]}
                if self.expected_collection is not None
                else None
            ),
            "oracle": {
                "allowed_failures": self.oracle_allowed_failures,
                "description": self.oracle_description,
            },
            "executable": self.executable,
        }


@dataclass(frozen=True)
class CheckContract:
    schema: str
    goal: str
    assessed_areas: tuple[str, ...]
    required_checks: tuple[CheckSpec, ...]
    optional_checks: tuple[CheckSpec, ...]
    negative_checks: tuple[CheckSpec, ...]
    env_allowlist: tuple[str, ...]
    network_enabled: bool
    model_enabled: bool
    supported_platforms: tuple[str, ...]
    timeouts: tuple[int, int]
    proposed_by: str
    created_at: str | None
    contract_id: str = field(default="", compare=False, repr=False)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CheckContract:
        """Parse, validate, freeze. See :func:`parse_contract`."""
        return parse_contract(data)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "schema": self.schema,
            "goal": self.goal,
            "assessed_areas": list(self.assessed_areas),
            "required_checks": [c.to_dict() for c in self.required_checks],
            "optional_checks": [c.to_dict() for c in self.optional_checks],
            "negative_checks": [c.to_dict() for c in self.negative_checks],
            "env_allowlist": list(self.env_allowlist),
            "network_enabled": self.network_enabled,
            "model_enabled": self.model_enabled,
            "supported_platforms": list(self.supported_platforms),
            "timeouts": {"per_check_seconds": self.timeouts[0], "total_seconds": self.timeouts[1]},
            "proposed_by": self.proposed_by,
            "created_at": self.created_at,
        }
        if self.contract_id:
            out["contract_id"] = self.contract_id
        return out


def _parse_expected_collection(value: Any, what: str) -> tuple[int, ...] | None:
    if value is None:
        return None
    if not isinstance(value, dict) or "tests" not in value:
        _err(f"{what}: expected_collection must be null or an object with 'tests'")
    tests = value["tests"]
    if tests is None:
        return None
    if not isinstance(tests, int) or isinstance(tests, bool) or tests < 0:
        _err(f"{what}: expected_collection.tests must be null or a non-negative integer")
    return (tests,)


def _parse_oracle(value: Any, what: str) -> tuple[int, str | None]:
    if value is None:
        return 0, None
    if not isinstance(value, dict):
        _err(f"{what}: oracle must be an object")
    allowed = value.get("allowed_failures", 0)
    if not isinstance(allowed, int) or isinstance(allowed, bool) or allowed < 0:
        _err(f"{what}: oracle.allowed_failures must be a non-negative integer")
    desc = value.get("description")
    if desc is not None:
        desc = _clean_str(desc, f"{what}.oracle.description", hi=2000)
    return allowed, desc


def _parse_check(data: Any, what: str) -> CheckSpec:
    if not isinstance(data, dict):
        _err(f"{what}: must be an object")
    unknown = set(data) - _SUGGESTED_CHECK_KEYS
    if unknown:
        _err(f"{what}: unknown field(s): {sorted(unknown)}")
    check_id = _clean_str(data.get("check_id"), f"{what}.check_id", hi=64)
    if not _CHECK_ID_RE.fullmatch(check_id):
        _err(f"{what}.check_id: must match [a-z0-9][a-z0-9-]{{0,63}}")
    label = _clean_str(data.get("label"), f"{what}.label", hi=200)
    kind = data.get("kind")
    if kind not in _KINDS:
        _err(f"{what}.kind: must be one of {sorted(_KINDS)}")
    argv = data.get("argv")
    if not isinstance(argv, list) or not 1 <= len(argv) <= 64:
        _err(f"{what}.argv: must be a 1..64 element list")
    argv_clean: list[str] = []
    for i, element in enumerate(argv):
        argv_clean.append(_clean_str(element, f"{what}.argv[{i}]", hi=512))
    cwd = data.get("cwd", ".")
    cwd = _clean_str(cwd, f"{what}.cwd") if cwd != "." else "."
    parser_id = data.get("parser_id")
    if parser_id not in _PARSERS:
        _err(f"{what}.parser_id: must be null, 'junit-xml' or 'pytest-terminal'")
    expected = _parse_expected_collection(data.get("expected_collection"), what)
    allowed_failures, oracle_desc = _parse_oracle(data.get("oracle"), what)
    executable = data.get("executable")
    if executable is None:
        executable = kind != "collect-only"
    if not isinstance(executable, bool):
        _err(f"{what}.executable: must be a boolean")
    return CheckSpec(
        check_id=check_id,
        label=label,
        kind=kind,
        argv=tuple(argv_clean),
        cwd=cwd,
        parser_id=parser_id,
        expected_collection=expected,
        oracle_allowed_failures=allowed_failures,
        oracle_description=oracle_desc,
        executable=executable,
    )


def _parse_timeouts(value: Any) -> tuple[int, int]:
    if value is None:
        return 600, 1800
    if not isinstance(value, dict):
        _err("timeouts: must be an object")
    per = value.get("per_check_seconds")
    total = value.get("total_seconds")
    for name, v in (("per_check_seconds", per), ("total_seconds", total)):
        if not isinstance(v, int) or isinstance(v, bool) or v <= 0:
            _err(f"timeouts.{name}: must be a positive integer")
    if per > total:
        _err("timeouts: per_check_seconds must not exceed total_seconds")
    return per, total


def _id_of(payload: dict[str, Any]) -> str:
    body = {k: v for k, v in payload.items() if k != "contract_id"}
    return sha256_hex(canonical_json(body))


def parse_contract(data: Any) -> CheckContract:
    """Validate and freeze a CheckContract v1 (strict: unknown fields are refused)."""
    if not isinstance(data, dict):
        _err("contract must be a JSON object")
    unknown = set(data) - _SUGGESTED_TOP_KEYS
    if unknown:
        _err(f"unknown top-level field(s): {sorted(unknown)}")
    if data.get("schema") != SCHEMA_NAME:
        _err(f"schema: must be {SCHEMA_NAME!r}")
    goal = _clean_str(data.get("goal"), "goal", lo=4, hi=600)
    areas = data.get("assessed_areas")
    if not isinstance(areas, list) or not 1 <= len(areas) <= 200:
        _err("assessed_areas: must be a non-empty list (max 200)")
    areas_clean = tuple(
        _clean_str(area, f"assessed_areas[{i}]", hi=255) for i, area in enumerate(areas)
    )
    req_raw = data.get("required_checks")
    if not isinstance(req_raw, list) or not 1 <= len(req_raw) <= 64:
        _err("required_checks: must be a 1..64 element list")
    required = tuple(_parse_check(c, f"required_checks[{i}]") for i, c in enumerate(req_raw))
    optional = tuple(
        _parse_check(c, f"optional_checks[{i}]") for i, c in enumerate(data.get("optional_checks") or [])
    )
    negative = tuple(
        _parse_check(c, f"negative_checks[{i}]") for i, c in enumerate(data.get("negative_checks") or [])
    )
    ids = [c.check_id for c in (*required, *optional, *negative)]
    if len(ids) != len(set(ids)):
        _err("check_id values must be unique across required/optional/negative checks")

    allowlist = data.get("env_allowlist")
    if not isinstance(allowlist, list):
        _err("env_allowlist: must be a list")
    allow_clean = tuple(
        _clean_str(e, f"env_allowlist[{i}]", hi=128) for i, e in enumerate(allowlist)
    )
    for flag in ("network_enabled", "model_enabled"):
        if not isinstance(data.get(flag), bool):
            _err(f"{flag}: must be a boolean")
    platforms = data.get("supported_platforms")
    if not isinstance(platforms, list) or not platforms:
        _err("supported_platforms: must be a non-empty list")
    for p in platforms:
        if p not in _PLATFORMS:
            _err(f"supported_platforms: {p!r} not in {sorted(_PLATFORMS)}")
    proposed_by = data.get("proposed_by", "review")
    if proposed_by not in _ORIGINS:
        _err(f"proposed_by: must be one of {sorted(_ORIGINS)}")
    created_at = data.get("created_at")
    if created_at is not None:
        created_at = _clean_str(created_at, "created_at", hi=40)
    contract = CheckContract(
        schema=SCHEMA_NAME,
        goal=goal,
        assessed_areas=areas_clean,
        required_checks=required,
        optional_checks=optional,
        negative_checks=negative,
        env_allowlist=allow_clean,
        network_enabled=bool(data["network_enabled"]),
        model_enabled=bool(data["model_enabled"]),
        supported_platforms=tuple(platforms),
        timeouts=_parse_timeouts(data.get("timeouts")),
        proposed_by=proposed_by,
        created_at=created_at,
    )
    if "contract_id" in data and data["contract_id"] != _id_of(contract.to_dict()):
        _err("contract_id: does not match the canonical digest of the contract body")
    object.__setattr__(contract, "contract_id", _id_of(contract.to_dict()))
    return contract
