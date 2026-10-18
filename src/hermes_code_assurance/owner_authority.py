"""Owner-signed, one-use execution authority (C0.2 kernel).

What counts as owner authority here, and what does not
------------------------------------------------------
Authority is an Ed25519 signature, made by the owner OUTSIDE this process, over the exact bytes of
a request that spells out the one operation being approved (candidate, contract, check, oracle,
toolchain, collector, image, isolation policy, argv, limits, attempt, route, data root, expiry).
The public key that verifies it comes from a trust file the executing identity can neither write
nor own. Nothing else is authority: not a JSON ``approved: true``, not a model message, not a hash,
not a ``--approved`` flag, not a receipt field, not a caller-chosen state file.

This module only VERIFIES and RECORDS. It has no sign/approve/enrol operation: it never reads,
creates or stores a private key, and it never writes the trust file. A claim is durable and happens
before any execution, so an ambiguous attempt can never be replayed under the same grant.

Honest limits: a compromised executing account can delete the ledger (reopening replay until the
short expiry) and cannot be defended by this module; the guarantee boundary is stated in
docs/threat-model.md.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import sqlite3
import stat
import time
from collections.abc import Callable, Mapping
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from typing import NoReturn

from . import ed25519
from .jsonio import JSONIOError, canonical_json, load_json_bytes

REQUEST_SCHEMA = "code-assurance-owner-request-v1"
KEYS_SCHEMA = "code-assurance-owner-keys-v1"

MAX_REQUEST_BYTES = 65536
MAX_TRUST_BYTES = 65536
MAX_LIFETIME_SECONDS = 24 * 3600
CLOCK_SKEW_SECONDS = 60
MAX_ENROLLED_KEYS = 8

OPERATION_FIELDS: tuple[str, ...] = (
    "schema_version", "owner", "route", "data_root", "assessment_id", "attempt", "attempt_id",
    "check_id", "candidate_digest", "contract_id", "oracle_digest", "toolchain_digest",
    "collector_digest", "image", "isolation_policy_digest", "argv", "env_digest", "limits",
    "network",
)
_REQUEST_FIELDS = {"schema", "summary", "operation", "nonce", "issued_at", "expires_at", "max_uses"}

_OWNER_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")
_NONCE_RE = re.compile(r"^[A-Za-z0-9_-]{16,128}$")


class AuthorityDenied(PermissionError):
    """No authentic authority for the exact requested operation. ``reasons`` names every cause."""

    def __init__(self, reasons):
        reasons = [reasons] if isinstance(reasons, str) else [str(r) for r in reasons]
        super().__init__("; ".join(reasons))
        self.reasons = reasons


def _deny(*reasons: str) -> NoReturn:
    raise AuthorityDenied(list(reasons))


# --------------------------------------------------------------------------------- identity


@dataclass(frozen=True)
class EffectiveIdentity:
    """Who is executing. ``can_write(path)`` is the kernel's answer for that identity."""

    uid: int
    can_write: Callable[[str], bool]

    @classmethod
    def current(cls) -> EffectiveIdentity:
        return cls(uid=os.geteuid(), can_write=lambda path: os.access(path, os.W_OK, effective_ids=True))


@dataclass(frozen=True)
class EnrolledKey:
    owner: str
    public_key: bytes
    key_id: str  # sha256 of the raw 32-byte public key


# --------------------------------------------------------------------------------- trust root


def _parse_keys(data) -> dict[str, EnrolledKey]:
    problems: list[str] = []
    if not isinstance(data, dict):
        _deny("trust file must be a JSON object")
    unknown = sorted(set(data) - {"schema", "keys"})
    if unknown:
        problems.append(f"unknown field(s) in trust file: {unknown}")
    if data.get("schema") != KEYS_SCHEMA:
        problems.append(f"trust file schema must be {KEYS_SCHEMA!r}")
    entries = data.get("keys")
    if not isinstance(entries, list) or not 1 <= len(entries) <= MAX_ENROLLED_KEYS:
        problems.append(f"trust file needs at least one key and at most {MAX_ENROLLED_KEYS}")
        entries = []
    keys: dict[str, EnrolledKey] = {}
    for index, entry in enumerate(entries):
        label = f"keys[{index}]"
        if not isinstance(entry, dict) or set(entry) != {"owner", "public_key_b64", "key_id"}:
            problems.append(f"{label}: unknown or missing field(s)")
            continue
        owner = entry["owner"]
        if not isinstance(owner, str) or not _OWNER_RE.fullmatch(owner):
            problems.append(f"{label}: owner must match {_OWNER_RE.pattern}")
            continue
        try:
            raw = base64.b64decode(str(entry["public_key_b64"]), validate=True)
        except (binascii.Error, ValueError):
            problems.append(f"{label}: public_key_b64 is not valid base64")
            continue
        if len(raw) != 32:
            problems.append(f"{label}: an Ed25519 public key is exactly 32 bytes")
            continue
        if entry["key_id"] != hashlib.sha256(raw).hexdigest():
            problems.append(f"{label}: key_id does not match the public key")
            continue
        if owner in keys:
            problems.append(f"{label}: duplicate owner {owner!r}")
            continue
        keys[owner] = EnrolledKey(owner=owner, public_key=raw, key_id=entry["key_id"])
    if problems:
        raise AuthorityDenied(problems)
    return keys


def _read_trust_bytes(path: Path) -> bytes:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as exc:
        _deny(f"trust file cannot be opened: {exc.strerror or exc}")
    with os.fdopen(fd, "rb") as stream:
        raw = stream.read(MAX_TRUST_BYTES + 1)
    if len(raw) > MAX_TRUST_BYTES:
        _deny("trust file is larger than the allowed size")
    return raw


def _load_keys(path: Path) -> dict[str, EnrolledKey]:
    try:
        data = load_json_bytes(_read_trust_bytes(path), max_bytes=MAX_TRUST_BYTES)
    except JSONIOError as exc:
        raise AuthorityDenied([f"trust file is not strict JSON: {exc}"]) from exc
    return _parse_keys(data)


def _assert_owner_controlled(path: Path, identity: EffectiveIdentity) -> None:
    """The trust file must be something the executing identity cannot rewrite.

    Otherwise the executor could enrol its own key and sign its own approvals."""
    reasons: list[str] = []
    absolute = Path(os.path.abspath(path))
    if os.path.realpath(absolute) != str(absolute):
        _deny("trust file path involves a symlink; refusing an indirect trust location")
    try:
        info = os.lstat(absolute)
    except OSError as exc:
        _deny(f"trust file is not readable: {exc.strerror or exc}")
    if not stat.S_ISREG(info.st_mode):
        reasons.append("trust file is not a regular file")
    if info.st_uid == identity.uid:
        reasons.append("trust file is owned by the executing identity: it is controlled by the "
                       "executing identity, so it cannot be an owner trust root")
    if identity.can_write(str(absolute)):
        reasons.append("trust file is writable by the executing identity: it is controlled by the "
                       "executing identity, so it cannot be an owner trust root")
    if stat.S_IMODE(info.st_mode) & 0o022:
        reasons.append("trust file is group- or world-writable")
    directory = absolute.parent
    dir_info = os.lstat(directory)
    if stat.S_IMODE(dir_info.st_mode) & 0o022 and not dir_info.st_mode & stat.S_ISVTX:
        reasons.append("trust directory is group- or world-writable")
    for ancestor in [directory, *directory.parents]:
        try:
            ancestor_info = os.lstat(ancestor)
        except OSError:
            continue
        if ancestor_info.st_uid == identity.uid:
            reasons.append(f"{ancestor} is owned by the executing identity: it is controlled by "
                           "the executing identity")
            break
        if identity.can_write(str(ancestor)):
            reasons.append(f"{ancestor} is writable by the executing identity: it is controlled "
                           "by the executing identity")
            break
    if reasons:
        raise AuthorityDenied(reasons)


class TrustRoot:
    """Enrolled owner public keys plus the class of authority they can confer."""

    def __init__(self, keys: Mapping[str, EnrolledKey], authority_class: str, source: str):
        self.keys = dict(keys)
        self.authority_class = authority_class
        self.source = source

    @classmethod
    def load_owner(cls, path, identity: EffectiveIdentity | None = None) -> TrustRoot:
        """The ONLY way to obtain class 'owner': the file must be foreign-controlled."""
        identity = identity or EffectiveIdentity.current()
        path = Path(path)
        _assert_owner_controlled(path, identity)
        return cls(_load_keys(path), "owner", str(path))

    @classmethod
    def load_fixture(cls, path) -> TrustRoot:
        """Test-only trust root (class 'fixture'): proves mechanics, never an owner, never clears
        public verification."""
        return cls(_load_keys(Path(path)), "fixture", str(path))

    def key_for(self, owner: str) -> EnrolledKey | None:
        return self.keys.get(owner)


# --------------------------------------------------------------------------------- requests


@dataclass(frozen=True)
class Authorization:
    owner: str
    key_id: str
    authority_class: str  # 'owner' | 'fixture'
    nonce: str
    request_sha256: str
    issued_at: int
    expires_at: int
    operation: dict


def build_request_bytes(operation: dict, *, nonce: str, issued_at: int, expires_at: int,
                        summary: str) -> bytes:
    """The exact bytes the owner reads and signs. Deterministic and human-readable."""
    body = {
        "schema": REQUEST_SCHEMA, "summary": summary, "operation": operation, "nonce": nonce,
        "issued_at": issued_at, "expires_at": expires_at, "max_uses": 1,
    }
    return (json.dumps(body, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode()


def _decode_signature(signature) -> bytes | None:
    if isinstance(signature, (bytes, bytearray)) and len(signature) == 64:
        return bytes(signature)
    if isinstance(signature, (bytes, bytearray)):
        try:
            signature = bytes(signature).decode("ascii")
        except UnicodeDecodeError:
            return None
    if isinstance(signature, str):
        try:
            raw = base64.b64decode("".join(signature.split()), validate=True)
        except (binascii.Error, ValueError):
            return None
        return raw if len(raw) == 64 else None
    return None


def _is_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _structure_problems(body) -> list[str]:
    if not isinstance(body, dict):
        return ["request must be a JSON object"]
    problems: list[str] = []
    unknown = sorted(set(body) - _REQUEST_FIELDS)
    missing = sorted(_REQUEST_FIELDS - set(body))
    if unknown:
        problems.append(f"unknown request field(s): {unknown}")
    if missing:
        problems.append(f"missing request field(s): {missing}")
    if body.get("schema") != REQUEST_SCHEMA:
        problems.append(f"request schema must be {REQUEST_SCHEMA!r}")
    if not _is_int(body.get("max_uses")) or body.get("max_uses") != 1:
        problems.append("max_uses must be the integer 1 (one-use grants only)")
    nonce = body.get("nonce")
    if not isinstance(nonce, str) or not _NONCE_RE.fullmatch(nonce):
        problems.append(f"nonce must match {_NONCE_RE.pattern}")
    for name in ("issued_at", "expires_at"):
        if not _is_int(body.get(name)):
            problems.append(f"{name} must be an integer epoch-seconds value")
    if not isinstance(body.get("summary"), str):
        problems.append("summary must be a string")
    operation = body.get("operation")
    if not isinstance(operation, dict) or set(operation) != set(OPERATION_FIELDS):
        have = set(operation) if isinstance(operation, dict) else set()
        problems.append(
            "operation fields differ from the schema "
            f"(missing: {sorted(set(OPERATION_FIELDS) - have)}, "
            f"unexpected: {sorted(have - set(OPERATION_FIELDS))})"
        )
    return problems


class OwnerAuthority:
    """Verifies an owner-signed request against the exact run about to happen. Writes nothing."""

    def __init__(self, trust: TrustRoot, ledger: AuthorityLedger | None = None, *,
                 clock: Callable[[], float] = time.time):
        self.trust = trust
        self.ledger = ledger
        self.clock = clock

    def evaluate(self, request_bytes: bytes, signature, expected_operation: dict) -> Authorization:
        reasons: list[str] = []
        now = self.clock()
        if not isinstance(request_bytes, (bytes, bytearray)) or not request_bytes:
            _deny("no signed request supplied")
        request_bytes = bytes(request_bytes)
        if len(request_bytes) > MAX_REQUEST_BYTES:
            _deny("signed request is larger than the allowed size")
        raw_signature = _decode_signature(signature)
        if raw_signature is None:
            reasons.append("signature is missing or malformed (expected 64 bytes or their base64)")
        try:
            body = load_json_bytes(request_bytes, max_bytes=MAX_REQUEST_BYTES)
        except JSONIOError as exc:
            raise AuthorityDenied(reasons + [f"request is not strict JSON: {exc}"]) from exc
        problems = _structure_problems(body)
        reasons.extend(problems)
        if not isinstance(body, dict):
            raise AuthorityDenied(reasons)

        operation = body.get("operation") if isinstance(body.get("operation"), dict) else {}
        owner = operation.get("owner")
        key = self.trust.key_for(owner) if isinstance(owner, str) else None
        if key is None:
            reasons.append(f"owner {owner!r} is not enrolled in the trust root")
        elif raw_signature is not None and not ed25519.verify(
            key.public_key, request_bytes, raw_signature
        ):
            reasons.append("signature does not verify under the enrolled key for this owner")

        if not problems:
            issued, expires = body["issued_at"], body["expires_at"]
            if expires <= now:
                reasons.append(f"request expired at {expires}")
            if issued > now + CLOCK_SKEW_SECONDS:
                reasons.append("request was issued in the future")
            if expires - issued > MAX_LIFETIME_SECONDS:
                reasons.append(f"request lifetime exceeds the {MAX_LIFETIME_SECONDS}s maximum")
            if self.ledger is not None and self.ledger.is_claimed(body["nonce"]):
                reasons.append("grant already consumed (replay refused)")
            for name in OPERATION_FIELDS:
                if canonical_json(operation.get(name)) != canonical_json(
                    expected_operation.get(name)
                ):
                    reasons.append(f"operation.{name} does not match the run being authorised")
        if reasons or key is None:
            raise AuthorityDenied(reasons or ["authority could not be established"])
        return Authorization(
            owner=key.owner, key_id=key.key_id, authority_class=self.trust.authority_class,
            nonce=body["nonce"], request_sha256=hashlib.sha256(request_bytes).hexdigest(),
            issued_at=body["issued_at"], expires_at=body["expires_at"], operation=dict(operation),
        )


# --------------------------------------------------------------------------------- ledger

_LEDGER_SCHEMA = """
CREATE TABLE IF NOT EXISTS claims (
    nonce TEXT PRIMARY KEY,
    owner TEXT NOT NULL,
    key_id TEXT NOT NULL,
    authority_class TEXT NOT NULL,
    request_sha256 TEXT NOT NULL,
    assessment_id TEXT NOT NULL,
    attempt_id TEXT NOT NULL,
    operation TEXT NOT NULL,
    claimed_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS executions (
    receipt_id TEXT PRIMARY KEY,
    nonce TEXT NOT NULL REFERENCES claims(nonce),
    assessment_id TEXT NOT NULL,
    attempt_id TEXT NOT NULL,
    check_id TEXT NOT NULL,
    collector TEXT NOT NULL,
    attestation_sha256 TEXT NOT NULL,
    launch_digest TEXT NOT NULL,
    container_id TEXT NOT NULL,
    recorded_at REAL NOT NULL
);
"""
_EXECUTION_FIELDS = (
    "receipt_id", "nonce", "assessment_id", "attempt_id", "check_id", "collector",
    "attestation_sha256", "launch_digest", "container_id",
)


class AuthorityLedger:
    """Durable one-use claims and execution provenance, private to the executing user and never
    mounted into any sandbox. Trust for a receipt comes from a row here, never from the receipt."""

    def __init__(self, path):
        self.path = Path(path)

    # -- opening ------------------------------------------------------------------------
    @classmethod
    def open_existing(cls, path):
        """A read handle if a ledger file already exists; never creates anything."""
        candidate = Path(path)
        if candidate.is_symlink() or not candidate.is_file():
            return None
        return cls(candidate)

    def ensure(self) -> None:
        """Create (or validate) the private ledger. Refuses unsafe directories and files."""
        directory = self.path.parent
        if directory.is_symlink():
            _deny("ledger directory is a symlink")
        if not directory.exists():
            os.makedirs(directory, mode=0o700, exist_ok=True)
        info = os.lstat(directory)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) & 0o077):
            _deny("ledger directory must be a private (0700) directory owned by the executing user")
        try:
            fd = os.open(self.path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        except OSError as exc:
            _deny(f"ledger file cannot be opened safely: {exc.strerror or exc}")
        try:
            file_info = os.fstat(fd)
            if (not stat.S_ISREG(file_info.st_mode) or file_info.st_nlink != 1
                    or file_info.st_uid != os.geteuid() or stat.S_IMODE(file_info.st_mode) & 0o077):
                _deny("ledger file must be a private regular file owned by the executing user")
        finally:
            os.close(fd)
        with closing(self._connect()) as conn:
            conn.executescript(_LEDGER_SCHEMA)

    def _connect(self, *, read_only: bool = False) -> sqlite3.Connection:
        if read_only:
            conn = sqlite3.connect(f"file:{self.path}?mode=ro", uri=True, timeout=30)
        else:
            conn = sqlite3.connect(str(self.path), timeout=30, isolation_level=None)
            conn.execute("PRAGMA synchronous=FULL")
        conn.row_factory = sqlite3.Row
        return conn

    # -- reads (never create, never write) ------------------------------------------------
    def _read(self, sql: str, params: tuple = ()):
        if not self.path.is_file():
            return []
        try:
            with closing(self._connect(read_only=True)) as conn:
                return conn.execute(sql, params).fetchall()
        except sqlite3.OperationalError:
            return []  # not initialised: no claims exist

    def is_claimed(self, nonce: str) -> bool:
        return bool(self._read("SELECT 1 FROM claims WHERE nonce = ?", (nonce,)))

    def attempt_count(self, assessment_id: str) -> int:
        rows = self._read("SELECT COUNT(*) AS n FROM claims WHERE assessment_id = ?", (assessment_id,))
        return int(rows[0]["n"]) if rows else 0

    def provenance(self, receipt_id: str) -> dict | None:
        rows = self._read(
            "SELECT e.receipt_id, e.nonce, e.assessment_id, e.attempt_id, e.check_id, e.collector, "
            "e.attestation_sha256, e.launch_digest, e.container_id, e.recorded_at, "
            "c.owner, c.key_id, c.authority_class, c.request_sha256 "
            "FROM executions e JOIN claims c ON c.nonce = e.nonce WHERE e.receipt_id = ?",
            (receipt_id,),
        )
        return dict(rows[0]) if rows else None

    # -- writes ---------------------------------------------------------------------------
    def claim(self, authorization: Authorization, *, now: float | None = None) -> None:
        """Consume the grant. Durable before any execution; exactly one claimant can win."""
        now = time.time() if now is None else now
        operation = authorization.operation
        with closing(self._connect()) as conn:
            try:
                conn.execute("BEGIN IMMEDIATE")
                conn.execute(
                    "INSERT INTO claims (nonce, owner, key_id, authority_class, request_sha256, "
                    "assessment_id, attempt_id, operation, claimed_at) VALUES (?,?,?,?,?,?,?,?,?)",
                    (authorization.nonce, authorization.owner, authorization.key_id,
                     authorization.authority_class, authorization.request_sha256,
                     str(operation.get("assessment_id")), str(operation.get("attempt_id")),
                     canonical_json(operation).decode(), now),
                )
                conn.execute("COMMIT")
            except sqlite3.IntegrityError:
                conn.execute("ROLLBACK")
                _deny("grant already consumed (replay refused)")
            except BaseException:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise

    def record_execution(self, **fields) -> None:
        """Bind a receipt to the claim that authorised it. ``now`` may be supplied for tests."""
        now = fields.pop("now", None)
        now = time.time() if now is None else now
        if set(fields) != set(_EXECUTION_FIELDS):
            _deny(f"execution record needs exactly the fields {sorted(_EXECUTION_FIELDS)}")
        with closing(self._connect()) as conn:
            try:
                conn.execute("BEGIN IMMEDIATE")
                if conn.execute("SELECT 1 FROM claims WHERE nonce = ?", (fields["nonce"],)).fetchone() is None:
                    conn.execute("ROLLBACK")
                    _deny("no claim exists for this execution; refusing to record unauthorised work")
                conn.execute(
                    "INSERT INTO executions (receipt_id, nonce, assessment_id, attempt_id, check_id, "
                    "collector, attestation_sha256, launch_digest, container_id, recorded_at) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (*(fields[name] for name in _EXECUTION_FIELDS), now),
                )
                conn.execute("COMMIT")
            except sqlite3.IntegrityError:
                conn.execute("ROLLBACK")
                _deny("an execution is already recorded for this receipt")
            except AuthorityDenied:
                raise
            except BaseException:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise
