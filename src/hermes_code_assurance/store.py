"""Durable assessment storage: SQLite (WAL) + cross-process writer fencing.

Contract: one writer per assessment; CAS-guarded state transitions recording an event row;
scrub-before-persist at the write boundary (privacy.scrub_record); no module-level process state
so two stores on two paths can never share data; duplicate creates are refused, never overwrite.
"""

from __future__ import annotations

import errno
import fcntl
import json
import sqlite3
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from .jsonio import load_json_bytes
from .privacy import scrub_record
from .state import require_transition

_SCHEMA_V1 = (
    """
    CREATE TABLE IF NOT EXISTS schema_version (
        version INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS assessments (
        id TEXT PRIMARY KEY,
        state TEXT NOT NULL,
        payload TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS receipts (
        assessment_id TEXT NOT NULL REFERENCES assessments(id),
        receipt_id TEXT PRIMARY KEY,
        payload TEXT NOT NULL,
        created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        assessment_id TEXT NOT NULL REFERENCES assessments(id),
        kind TEXT NOT NULL,
        detail TEXT NOT NULL,
        at TEXT NOT NULL
    );
    """
)


def _utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


class StoreLocked(RuntimeError):
    """Another process holds the writer fence for this store path."""


class StoreStateConflict(RuntimeError):
    """The stored state differs from the caller's expected (CAS) state."""


class AssessmentStore:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.lock_path = self.path.with_suffix(self.path.suffix + ".lock")
        self._fence_depth = 0
        self._fence_conn: sqlite3.Connection | None = None

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.path), timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=30000")
        return conn

    def initialize(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.executescript(_SCHEMA_V1)
            row = conn.execute("SELECT version FROM schema_version").fetchone()
            if row is None:
                conn.execute("INSERT INTO schema_version (version) VALUES (1)")
            elif row["version"] != 1:
                raise RuntimeError(f"unsupported store schema version: {row['version']}")

    @contextmanager
    def transaction(self, timeout: float = 5.0):
        """Cross-process writer fence via flock, then an IMMEDIATE write transaction.

        Nesting is supported on the SAME store instance using SQLite SAVEPOINTs on the shared
        connection (SQLite has exactly one writer — a second BEGIN on a new connection would
        deadlock). timeout <= 0: non-blocking, StoreLocked immediately when fenced elsewhere.
        timeout > 0: retry until deadline, then StoreLocked.
        """
        if self._fence_depth:
            conn = self._fence_conn
            sp = f"sp{self._fence_depth}"
            self._fence_depth += 1
            conn.execute(f"SAVEPOINT {sp}")  # type: ignore[union-attr]
            try:
                yield conn
            except BaseException:
                conn.execute(f"ROLLBACK TO {sp}")  # type: ignore[union-attr]
                conn.execute(f"RELEASE {sp}")  # type: ignore[union-attr]
                raise
            else:
                conn.execute(f"RELEASE {sp}")  # type: ignore[union-attr]
            finally:
                self._fence_depth -= 1
            return

        import time as _time

        deadline = _time.monotonic() + max(0.0, timeout)
        fd = self.lock_path.open("w")
        if timeout <= 0:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                fd.close()
                if exc.errno in (errno.EWOULDBLOCK, errno.EAGAIN):
                    raise StoreLocked(f"writer fence held elsewhere: {self.lock_path}")
                raise
        else:
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except OSError as exc:
                    fd.close()
                    if exc.errno not in (errno.EWOULDBLOCK, errno.EAGAIN):
                        raise
                    if _time.monotonic() >= deadline:
                        raise StoreLocked(f"writer fence busy past deadline: {self.lock_path}")
                    fd = self.lock_path.open("w")
                    _time.sleep(0.05)

        conn = self._connect()
        self._fence_depth = 1
        self._fence_conn = conn
        try:
            conn.execute("BEGIN IMMEDIATE")
            yield conn
            conn.commit()
        except BaseException:
            conn.rollback()
            raise
        finally:
            conn.close()
            self._fence_depth = 0
            self._fence_conn = None
            fcntl.flock(fd, fcntl.LOCK_UN)
            fd.close()

    def _event(self, conn, assessment_id: str, kind: str, detail: dict) -> None:
        conn.execute(
            "INSERT INTO events (assessment_id, kind, detail, at) VALUES (?, ?, ?, ?)",
            (assessment_id, kind, json.dumps(scrub_record(detail)), _utc_now()),
        )

    def create_assessment(self, assessment_id: str, state: str, payload: dict) -> bool:
        """Idempotent create: a second create of the same id is REFUSED (returns False)."""
        body = json.dumps(scrub_record(payload))
        with self.transaction() as conn:
            exists = conn.execute(
                "SELECT 1 FROM assessments WHERE id = ?", (assessment_id,)
            ).fetchone()
            if exists:
                return False
            now = _utc_now()
            conn.execute(
                "INSERT INTO assessments (id, state, payload, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (assessment_id, state, body, now, now),
            )
            self._event(conn, assessment_id, "created", {"state": state})
        return True

    def get_assessment(self, assessment_id: str) -> dict | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT id, state, payload, created_at, updated_at FROM assessments WHERE id = ?",
                (assessment_id,),
            ).fetchone()
        if row is None:
            return None
        return {
            "id": row["id"],
            "state": row["state"],
            "payload": load_json_bytes(row["payload"]),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def set_state(self, assessment_id: str, new_state: str, old_state: str | None = None) -> None:
        with self.transaction() as conn:
            row = conn.execute(
                "SELECT state FROM assessments WHERE id = ?", (assessment_id,)
            ).fetchone()
            if row is None:
                raise KeyError(f"unknown assessment: {assessment_id}")
            stored_state = row["state"]
            if old_state is not None and stored_state != old_state:
                raise StoreStateConflict(
                    f"expected state {old_state!r}, store has {stored_state!r}"
                )
            require_transition(stored_state, new_state)
            conn.execute(
                "UPDATE assessments SET state = ?, updated_at = ? WHERE id = ?",
                (new_state, _utc_now(), assessment_id),
            )
            self._event(
                conn, assessment_id, "state-change", {"from": stored_state, "to": new_state}
            )

    def append_receipt(self, assessment_id: str, payload: dict) -> str:
        receipt_id = str(payload.get("receipt_id") or "")
        if not receipt_id:
            raise ValueError("append_receipt requires a receipt_id in the payload")
        body = json.dumps(scrub_record(payload))
        with self.transaction() as conn:
            exists = conn.execute(
                "SELECT 1 FROM assessments WHERE id = ?", (assessment_id,)
            ).fetchone()
            if not exists:
                raise KeyError(f"unknown assessment: {assessment_id}")
            dup = conn.execute(
                "SELECT 1 FROM receipts WHERE receipt_id = ?", (receipt_id,)
            ).fetchone()
            if dup:
                raise StoreStateConflict(f"receipt already stored: {receipt_id}")
            conn.execute(
                "INSERT INTO receipts (assessment_id, receipt_id, payload, created_at) "
                "VALUES (?, ?, ?, ?)",
                (assessment_id, receipt_id, body, _utc_now()),
            )
            self._event(
                conn, assessment_id, "receipt", {"receipt_id": receipt_id}
            )
        return receipt_id

    def receipts(self, assessment_id: str) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT receipt_id, payload, created_at FROM receipts "
                "WHERE assessment_id = ? ORDER BY created_at, receipt_id",
                (assessment_id,),
            ).fetchall()
        return [
            {
                "receipt_id": r["receipt_id"],
                "payload": load_json_bytes(r["payload"]),
                "created_at": r["created_at"],
            }
            for r in rows
        ]

    def events(self, assessment_id: str) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT kind, detail, at FROM events WHERE assessment_id = ? ORDER BY id",
                (assessment_id,),
            ).fetchall()
        return [
            {"kind": r["kind"], "detail": load_json_bytes(r["detail"]), "at": r["at"]}
            for r in rows
        ]
