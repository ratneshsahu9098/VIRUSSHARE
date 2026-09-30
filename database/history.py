"""virusShare - SQLite transfer history.

One row per finished transfer session.  The database lives at
``%APPDATA%\\virusShare\\history.db`` (see ``core.constants.get_history_db_path``)
and is safe to access from worker threads: a single connection guarded by an
RLock, with WAL not required (short, serialized transactions).
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from core.constants import get_history_db_path
from models import TransferSession

log = logging.getLogger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS history (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id       TEXT NOT NULL,
    direction        TEXT NOT NULL,
    peer_id          TEXT NOT NULL,
    peer_name        TEXT NOT NULL,
    files_json       TEXT NOT NULL,
    total_size       INTEGER NOT NULL DEFAULT 0,
    transferred_size INTEGER NOT NULL DEFAULT 0,
    status           TEXT NOT NULL,
    error            TEXT NOT NULL DEFAULT '',
    started_at       TEXT,
    finished_at      TEXT
);
CREATE INDEX IF NOT EXISTS idx_history_started ON history (started_at DESC);
CREATE INDEX IF NOT EXISTS idx_history_peer ON history (peer_id);
"""

_MAX_PRUNE_BATCH = 5000

MAX_HISTORY_ENTRIES = 5000


@dataclass
class HistoryEntry:
    """One row of the transfer history."""

    id: int = 0
    session_id: str = ""
    direction: str = "send"
    peer_id: str = ""
    peer_name: str = ""
    files: List[Dict[str, Any]] = field(default_factory=list)
    total_size: int = 0
    transferred_size: int = 0
    status: str = "completed"
    error: str = ""
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None

    @classmethod
    def from_session(cls, session: TransferSession) -> "HistoryEntry":
        return cls(
            session_id=session.id,
            direction=session.direction,
            peer_id=session.computer_id,
            peer_name=session.computer_name,
            files=[
                {
                    "name": f.name,
                    "path": f.path,
                    "size": f.size,
                    "checksum": f.checksum,
                }
                for f in session.files
            ],
            total_size=session.total_size,
            transferred_size=session.transferred_size,
            status=session.status.value,
            error=session.error_message,
            started_at=session.start_time,
            finished_at=session.end_time,
        )

    @property
    def file_count(self) -> int:
        return len(self.files)

    @property
    def success(self) -> bool:
        return self.status == "completed"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "session_id": self.session_id,
            "direction": self.direction,
            "peer_id": self.peer_id,
            "peer_name": self.peer_name,
            "files": list(self.files),
            "total_size": self.total_size,
            "transferred_size": self.transferred_size,
            "status": self.status,
            "error": self.error,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "finished_at": (
                self.finished_at.isoformat() if self.finished_at else None
            ),
        }


class HistoryDB:
    """Append/query transfer history.  Usable as a context manager."""

    def __init__(
        self,
        path: Optional[Path] = None,
        *,
        max_entries: int = MAX_HISTORY_ENTRIES,
    ) -> None:
        self.path = Path(path) if path is not None else get_history_db_path()
        self.max_entries = int(max_entries)
        self._lock = threading.RLock()
        self._conn: Optional[sqlite3.Connection] = None
        self._connect()

    # ------------------------------------------------------------------ #
    # connection lifecycle
    # ------------------------------------------------------------------ #

    def _connect(self) -> None:
        with self._lock:
            if self._conn is not None:
                return
            if self.path.parent and str(self.path.parent) not in ("", "."):
                self.path.parent.mkdir(parents=True, exist_ok=True)
            try:
                conn = self._open()
            except sqlite3.DatabaseError:
                self._quarantine_corrupt()
                conn = self._open()
            self._conn = conn
            try:
                self.prune(self.max_entries)
            except sqlite3.Error:
                log.exception("history prune on open failed")
            log.debug("history db opened: %s", self.path)

    def _open(self) -> sqlite3.Connection:
        conn = sqlite3.connect(
            str(self.path), check_same_thread=False, timeout=15.0
        )
        try:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.executescript(_SCHEMA)
            conn.commit()
        except BaseException:
            conn.close()
            raise
        return conn

    def _quarantine_corrupt(self) -> None:
        """Move an unreadable history.db aside and start fresh (M26).

        Mirrors TrustStore's corruption handling: the broken file is kept
        for inspection under a ``.corrupt-<timestamp>`` name so a bad disk
        or partial write can never brick startup.
        """
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
        backup = self.path.with_name(f"{self.path.name}.corrupt-{stamp}")
        try:
            self.path.replace(backup)
            for suffix in ("-wal", "-shm"):
                sidecar = self.path.with_name(self.path.name + suffix)
                try:
                    sidecar.unlink()
                except FileNotFoundError:
                    pass
                except OSError:
                    log.exception(
                        "could not remove corrupt history sidecar %s", sidecar
                    )
            log.error("history db corrupt; quarantined to %s", backup)
        except OSError:
            log.exception("history db corrupt and could not be quarantined")

    def close(self) -> None:
        with self._lock:
            if self._conn is None:
                return
            conn, self._conn = self._conn, None
            try:
                conn.commit()
            except Exception:  # noqa: BLE001 - a failed flush must not leak
                log.exception("history commit on close failed")
            finally:
                conn.close()

    def __enter__(self) -> "HistoryDB":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def _require(self) -> sqlite3.Connection:
        if self._conn is None:
            raise RuntimeError("history database is closed")
        return self._conn

    # ------------------------------------------------------------------ #
    # writes
    # ------------------------------------------------------------------ #

    def record(self, session: TransferSession) -> int:
        """Insert one finished session; returns the row id."""
        entry = HistoryEntry.from_session(session)
        with self._lock:
            conn = self._require()
            cur = conn.execute(
                """
                INSERT INTO history (
                    session_id, direction, peer_id, peer_name, files_json,
                    total_size, transferred_size, status, error,
                    started_at, finished_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    entry.session_id,
                    entry.direction,
                    entry.peer_id,
                    entry.peer_name,
                    json.dumps(entry.files, ensure_ascii=False),
                    entry.total_size,
                    entry.transferred_size,
                    entry.status,
                    entry.error,
                    entry.started_at.isoformat() if entry.started_at else None,
                    entry.finished_at.isoformat() if entry.finished_at else None,
                ),
            )
            conn.commit()
            self.prune(self.max_entries)
            return int(cur.lastrowid or 0)

    def record_entry(self, entry: HistoryEntry) -> int:
        """Insert a pre-built entry (rarely needed; kept for symmetry)."""
        with self._lock:
            conn = self._require()
            cur = conn.execute(
                """
                INSERT INTO history (
                    session_id, direction, peer_id, peer_name, files_json,
                    total_size, transferred_size, status, error,
                    started_at, finished_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    entry.session_id,
                    entry.direction,
                    entry.peer_id,
                    entry.peer_name,
                    json.dumps(entry.files, ensure_ascii=False),
                    entry.total_size,
                    entry.transferred_size,
                    entry.status,
                    entry.error,
                    entry.started_at.isoformat() if entry.started_at else None,
                    entry.finished_at.isoformat() if entry.finished_at else None,
                ),
            )
            conn.commit()
            self.prune(self.max_entries)
            return int(cur.lastrowid or 0)

    # ------------------------------------------------------------------ #
    # reads
    # ------------------------------------------------------------------ #

    def recent(
        self,
        limit: int = 50,
        *,
        direction: Optional[str] = None,
        peer_id: Optional[str] = None,
    ) -> List[HistoryEntry]:
        """Newest-first page of history, optionally filtered."""
        limit = max(1, int(limit))
        sql = "SELECT * FROM history"
        clauses: List[str] = []
        params: List[Any] = []
        if direction is not None:
            clauses.append("direction = ?")
            params.append(direction)
        if peer_id is not None:
            clauses.append("peer_id = ?")
            params.append(peer_id)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(limit)

        with self._lock:
            rows = self._require().execute(sql, params).fetchall()
        return [_row_to_entry(r) for r in rows]

    def get(self, history_id: int) -> Optional[HistoryEntry]:
        with self._lock:
            row = self._require().execute(
                "SELECT * FROM history WHERE id = ?", (int(history_id),)
            ).fetchone()
        return _row_to_entry(row) if row else None

    def count(self) -> int:
        with self._lock:
            row = self._require().execute("SELECT COUNT(*) AS n FROM history").fetchone()
        return int(row["n"])

    def search(self, query: str, limit: int = 50) -> List[HistoryEntry]:
        """Case-insensitive substring match on peer name or file name."""
        pattern = f"%{query}%"
        with self._lock:
            rows = self._require().execute(
                """
                SELECT * FROM history
                WHERE peer_name LIKE ? COLLATE NOCASE
                   OR files_json LIKE ? COLLATE NOCASE
                ORDER BY id DESC LIMIT ?
                """,
                (pattern, pattern, max(1, int(limit))),
            ).fetchall()
        return [_row_to_entry(r) for r in rows]

    # ------------------------------------------------------------------ #
    # maintenance
    # ------------------------------------------------------------------ #

    def clear(self) -> int:
        with self._lock:
            conn = self._require()
            cur = conn.execute("DELETE FROM history")
            conn.commit()
            return cur.rowcount

    def prune(self, max_entries: int) -> int:
        """Keep only the newest ``max_entries`` rows; returns rows removed."""
        max_entries = max(0, int(max_entries))
        with self._lock:
            conn = self._require()
            cur = conn.execute(
                """
                DELETE FROM history WHERE id NOT IN (
                    SELECT id FROM history ORDER BY id DESC LIMIT ?
                )
                """,
                (max_entries,),
            )
            conn.commit()
            return cur.rowcount


def _row_to_entry(row: sqlite3.Row) -> HistoryEntry:
    try:
        files = json.loads(row["files_json"] or "[]")
        if not isinstance(files, list):
            files = []
    except (ValueError, TypeError):
        files = []
    return HistoryEntry(
        id=int(row["id"]),
        session_id=row["session_id"] or "",
        direction=row["direction"] or "send",
        peer_id=row["peer_id"] or "",
        peer_name=row["peer_name"] or "",
        files=files,
        total_size=int(row["total_size"] or 0),
        transferred_size=int(row["transferred_size"] or 0),
        status=row["status"] or "completed",
        error=row["error"] or "",
        started_at=_parse_ts(row["started_at"]),
        finished_at=_parse_ts(row["finished_at"]),
    )


def _parse_ts(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None
