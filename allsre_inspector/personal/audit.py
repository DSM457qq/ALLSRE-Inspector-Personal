from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Any
import sqlite3


class PersonalAuditStore:
    """Small SQLite command audit for the personal Inspector."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = Lock()
        with self._connect() as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS command_audits ("
                "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                "command_hash TEXT NOT NULL,"
                "command_summary TEXT NOT NULL,"
                "classification TEXT NOT NULL,"
                "status TEXT NOT NULL,"
                "exit_code INTEGER,"
                "duration_ms INTEGER,"
                "created_at TEXT NOT NULL"
                ")"
            )

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        return db

    def create(self, values: dict[str, Any]) -> int:
        with self._lock, self._connect() as db:
            cursor = db.execute(
                "INSERT INTO command_audits(command_hash, command_summary, classification, "
                "status, created_at) VALUES (?, ?, ?, ?, ?)",
                (
                    values["command_hash"], values["command_summary"],
                    values["classification"], "STARTED",
                    datetime.now(timezone.utc).isoformat(timespec="seconds"),
                ),
            )
            return int(cursor.lastrowid)

    def finish(self, audit_id: int, *, status: str, exit_code: int | None = None,
               duration_ms: int | None = None) -> None:
        with self._lock, self._connect() as db:
            db.execute(
                "UPDATE command_audits SET status=?, exit_code=?, duration_ms=? WHERE id=?",
                (status, exit_code, duration_ms, audit_id),
            )

    def list(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock, self._connect() as db:
            rows = db.execute(
                "SELECT * FROM command_audits ORDER BY id DESC LIMIT ?",
                (max(1, min(int(limit), 500)),),
            ).fetchall()
        return [dict(row) for row in rows]
