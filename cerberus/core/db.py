from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cerberus.core.event import Event

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id          TEXT PRIMARY KEY,
    timestamp   TEXT NOT NULL,
    source      TEXT NOT NULL,
    type        TEXT NOT NULL,
    host        TEXT NOT NULL,
    pid         INTEGER,
    user        TEXT,
    raw         TEXT NOT NULL,
    indicators  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_source ON events(source);
"""


class EventStore:
    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.path, isolation_level=None)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.row_factory = sqlite3.Row

    def init_schema(self) -> None:
        self._conn.executescript(_SCHEMA)

    def table_exists(self, name: str) -> bool:
        row = self._conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
            (name,),
        ).fetchone()
        return row is not None

    def insert(self, event: Event) -> None:
        self._conn.execute(
            """
            INSERT INTO events(id, timestamp, source, type, host, pid, user, raw, indicators)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event.id,
                event.timestamp.isoformat(),
                event.source,
                event.type,
                event.host,
                event.pid,
                event.user,
                json.dumps(event.raw),
                json.dumps(event.indicators),
            ),
        )

    def fetch_all(self) -> list[dict[str, Any]]:
        rows = self._conn.execute("SELECT * FROM events ORDER BY timestamp").fetchall()
        return [dict(r) for r in rows]

    def fetch_by_source(self, source: str) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT * FROM events WHERE source=? ORDER BY timestamp", (source,),
        ).fetchall()
        return [dict(r) for r in rows]

    def count(self) -> int:
        row = self._conn.execute("SELECT COUNT(*) AS n FROM events").fetchone()
        return int(row["n"])

    def purge_older_than(self, days: int) -> int:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        cur = self._conn.execute("DELETE FROM events WHERE timestamp < ?", (cutoff,))
        return cur.rowcount

    def close(self) -> None:
        self._conn.close()
