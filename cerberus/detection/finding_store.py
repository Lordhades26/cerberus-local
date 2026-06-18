from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from cerberus.core.event import Severity
from cerberus.core.finding import Finding

_SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    id                TEXT PRIMARY KEY,
    timestamp         TEXT NOT NULL,
    host              TEXT NOT NULL,
    pid               INTEGER,
    user              TEXT,
    severity          INTEGER NOT NULL,
    severity_base     INTEGER NOT NULL,
    sources           TEXT NOT NULL,
    categories        TEXT NOT NULL,
    primary_event_id  TEXT NOT NULL,
    rule_ids          TEXT NOT NULL,
    rule_categories   TEXT NOT NULL DEFAULT '[]',
    ai_triage         TEXT,
    evidence          TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_timestamp ON findings(timestamp);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
"""


class FindingStore:
    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.path, isolation_level=None, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._conn.row_factory = sqlite3.Row

    def init_schema(self) -> None:
        self._conn.executescript(_SCHEMA)
        # Migración rápida por si la tabla ya existe sin la columna
        try:
            self._conn.execute("ALTER TABLE findings ADD COLUMN rule_categories TEXT NOT NULL DEFAULT '[]'")
        except sqlite3.OperationalError:
            pass # Ya existe

    def table_exists(self, name: str) -> bool:
        row = self._conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
            (name,),
        ).fetchone()
        return row is not None

    def insert(self, finding: Finding) -> None:
        d = finding.to_dict()
        ai_triage = json.dumps(d["ai_triage"]) if d["ai_triage"] is not None else None
        self._conn.execute(
            """
            INSERT INTO findings(
                id, timestamp, host, pid, user, severity, severity_base,
                sources, categories, primary_event_id, rule_ids, rule_categories,
                ai_triage, evidence
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                d["id"],
                d["timestamp"],
                d["host"],
                d["pid"],
                d["user"],
                d["severity"],
                d["severity_base"],
                json.dumps(d["sources"]),
                json.dumps(d["categories"]),
                d["primary_event_id"],
                json.dumps(d["rule_ids"]),
                json.dumps(d.get("rule_categories", [])),
                ai_triage,
                json.dumps(d["evidence"]),
            ),
        )

    def _row_to_dict(self, row: Any) -> dict[str, Any]:
        d = dict(row)
        d["sources"] = json.loads(d["sources"])
        d["categories"] = json.loads(d["categories"])
        d["rule_ids"] = json.loads(d["rule_ids"])
        d["rule_categories"] = json.loads(d.get("rule_categories", "[]"))
        d["ai_triage"] = json.loads(d["ai_triage"]) if d["ai_triage"] is not None else None
        d["evidence"] = json.loads(d["evidence"])
        return d

    def fetch_all(self) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT * FROM findings ORDER BY timestamp"
        ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def fetch_by_min_severity(self, severity: Severity) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT * FROM findings WHERE severity >= ? ORDER BY timestamp",
            (int(severity),),
        ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def count(self) -> int:
        row = self._conn.execute("SELECT COUNT(*) AS n FROM findings").fetchone()
        return int(row["n"])

    def purge_older_than(self, days: int) -> int:
        cutoff = (datetime.now(UTC) - timedelta(days=days)).isoformat()
        cur = self._conn.execute(
            "DELETE FROM findings WHERE timestamp < ?", (cutoff,)
        )
        return cur.rowcount

    def close(self) -> None:
        self._conn.close()
