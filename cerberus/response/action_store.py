from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cerberus.response.actions import ActionResult

_SCHEMA = """
CREATE TABLE IF NOT EXISTS actions_log (
    id                TEXT PRIMARY KEY,
    timestamp         TEXT NOT NULL,
    finding_id        TEXT NOT NULL,
    policy_id         TEXT NOT NULL,
    action_type       TEXT NOT NULL,
    params            TEXT NOT NULL,
    executed          INTEGER NOT NULL,
    success           INTEGER NOT NULL,
    command           TEXT NOT NULL,
    reverted_command  TEXT,
    reason            TEXT NOT NULL,
    mode              TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_actions_timestamp ON actions_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_actions_finding ON actions_log(finding_id);
"""


class ActionStore:
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
            "SELECT name FROM sqlite_master WHERE type='table' AND name=?", (name,),
        ).fetchone()
        return row is not None

    def insert(self, result: ActionResult, finding_id: str, policy_id: str, mode: str) -> str:
        d = result.to_dict()
        action_id = str(uuid.uuid4())
        self._conn.execute(
            """
            INSERT INTO actions_log(
                id, timestamp, finding_id, policy_id, action_type, params,
                executed, success, command, reverted_command, reason, mode
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                action_id,
                datetime.now(UTC).isoformat(),
                finding_id,
                policy_id,
                d["action_type"],
                json.dumps(d["params"]),
                1 if d["executed"] else 0,
                1 if d["success"] else 0,
                d["command"],
                d["reverted_command"],
                d["reason"],
                mode,
            ),
        )
        return action_id

    def _row_to_dict(self, row: Any) -> dict[str, Any]:
        d = dict(row)
        d["params"] = json.loads(d["params"])
        return d

    def fetch_by_id(self, action_id: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT * FROM actions_log WHERE id=?", (action_id,),
        ).fetchone()
        return self._row_to_dict(row) if row is not None else None

    def fetch_recent(self, limit: int = 50) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT * FROM actions_log ORDER BY timestamp DESC LIMIT ?", (limit,),
        ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def close(self) -> None:
        self._conn.close()
