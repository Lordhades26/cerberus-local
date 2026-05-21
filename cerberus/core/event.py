from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import IntEnum
from typing import Any, Literal

SourceType = Literal["proc", "net", "fs", "evt"]
_VALID_SOURCES = {"proc", "net", "fs", "evt"}


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass(frozen=True)
class Event:
    """Evento normalizado emitido por cualquier collector."""

    source: SourceType
    type: str
    host: str
    pid: int | None
    user: str | None
    raw: dict[str, Any]
    indicators: dict[str, Any]
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self) -> None:
        if self.source not in _VALID_SOURCES:
            raise ValueError(
                f"Invalid source {self.source!r}; must be one of {sorted(_VALID_SOURCES)}"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "source": self.source,
            "type": self.type,
            "host": self.host,
            "pid": self.pid,
            "user": self.user,
            "raw": self.raw,
            "indicators": self.indicators,
        }
