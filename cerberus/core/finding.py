from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from cerberus.core.event import Event, Severity


@dataclass(frozen=True)
class Finding:
    """Cluster de eventos correlacionados promovido por el Correlator.

    En M2 la severidad es siempre MEDIUM (base heurística). En M3 el RuleEngine
    ajustará `severity` según reglas Sigma-like y el AIAnalyst la afinará ±1 nivel.
    """

    host: str
    pid: int | None
    user: str | None
    evidence: tuple[Event, ...]
    severity: Severity = Severity.MEDIUM
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))

    @classmethod
    def from_cluster(
        cls,
        host: str,
        pid: int | None,
        user: str | None,
        evidence: list[Event],
        severity: Severity = Severity.MEDIUM,
    ) -> Finding:
        if not evidence:
            raise ValueError("Finding requires at least one evidence event")
        return cls(
            host=host,
            pid=pid,
            user=user,
            evidence=tuple(evidence),
            severity=severity,
        )

    @property
    def sources(self) -> set[str]:
        return {ev.source for ev in self.evidence}

    @property
    def categories(self) -> set[str]:
        return {ev.type for ev in self.evidence}

    @property
    def primary_event_id(self) -> str:
        return self.evidence[0].id

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "host": self.host,
            "pid": self.pid,
            "user": self.user,
            "severity": int(self.severity),
            "sources": sorted(self.sources),
            "categories": sorted(self.categories),
            "primary_event_id": self.primary_event_id,
            "evidence": [ev.to_dict() for ev in self.evidence],
        }
