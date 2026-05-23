from __future__ import annotations

from collections import Counter
from datetime import datetime
from typing import Any

from cerberus import __version__
from cerberus.core.config import CerberusConfig
from cerberus.core.db import EventStore
from cerberus.core.event import Severity
from cerberus.core.runtime_state import RuntimeState
from cerberus.detection.finding_store import FindingStore
from cerberus.response.action_store import ActionStore

_SEV_NAMES = {s.value: s.name for s in Severity}


def _hour_bucket(iso_ts: str) -> str:
    try:
        return datetime.fromisoformat(iso_ts).strftime("%Y-%m-%dT%H:00")
    except ValueError:
        return "unknown"


class DashboardData:
    """Capa de datos read-only del dashboard: lee los SQLite stores + estado del agente.

    Pura respecto al transporte (sin HTTP): cada método devuelve dicts JSON-serializables.
    Abre las conexiones por llamada (seguro entre hilos del servidor HTTP).
    """

    def __init__(self, cfg: CerberusConfig) -> None:
        self._cfg = cfg
        # Inicializa el schema UNA sola vez (DDL = escritura). Las lecturas por
        # request abren sin init_schema, así varios hilos del dashboard concurren
        # solo como lectores (WAL) en vez de competir por un lock de escritura DDL
        # ("database is locked").
        for store in (
            EventStore(self._cfg.paths.events_db),
            FindingStore(self._cfg.paths.findings_db),
            ActionStore(self._cfg.paths.actions_db),
        ):
            store.init_schema()
            store.close()

    # ---- helpers de apertura (solo conexión; el schema ya existe) ----
    def _events(self) -> EventStore:
        return EventStore(self._cfg.paths.events_db)

    def _findings(self) -> FindingStore:
        return FindingStore(self._cfg.paths.findings_db)

    def _actions(self) -> ActionStore:
        return ActionStore(self._cfg.paths.actions_db)

    # ---- endpoints ----
    def status(self) -> dict[str, Any]:
        c = self._cfg.collectors
        mode = RuntimeState(self._cfg.paths.state_file).get_mode(default=self._cfg.mode)
        return {
            "version": __version__,
            "host": self._cfg.host_name,
            "mode": mode,
            "killswitch_active": self._cfg.paths.killswitch_path.exists(),
            "integrity_enabled": self._cfg.integrity.enabled,
            "response_enabled": self._cfg.response.enabled,
            "collectors": {
                "proc": c.proc.enabled,
                "net": c.net.enabled,
                "fs": c.fs.enabled,
                "evt": c.evt.enabled,
            },
        }

    def summary(self) -> dict[str, Any]:
        ev = self._events()
        fs = self._findings()
        ac = self._actions()
        try:
            findings = fs.fetch_all()
            actions = ac.fetch_recent(limit=100000)
            by_sev: Counter[str] = Counter(
                _SEV_NAMES.get(int(f["severity"]), "INFO") for f in findings
            )
            executed = sum(1 for a in actions if a["executed"])
            mode = RuntimeState(self._cfg.paths.state_file).get_mode(default=self._cfg.mode)
            return {
                "events_total": ev.count(),
                "findings_total": len(findings),
                "findings_by_severity": dict(by_sev),
                "actions_total": len(actions),
                "actions_executed": executed,
                "mode": mode,
                "killswitch_active": self._cfg.paths.killswitch_path.exists(),
            }
        finally:
            ev.close()
            fs.close()
            ac.close()

    def findings(self, limit: int = 10) -> list[dict[str, Any]]:
        fs = self._findings()
        try:
            rows = fs.fetch_all()
        finally:
            fs.close()
        rows.sort(key=lambda r: r["timestamp"], reverse=True)
        out: list[dict[str, Any]] = []
        for r in rows[:limit]:
            triage = r.get("ai_triage") or {}
            out.append({
                "id": r["id"],
                "timestamp": r["timestamp"],
                "pid": r["pid"],
                "severity": _SEV_NAMES.get(int(r["severity"]), "INFO"),
                "severity_base": _SEV_NAMES.get(int(r["severity_base"]), "INFO"),
                "rule_ids": r.get("rule_ids", []),
                "sources": r.get("sources", []),
                "ai_family": triage.get("family_guess"),
                "ai_confidence": triage.get("confidence"),
            })
        return out

    def events(self, hours: int = 12) -> dict[str, Any]:
        ev = self._events()
        try:
            rows = ev.fetch_all()
        finally:
            ev.close()
        by_source: Counter[str] = Counter(r["source"] for r in rows)
        by_type: Counter[str] = Counter(r["type"] for r in rows)
        timeline: Counter[str] = Counter(_hour_bucket(r["timestamp"]) for r in rows)
        ordered = sorted(timeline.items())[-hours:]
        return {
            "by_source": dict(by_source),
            "by_type": dict(by_type.most_common(10)),
            "timeline": [{"bucket": b, "count": n} for b, n in ordered],
        }

    def actions(self, limit: int = 10) -> list[dict[str, Any]]:
        ac = self._actions()
        try:
            rows = ac.fetch_recent(limit=limit)
        finally:
            ac.close()
        return [
            {
                "id": r["id"],
                "timestamp": r["timestamp"],
                "action_type": r["action_type"],
                "executed": bool(r["executed"]),
                "success": bool(r["success"]),
                "reason": r["reason"],
                "finding_id": r["finding_id"],
                "policy_id": r["policy_id"],
                "mode": r["mode"],
            }
            for r in rows
        ]

    def metrics(self) -> dict[str, Any]:
        fs = self._findings()
        ac = self._actions()
        try:
            findings = fs.fetch_all()
            actions = ac.fetch_recent(limit=100000)
        finally:
            fs.close()
            ac.close()
        distinct_rules = {rid for f in findings for rid in f.get("rule_ids", [])}
        executed = sum(1 for a in actions if a["executed"])
        total_actions = len(actions)
        auto_pct = round(100.0 * executed / total_actions, 1) if total_actions else 0.0
        ai_count = sum(1 for f in findings if f.get("ai_triage"))
        return {
            "findings_total": len(findings),
            "distinct_rules": len(distinct_rules),
            "actions_total": total_actions,
            "auto_executed_pct": auto_pct,
            "findings_with_ai": ai_count,
        }
