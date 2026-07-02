"""Generador de carga con trabajo REAL sobre el pipeline de CERBERUS.

Ejercita los componentes reales (EventBus -> Correlator -> RuleEngine ->
DetectionPipeline -> ResponseEngine en dry_run) con SQLite real. NO ejecuta
acciones del SO (dry_run solo construye/registra). Usado por los tests de carga
y por scripts/loadtest.py.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path

from cerberus.core.db import EventStore
from cerberus.core.event import Event
from cerberus.core.event_bus import EventBus
from cerberus.core.finding import Finding
from cerberus.detection.correlator import Correlator
from cerberus.detection.finding_store import FindingStore
from cerberus.detection.pipeline import DetectionPipeline
from cerberus.detection.rule_engine import RuleEngine
from cerberus.response.action_store import ActionStore
from cerberus.response.engine import ResponseEngine
from cerberus.response.executor import SystemExecutor
from cerberus.response.policy_engine import PolicyEngine
from cerberus.response.rate_limiter import RateLimiter

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent


@dataclass(frozen=True)
class LoadResult:
    events: int
    findings: int
    actions_logged: int
    elapsed_s: float
    events_per_s: float


def _make_events(pid: int, host: str) -> list[Event]:
    """3 eventos multi-fuente para un mismo pid (dispara correlación + reglas)."""
    return [
        Event(source="fs", type="mass_rename", host=host, pid=pid, user="u",
              raw={}, indicators={"rename_count": 30}),
        Event(source="proc", type="new_process", host=host, pid=pid, user="u",
              raw={}, indicators={"cmdline": "powershell -enc AAAA",
                                  "exe": f"C:\\\\tmp\\\\p{pid}.exe"}),
        Event(source="net", type="outbound_conn", host=host, pid=pid, user="u",
              raw={}, indicators={"remote_ip": "9.9.9.9"}),
    ]


async def run_load(work_dir: Path, n_pids: int, mode: str = "dry_run") -> LoadResult:
    """Corre la carga: n_pids procesos sintéticos (3 eventos c/u) por el pipeline real."""
    events_db = work_dir / "events.db"
    findings_db = work_dir / "findings.db"
    actions_db = work_dir / "actions.db"

    store = EventStore(events_db)
    store.init_schema()
    fstore = FindingStore(findings_db)
    fstore.init_schema()
    astore = ActionStore(actions_db)
    astore.init_schema()

    rule_engine = RuleEngine(_REPO_ROOT / "rules")
    rule_engine.load()
    pipeline = DetectionPipeline(rule_engine, ai_analyst=None, ai_enabled=False)

    policy_engine = PolicyEngine(_REPO_ROOT / "policies")
    policy_engine.load()
    response = ResponseEngine(
        policy_engine=policy_engine,
        executor=SystemExecutor(quarantine_dir=work_dir / "q"),
        action_store=astore,
        rate_limiter=RateLimiter(max_actions_per_minute=10_000, max_isolate_per_hour=10_000),
        mode=mode,
        killswitch_path=work_dir / "KILLSWITCH",
        auto_critical_categories=frozenset({"mass_rename", "ransomware", "c2", "data_exfil"}),
    )

    findings_count = 0

    async def on_finding(f: Finding) -> None:
        nonlocal findings_count
        enriched = await pipeline.process(f)
        fstore.insert(enriched)
        await response.handle(enriched)
        findings_count += 1

    bus = EventBus(maxsize=100_000)
    bus.subscribe(store.insert)
    correlator = Correlator(window_seconds=3600, min_sources_for_finding=2,
                            on_finding=on_finding)
    correlator.attach(bus)
    bus.start()

    start = time.perf_counter()
    total_events = 0
    for pid in range(1, n_pids + 1):
        for ev in _make_events(pid, host="LOADHOST"):
            await bus.publish(ev)
            total_events += 1
    await bus.drain()
    await correlator.flush()
    await correlator.join()   # esperar el manejo de todos los hallazgos promovidos
    await bus.stop()
    elapsed = time.perf_counter() - start

    actions_logged = len(astore.fetch_recent(limit=10_000_000))
    store.close()
    fstore.close()
    astore.close()

    return LoadResult(
        events=total_events,
        findings=findings_count,
        actions_logged=actions_logged,
        elapsed_s=round(elapsed, 4),
        events_per_s=round(total_events / elapsed, 1) if elapsed else 0.0,
    )
