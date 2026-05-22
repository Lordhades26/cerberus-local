from __future__ import annotations

import asyncio
import signal
from datetime import UTC, datetime
from pathlib import Path

from cerberus import __version__
from cerberus.ai.ollama_client import OllamaClient
from cerberus.collectors.base import Collector
from cerberus.collectors.evt import EvtCollector
from cerberus.collectors.fs import FsCollector
from cerberus.collectors.net import NetCollector
from cerberus.collectors.proc import ProcCollector
from cerberus.core.config import CerberusConfig, load_config
from cerberus.core.db import EventStore
from cerberus.core.event import Event
from cerberus.core.event_bus import EventBus
from cerberus.core.finding import Finding
from cerberus.core.logger import get_logger
from cerberus.detection.ai_analyst import AIAnalyst
from cerberus.detection.correlator import Correlator
from cerberus.detection.finding_store import FindingStore
from cerberus.detection.pipeline import DetectionPipeline
from cerberus.detection.rule_engine import RuleEngine
from cerberus.reporting.markdown import MarkdownReportWriter
from cerberus.response.action_store import ActionStore
from cerberus.response.actions import ActionReport
from cerberus.response.engine import ResponseEngine
from cerberus.response.executor import SystemExecutor
from cerberus.response.policy_engine import PolicyEngine
from cerberus.response.rate_limiter import RateLimiter

_log = get_logger("cerberus.cli")


def cmd_version() -> int:
    print(f"cerberus-local {__version__}")
    return 0


def cmd_status(cfg: CerberusConfig) -> int:
    store = EventStore(cfg.paths.events_db)
    store.init_schema()
    fstore = FindingStore(cfg.paths.findings_db)
    fstore.init_schema()
    print(f"Host        : {cfg.host_name}")
    print(f"Mode        : {cfg.mode}")
    print(f"Events DB   : {cfg.paths.events_db}")
    print(f"Findings DB : {cfg.paths.findings_db}")
    astore = ActionStore(cfg.paths.actions_db)
    astore.init_schema()
    print(f"Eventos     : {store.count()}")
    print(f"Findings    : {fstore.count()}")
    print(f"Acciones    : {len(astore.fetch_recent(limit=100000))}")
    astore.close()
    print("Collectors  : "
          f"proc={cfg.collectors.proc.enabled} "
          f"net={cfg.collectors.net.enabled} "
          f"fs={cfg.collectors.fs.enabled} "
          f"evt={cfg.collectors.evt.enabled}")
    store.close()
    fstore.close()
    return 0


def cmd_start(cfg: CerberusConfig) -> int:
    if cfg.mode != "dry_run":
        _log.warning("mode_forced_dry_run", extra={"requested": cfg.mode})
    return asyncio.run(_run_loop(cfg))


def _build_collectors(cfg: CerberusConfig) -> list[Collector]:
    collectors: list[Collector] = []
    if cfg.collectors.proc.enabled:
        collectors.append(ProcCollector(
            host=cfg.host_name,
            poll_interval_seconds=cfg.collectors.proc.poll_interval_seconds,
        ))
    if cfg.collectors.net.enabled:
        collectors.append(NetCollector(
            host=cfg.host_name,
            poll_interval_seconds=cfg.collectors.net.poll_interval_seconds,
            beaconing_window_seconds=cfg.collectors.net.beaconing_window_seconds,
            beaconing_min_connections=cfg.collectors.net.beaconing_min_connections,
        ))
    if cfg.collectors.fs.enabled:
        collectors.append(FsCollector(
            host=cfg.host_name,
            watch_paths=cfg.collectors.fs.watch_paths,
            mass_rename_threshold=cfg.collectors.fs.mass_rename_threshold,
            mass_rename_window_seconds=cfg.collectors.fs.mass_rename_window_seconds,
            high_entropy_threshold=cfg.collectors.fs.high_entropy_threshold,
        ))
    if cfg.collectors.evt.enabled:
        collectors.append(EvtCollector(
            host=cfg.host_name,
            channels=cfg.collectors.evt.channels,
        ))
    return collectors


def _build_pipeline(cfg: CerberusConfig) -> DetectionPipeline:
    repo_root = Path(__file__).resolve().parent.parent.parent
    rules_dir = cfg.detection.rule_engine.rules_dir
    if not rules_dir.is_absolute():
        rules_dir = repo_root / rules_dir
    rule_engine = RuleEngine(rules_dir)
    if cfg.detection.rule_engine.enabled:
        n = rule_engine.load()
        _log.info("rules_loaded", extra={"count": n})

    ai_analyst: AIAnalyst | None = None
    ai_enabled = cfg.detection.ai_analyst.enabled
    if ai_enabled:
        template_path = repo_root / "prompts" / "triage.md"
        template = template_path.read_text(encoding="utf-8")
        client = OllamaClient(
            base_url=cfg.detection.ai_analyst.base_url,
            timeout_seconds=cfg.detection.ai_analyst.timeout_seconds,
        )
        ai_analyst = AIAnalyst(
            client,
            model=cfg.detection.ai_analyst.model,
            prompt_template=template,
            max_severity_delta=cfg.detection.ai_analyst.max_severity_delta,
        )
    return DetectionPipeline(rule_engine, ai_analyst=ai_analyst, ai_enabled=ai_enabled)


def _build_response_engine(cfg: CerberusConfig, action_store: ActionStore) -> ResponseEngine | None:
    if not cfg.response.enabled:
        return None
    repo_root = Path(__file__).resolve().parent.parent.parent
    policies_dir = cfg.response.policies_dir
    if not policies_dir.is_absolute():
        policies_dir = repo_root / policies_dir
    policy_engine = PolicyEngine(policies_dir)
    n = policy_engine.load()
    _log.info("policies_loaded", extra={"count": n})
    return ResponseEngine(
        policy_engine=policy_engine,
        executor=SystemExecutor(quarantine_dir=cfg.paths.quarantine_dir),
        action_store=action_store,
        rate_limiter=RateLimiter(
            max_actions_per_minute=cfg.response.rate.max_actions_per_minute,
            max_isolate_per_hour=cfg.response.rate.max_isolate_per_hour,
        ),
        mode=cfg.mode,
        killswitch_path=cfg.paths.killswitch_path,
        auto_critical_categories=cfg.response.auto_critical_categories,
    )


async def _run_loop(cfg: CerberusConfig) -> int:
    store = EventStore(cfg.paths.events_db)
    store.init_schema()
    fstore = FindingStore(cfg.paths.findings_db)
    fstore.init_schema()
    astore = ActionStore(cfg.paths.actions_db)
    astore.init_schema()
    bus = EventBus()
    writer = MarkdownReportWriter(cfg.paths.reports_dir, host=cfg.host_name)

    collected_events: list[Event] = []
    collected_findings: list[Finding] = []
    collected_action_reports: list[ActionReport] = []

    async def persist_event(ev: Event) -> None:
        store.insert(ev)
        collected_events.append(ev)

    pipeline = _build_pipeline(cfg)
    response_engine = _build_response_engine(cfg, astore)

    async def on_finding(f: Finding) -> None:
        enriched = await pipeline.process(f)
        fstore.insert(enriched)
        collected_findings.append(enriched)
        if response_engine is not None:
            report = await response_engine.handle(enriched)
            collected_action_reports.append(report)

    bus.subscribe(persist_event)
    correlator = Correlator(
        window_seconds=cfg.correlator.window_seconds,
        min_sources_for_finding=cfg.correlator.min_sources_for_finding,
        on_finding=on_finding,
    )
    correlator.attach(bus)
    bus.start()
    correlator_task = asyncio.create_task(correlator.run(), name="correlator")

    collectors = _build_collectors(cfg)
    collector_tasks = [
        asyncio.create_task(c.start(bus), name=f"collector_{c.name}")
        for c in collectors
    ]
    reporter_task = asyncio.create_task(
        _report_loop(writer, collected_events, collected_findings,
                     collected_action_reports, cfg.reporting.interval_seconds),
        name="reporter",
    )

    stop_event = asyncio.Event()

    def _on_signal(*_a: object) -> None:
        stop_event.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _on_signal)
        except NotImplementedError:
            signal.signal(sig, lambda *_: stop_event.set())

    _log.info("cerberus_started",
              extra={"host": cfg.host_name, "mode": cfg.mode,
                     "collectors": [c.name for c in collectors]})
    try:
        await stop_event.wait()
    finally:
        for c in collectors:
            await c.stop()
        await correlator.stop()
        # drenar eventos pendientes y promover findings finales antes de cerrar
        await bus.drain()
        await correlator.flush()
        for t in (*collector_tasks, correlator_task, reporter_task):
            t.cancel()
        for t in (*collector_tasks, correlator_task, reporter_task):
            try:
                await t
            except asyncio.CancelledError:
                pass
        await bus.stop()
        if collected_events or collected_findings or collected_action_reports:
            writer.write(collected_events, when=datetime.now(UTC),
                         findings=collected_findings,
                         action_reports=collected_action_reports)
        store.close()
        fstore.close()
        astore.close()
    return 0


async def _report_loop(
    writer: MarkdownReportWriter,
    events: list[Event],
    findings: list[Finding],
    action_reports: list[ActionReport],
    interval: int,
) -> None:
    while True:
        await asyncio.sleep(interval)
        ev_snapshot = list(events)
        fn_snapshot = list(findings)
        ar_snapshot = list(action_reports)
        events.clear()
        findings.clear()
        action_reports.clear()
        writer.write(ev_snapshot, when=datetime.now(UTC), findings=fn_snapshot,
                     action_reports=ar_snapshot)


def cmd_stop(cfg: CerberusConfig) -> int:
    print("M2 corre en foreground. Usa Ctrl+C para detener.")
    return 0


def resolve_config(path: Path | None) -> CerberusConfig:
    if path is None:
        path = Path(__file__).resolve().parent.parent.parent / "config" / "cerberus.default.yml"
    return load_config(path)
