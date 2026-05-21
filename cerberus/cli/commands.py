from __future__ import annotations

import asyncio
import signal
from datetime import datetime, timezone
from pathlib import Path

from cerberus import __version__
from cerberus.collectors.proc import ProcCollector
from cerberus.core.config import CerberusConfig, load_config
from cerberus.core.db import EventStore
from cerberus.core.event import Event
from cerberus.core.event_bus import EventBus
from cerberus.core.logger import get_logger
from cerberus.reporting.markdown import MarkdownReportWriter

_log = get_logger("cerberus.cli")


def cmd_version() -> int:
    print(f"cerberus-local {__version__}")
    return 0


def cmd_status(cfg: CerberusConfig) -> int:
    store = EventStore(cfg.paths.events_db)
    store.init_schema()
    print(f"Host       : {cfg.host_name}")
    print(f"Mode       : {cfg.mode}")
    print(f"Events DB  : {cfg.paths.events_db}")
    print(f"Eventos    : {store.count()}")
    store.close()
    return 0


def cmd_start(cfg: CerberusConfig) -> int:
    if cfg.mode != "dry_run":
        # M1 sólo soporta dry_run; monitor/auto_* vienen en hitos posteriores
        _log.warning("mode_forced_dry_run", extra={"requested": cfg.mode})
    return asyncio.run(_run_loop(cfg))


async def _run_loop(cfg: CerberusConfig) -> int:
    store = EventStore(cfg.paths.events_db)
    store.init_schema()
    bus = EventBus()
    writer = MarkdownReportWriter(cfg.paths.reports_dir, host=cfg.host_name)

    collected: list[Event] = []

    async def persist_and_buffer(ev: Event) -> None:
        store.insert(ev)
        collected.append(ev)

    bus.subscribe(persist_and_buffer)
    bus.start()

    collector = ProcCollector(
        host=cfg.host_name,
        poll_interval_seconds=cfg.collectors.proc.poll_interval_seconds,
    )
    collector_task = asyncio.create_task(collector.start(bus), name="proc_collector")
    reporter_task = asyncio.create_task(
        _report_loop(writer, collected, cfg.reporting.interval_seconds),
        name="reporter",
    )

    stop_event = asyncio.Event()

    def _on_signal(*_a):
        stop_event.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _on_signal)
        except NotImplementedError:
            # Windows no soporta add_signal_handler para SIGTERM en algunos contextos
            signal.signal(sig, lambda *_: stop_event.set())

    _log.info("cerberus_started", extra={"host": cfg.host_name, "mode": cfg.mode})
    try:
        await stop_event.wait()
    finally:
        await collector.stop()
        collector_task.cancel()
        reporter_task.cancel()
        for t in (collector_task, reporter_task):
            try:
                await t
            except asyncio.CancelledError:
                pass
        await bus.stop()
        if collected:
            writer.write(collected, when=datetime.now(timezone.utc))
        store.close()
    return 0


async def _report_loop(writer: MarkdownReportWriter, buffer: list[Event], interval: int) -> None:
    while True:
        await asyncio.sleep(interval)
        snapshot = list(buffer)
        buffer.clear()
        writer.write(snapshot, when=datetime.now(timezone.utc))


def cmd_stop(cfg: CerberusConfig) -> int:
    # M1 corre en foreground; stop = matar el proceso. Se elaborará IPC en M4.
    print("M1 corre en foreground. Usa Ctrl+C para detener.")
    return 0


def resolve_config(path: Path | None) -> CerberusConfig:
    if path is None:
        path = Path(__file__).resolve().parent.parent.parent / "config" / "cerberus.default.yml"
    return load_config(path)
