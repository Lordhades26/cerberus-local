import asyncio
from pathlib import Path
from unittest.mock import patch

import pytest

from cerberus.collectors.proc import ProcCollector
from cerberus.core.db import EventStore
from cerberus.core.event import Event
from cerberus.core.event_bus import EventBus
from cerberus.reporting.markdown import MarkdownReportWriter


class _FakeProc:
    def __init__(self, pid: int, name: str) -> None:
        self.pid = pid
        self.info = {
            "pid": pid, "name": name, "cmdline": [name],
            "username": "u", "create_time": 1.0, "exe": f"C:\\{name}",
        }


@pytest.mark.asyncio
async def test_m1_pipeline_persists_and_reports(tmp_path: Path) -> None:
    db_path = tmp_path / "events.db"
    reports = tmp_path / "reports"

    bus = EventBus()
    store = EventStore(db_path)
    store.init_schema()
    writer = MarkdownReportWriter(reports, host="H")

    collected: list[Event] = []

    async def sink(ev: Event) -> None:
        store.insert(ev)
        collected.append(ev)

    bus.subscribe(sink)
    bus.start()

    procs_seq = iter([
        [_FakeProc(100, "explorer.exe")],
        [_FakeProc(100, "explorer.exe"), _FakeProc(200, "notepad.exe")],
        [_FakeProc(100, "explorer.exe")],
    ])

    def fake_iter(attrs: object) -> list[_FakeProc]:
        try:
            return next(procs_seq)
        except StopIteration:
            return [_FakeProc(100, "explorer.exe")]

    collector = ProcCollector(host="H", poll_interval_seconds=0.05)
    with patch("cerberus.collectors.proc.psutil.process_iter", side_effect=fake_iter):
        task = asyncio.create_task(collector.start(bus))
        await asyncio.sleep(0.4)
        await collector.stop()
        try:
            await task
        except asyncio.CancelledError:
            pass

    await bus.stop()

    rows = store.fetch_all()
    types_db = {r["type"] for r in rows}
    assert "new_process" in types_db
    assert "process_exit" in types_db
    assert store.count() == len(collected)
    store.close()

    report_path = writer.write(collected)
    text = report_path.read_text(encoding="utf-8")
    assert "## proc" in text
    assert "new_process" in text
