import asyncio
from unittest.mock import patch

import pytest

from cerberus.collectors.proc import ProcCollector
from cerberus.core.event import Event
from cerberus.core.event_bus import EventBus


class _FakeProc:
    def __init__(self, pid, name, cmdline, username, create_time):
        self.pid = pid
        self.info = {
            "pid": pid,
            "name": name,
            "cmdline": cmdline,
            "username": username,
            "create_time": create_time,
            "exe": f"C:\\\\Windows\\\\{name}",
        }


async def _collect_events(bus: EventBus, target_count: int, timeout: float = 2.0) -> list[Event]:
    received: list[Event] = []
    done = asyncio.Event()

    async def handler(ev: Event) -> None:
        received.append(ev)
        if len(received) >= target_count:
            done.set()

    bus.subscribe(handler)
    bus.start()
    try:
        await asyncio.wait_for(done.wait(), timeout=timeout)
    except asyncio.TimeoutError:
        pass
    await bus.stop()
    return received


@pytest.mark.asyncio
async def test_proc_collector_emits_new_process_events():
    fake_procs_before = [_FakeProc(100, "explorer.exe", ["explorer.exe"], "u", 1000.0)]
    fake_procs_after = fake_procs_before + [
        _FakeProc(200, "notepad.exe", ["notepad.exe", "a.txt"], "u", 2000.0),
    ]
    iterations = iter([fake_procs_before, fake_procs_after])

    def fake_iter(attrs):
        return next(iterations)

    bus = EventBus()
    collector = ProcCollector(host="H", poll_interval_seconds=0.05)
    with patch("cerberus.collectors.proc.psutil.process_iter", side_effect=fake_iter):
        task = asyncio.create_task(collector.start(bus))
        received = await _collect_events(bus, target_count=1, timeout=1.0)
        await collector.stop()
        task.cancel()

    types = {ev.type for ev in received}
    assert "new_process" in types
    new = next(e for e in received if e.type == "new_process")
    assert new.pid == 200
    assert new.indicators.get("name") == "notepad.exe"


@pytest.mark.asyncio
async def test_proc_collector_emits_process_exit():
    procs_a = [_FakeProc(100, "a.exe", ["a.exe"], "u", 1.0),
               _FakeProc(200, "b.exe", ["b.exe"], "u", 1.0)]
    procs_b = [_FakeProc(100, "a.exe", ["a.exe"], "u", 1.0)]
    iterations = iter([procs_a, procs_b])

    def fake_iter(attrs):
        return next(iterations)

    bus = EventBus()
    collector = ProcCollector(host="H", poll_interval_seconds=0.05)
    with patch("cerberus.collectors.proc.psutil.process_iter", side_effect=fake_iter):
        task = asyncio.create_task(collector.start(bus))
        received = await _collect_events(bus, target_count=1, timeout=1.0)
        await collector.stop()
        task.cancel()

    exit_events = [e for e in received if e.type == "process_exit"]
    assert len(exit_events) >= 1
    assert exit_events[0].pid == 200


def test_proc_collector_health_initial():
    c = ProcCollector(host="H")
    h = c.health()
    assert h.name == "proc"
    assert h.running is False
    assert h.events_emitted == 0
