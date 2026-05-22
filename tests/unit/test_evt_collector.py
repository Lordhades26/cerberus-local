import asyncio

import pytest

from cerberus.collectors.evt import EvtCollector, EvtRecord
from cerberus.core.event import Event
from cerberus.core.event_bus import EventBus


class FakeEvtSource:
    """Source inyectable: entrega lotes predefinidos y luego vacío."""

    def __init__(self, batches: list[list[EvtRecord]]) -> None:
        self._batches = iter(batches)

    def poll(self) -> list[EvtRecord]:
        try:
            return next(self._batches)
        except StopIteration:
            return []


async def _collect_events(bus: EventBus, target_count: int, wait_secs: float = 1.5) -> list[Event]:
    received: list[Event] = []
    done = asyncio.Event()

    async def handler(ev: Event) -> None:
        received.append(ev)
        if len(received) >= target_count:
            done.set()

    bus.subscribe(handler)
    bus.start()
    try:
        await asyncio.wait_for(done.wait(), timeout=wait_secs)
    except TimeoutError:
        pass
    await bus.stop()
    return received


@pytest.mark.asyncio
async def test_evt_collector_maps_logon_failure():
    rec = EvtRecord(channel="Security", event_id=4625,
                    raw={"TargetUserName": "admin"})
    bus = EventBus()
    c = EvtCollector(host="H", channels=["Security"], poll_interval_seconds=0.05,
                     source=FakeEvtSource([[rec]]))
    task = asyncio.create_task(c.start(bus))
    received = await _collect_events(bus, target_count=1, wait_secs=1.0)
    await c.stop()
    task.cancel()

    logon = [e for e in received if e.type == "logon_failure"]
    assert len(logon) == 1
    assert logon[0].source == "evt"
    assert logon[0].indicators["event_id"] == 4625
    assert logon[0].indicators["channel"] == "Security"


@pytest.mark.asyncio
async def test_evt_collector_maps_known_ids():
    recs = [
        EvtRecord(channel="Security", event_id=4697, raw={}),
        EvtRecord(channel="Security", event_id=4698, raw={}),
        EvtRecord(channel="Microsoft-Windows-PowerShell/Operational",
                  event_id=4104, raw={}),
    ]
    bus = EventBus()
    c = EvtCollector(host="H", channels=["Security"], poll_interval_seconds=0.05,
                     source=FakeEvtSource([recs]))
    task = asyncio.create_task(c.start(bus))
    received = await _collect_events(bus, target_count=3, wait_secs=1.0)
    await c.stop()
    task.cancel()

    types = {e.type for e in received}
    assert "service_install" in types
    assert "scheduled_task_create" in types
    assert "ps_blocklist" in types


@pytest.mark.asyncio
async def test_evt_collector_unknown_id_emits_generic():
    rec = EvtRecord(channel="Security", event_id=9999, raw={})
    bus = EventBus()
    c = EvtCollector(host="H", channels=["Security"], poll_interval_seconds=0.05,
                     source=FakeEvtSource([[rec]]))
    task = asyncio.create_task(c.start(bus))
    received = await _collect_events(bus, target_count=1, wait_secs=1.0)
    await c.stop()
    task.cancel()

    assert len(received) == 1
    assert received[0].type == "win_event"   # tipo genérico para IDs no mapeados
    assert received[0].indicators["event_id"] == 9999


@pytest.mark.asyncio
async def test_evt_collector_disabled_when_no_source_available():
    # source="unavailable" y win32evtlog no disponible -> health.running=False, sin excepción
    bus = EventBus()
    c = EvtCollector(host="H", channels=["Security"], poll_interval_seconds=0.05,
                     source="unavailable")
    await c.start(bus)
    h = c.health()
    assert h.running is False
    assert h.last_error == "evt_source_unavailable"
    await c.stop()


def test_evt_collector_health_initial():
    c = EvtCollector(host="H", channels=["Security"], source="unavailable")
    h = c.health()
    assert h.name == "evt"
    assert h.running is False
