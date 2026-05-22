import asyncio

import pytest

from cerberus.core.event import Event
from cerberus.core.event_bus import EventBus
from cerberus.core.finding import Finding
from cerberus.detection.correlator import Correlator


def _ev(source, type_, pid=10, user="u", host="H"):
    return Event(source=source, type=type_, host=host, pid=pid,
                 user=user, raw={}, indicators={})


@pytest.mark.asyncio
async def test_correlator_promotes_multi_source_cluster():
    findings: list[Finding] = []

    async def on_finding(f: Finding) -> None:
        findings.append(f)

    bus = EventBus()
    corr = Correlator(window_seconds=10, min_sources_for_finding=2, on_finding=on_finding)
    corr.attach(bus)
    bus.start()

    await bus.publish(_ev("proc", "new_process", pid=10))
    await bus.publish(_ev("net", "outbound_conn", pid=10))
    await bus.drain()
    await corr.flush()
    await bus.stop()

    assert len(findings) == 1
    f = findings[0]
    assert f.pid == 10
    assert f.sources == {"proc", "net"}


@pytest.mark.asyncio
async def test_correlator_single_source_does_not_promote():
    findings: list[Finding] = []

    async def on_finding(f: Finding) -> None:
        findings.append(f)

    bus = EventBus()
    corr = Correlator(window_seconds=10, min_sources_for_finding=2, on_finding=on_finding)
    corr.attach(bus)
    bus.start()

    await bus.publish(_ev("proc", "new_process", pid=10))
    await bus.publish(_ev("proc", "process_exit", pid=10))
    await bus.drain()
    await corr.flush()
    await bus.stop()

    assert findings == []


@pytest.mark.asyncio
async def test_correlator_groups_by_pid():
    findings: list[Finding] = []

    async def on_finding(f: Finding) -> None:
        findings.append(f)

    bus = EventBus()
    corr = Correlator(window_seconds=10, min_sources_for_finding=2, on_finding=on_finding)
    corr.attach(bus)
    bus.start()

    # pid 10 multi-fuente -> finding; pid 20 single-source -> no
    await bus.publish(_ev("proc", "new_process", pid=10))
    await bus.publish(_ev("fs", "file_created", pid=10))
    await bus.publish(_ev("net", "outbound_conn", pid=20))
    await bus.drain()
    await corr.flush()
    await bus.stop()

    assert len(findings) == 1
    assert findings[0].pid == 10


@pytest.mark.asyncio
async def test_correlator_promotes_cluster_only_once():
    findings: list[Finding] = []

    async def on_finding(f: Finding) -> None:
        findings.append(f)

    bus = EventBus()
    corr = Correlator(window_seconds=10, min_sources_for_finding=2, on_finding=on_finding)
    corr.attach(bus)
    bus.start()

    await bus.publish(_ev("proc", "new_process", pid=10))
    await bus.publish(_ev("net", "outbound_conn", pid=10))
    await bus.drain()
    await corr.flush()
    await corr.flush()   # segundo flush no debe re-promover el mismo cluster
    await bus.stop()

    assert len(findings) == 1


@pytest.mark.asyncio
async def test_correlator_evicts_events_outside_window():
    findings: list[Finding] = []

    async def on_finding(f: Finding) -> None:
        findings.append(f)

    bus = EventBus()
    # ventana de 0 segundos -> todo evento envejece inmediatamente; sin clusters vivos
    corr = Correlator(window_seconds=0, min_sources_for_finding=2, on_finding=on_finding)
    corr.attach(bus)
    bus.start()

    await bus.publish(_ev("proc", "new_process", pid=10))
    await bus.publish(_ev("net", "outbound_conn", pid=10))
    await bus.drain()
    await asyncio.sleep(0.01)
    await corr.flush()
    await bus.stop()

    assert findings == []
