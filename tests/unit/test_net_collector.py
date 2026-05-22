import asyncio
from collections import namedtuple
from unittest.mock import patch

import pytest

from cerberus.collectors.net import NetCollector
from cerberus.core.event import Event
from cerberus.core.event_bus import EventBus

_Addr = namedtuple("_Addr", ["ip", "port"])
_SConn = namedtuple("_SConn", ["fd", "family", "type", "laddr", "raddr", "status", "pid"])


def _conn(pid, rip, rport, status="ESTABLISHED"):
    return _SConn(
        fd=1, family=2, type=1,
        laddr=_Addr("192.168.1.5", 50000),
        raddr=_Addr(rip, rport),
        status=status, pid=pid,
    )


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
async def test_net_collector_emits_outbound_conn_for_new_connection():
    seq = iter([
        [],  # seed: sin conexiones
        [_conn(1000, "185.10.10.10", 443)],  # aparece una nueva
    ])

    def fake_net_connections(kind="inet"):
        try:
            return next(seq)
        except StopIteration:
            return [_conn(1000, "185.10.10.10", 443)]

    bus = EventBus()
    c = NetCollector(host="H", poll_interval_seconds=0.05,
                     beaconing_window_seconds=60, beaconing_min_connections=10)
    with patch("cerberus.collectors.net.psutil.net_connections",
               side_effect=fake_net_connections):
        task = asyncio.create_task(c.start(bus))
        received = await _collect_events(bus, target_count=1, wait_secs=1.0)
        await c.stop()
        task.cancel()

    outbound = [e for e in received if e.type == "outbound_conn"]
    assert len(outbound) >= 1
    ev = outbound[0]
    assert ev.source == "net"
    assert ev.indicators["remote_ip"] == "185.10.10.10"
    assert ev.indicators["remote_port"] == 443
    assert ev.pid == 1000


@pytest.mark.asyncio
async def test_net_collector_skips_loopback_and_listening():
    loop_conn = _SConn(fd=1, family=2, type=1,
                       laddr=_Addr("127.0.0.1", 1), raddr=_Addr("127.0.0.1", 2),
                       status="ESTABLISHED", pid=1)
    listen_conn = _SConn(fd=2, family=2, type=1,
                         laddr=_Addr("0.0.0.0", 80), raddr=(),
                         status="LISTEN", pid=2)
    seq = iter([[], [loop_conn, listen_conn]])

    def fake_net_connections(kind="inet"):
        try:
            return next(seq)
        except StopIteration:
            return [loop_conn, listen_conn]

    bus = EventBus()
    c = NetCollector(host="H", poll_interval_seconds=0.05,
                     beaconing_window_seconds=60, beaconing_min_connections=10)
    with patch("cerberus.collectors.net.psutil.net_connections",
               side_effect=fake_net_connections):
        task = asyncio.create_task(c.start(bus))
        received = await _collect_events(bus, target_count=1, wait_secs=0.5)
        await c.stop()
        task.cancel()

    assert [e for e in received if e.type == "outbound_conn"] == []


@pytest.mark.asyncio
async def test_net_collector_emits_beaconing_suspect():
    # mismo destino repetido supera el umbral -> beaconing_suspect
    def make_conn(i):
        return _SConn(fd=i, family=2, type=1,
                      laddr=_Addr("192.168.1.5", 50000 + i),
                      raddr=_Addr("9.9.9.9", 443),
                      status="ESTABLISHED", pid=2000)
    ticks = [[]] + [[make_conn(i)] for i in range(1, 6)]
    seq = iter(ticks)

    def fake_net_connections(kind="inet"):
        try:
            return next(seq)
        except StopIteration:
            return []

    bus = EventBus()
    c = NetCollector(host="H", poll_interval_seconds=0.02,
                     beaconing_window_seconds=60, beaconing_min_connections=3)
    with patch("cerberus.collectors.net.psutil.net_connections",
               side_effect=fake_net_connections):
        task = asyncio.create_task(c.start(bus))
        received = await _collect_events(bus, target_count=6, wait_secs=1.0)
        await c.stop()
        task.cancel()

    beacons = [e for e in received if e.type == "beaconing_suspect"]
    assert len(beacons) >= 1
    assert beacons[0].indicators["remote_ip"] == "9.9.9.9"
    assert beacons[0].indicators["connection_count"] >= 3


def test_net_collector_health_initial():
    c = NetCollector(host="H")
    h = c.health()
    assert h.name == "net"
    assert h.running is False
    assert h.events_emitted == 0


@pytest.mark.asyncio
async def test_net_collector_purges_stale_beacon_keys(monkeypatch):
    import cerberus.collectors.net as netmod
    clock = {"t": 1000.0}
    monkeypatch.setattr(netmod.time, "monotonic", lambda: clock["t"])

    def make_conn(pid, ip, lport):
        return _SConn(fd=lport, family=2, type=1,
                      laddr=_Addr("192.168.1.5", lport),
                      raddr=_Addr(ip, 443), status="ESTABLISHED", pid=pid)

    seq = iter([[], [make_conn(2000, "9.9.9.9", 50001)]])

    def fake_net_connections(kind="inet"):
        try:
            return next(seq)
        except StopIteration:
            return []

    bus = EventBus()
    c = NetCollector(host="H", poll_interval_seconds=0.02,
                     beaconing_window_seconds=60, beaconing_min_connections=10)
    with patch("cerberus.collectors.net.psutil.net_connections",
               side_effect=fake_net_connections):
        task = asyncio.create_task(c.start(bus))
        await _collect_events(bus, target_count=1, wait_secs=0.5)
        clock["t"] += 120.0     # avanzar mas alla de la ventana de beaconing
        c.purge_stale()
        await c.stop()
        task.cancel()

    assert c.beacon_key_count() == 0
