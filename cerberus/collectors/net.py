from __future__ import annotations

import asyncio
import ipaddress
import time
from collections import defaultdict, deque
from typing import Any

import psutil

from cerberus.collectors.base import Collector
from cerberus.core.event import Event
from cerberus.core.event_bus import EventBus
from cerberus.core.logger import get_logger

_log = get_logger("cerberus.collectors.net")


def _is_routable(ip: str) -> bool:
    """True si la IP no es loopback/link-local/no especificada."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (addr.is_loopback or addr.is_link_local or addr.is_unspecified)


class NetCollector(Collector):
    """Detecta conexiones salientes y patrones de beaconing por polling psutil.

    M2: sin captura de paquetes (pyshark/Npcap se difiere a M3). Solo observa el
    estado de las conexiones del host con psutil.net_connections().
    """

    name = "net"

    def __init__(
        self,
        host: str,
        poll_interval_seconds: float = 2.0,
        beaconing_window_seconds: int = 60,
        beaconing_min_connections: int = 10,
    ) -> None:
        super().__init__()
        self._host = host
        self._interval = poll_interval_seconds
        self._beacon_window = beaconing_window_seconds
        self._beacon_min = beaconing_min_connections
        # clave de conexión vista: (pid, remote_ip, remote_port, lport)
        self._known: set[tuple[int | None, str, int, int]] = set()
        # historial de timestamps por (pid, remote_ip) para detectar beaconing
        self._beacon_hist: dict[tuple[int | None, str], deque[float]] = defaultdict(deque)
        self._beacon_alerted: set[tuple[int | None, str]] = set()
        self._stop = asyncio.Event()

    async def start(self, bus: EventBus) -> None:
        self._running = True
        self._stop.clear()
        try:
            self._seed()
            while not self._stop.is_set():
                try:
                    await self._tick(bus)
                except Exception as exc:
                    self._last_error = repr(exc)
                    _log.error("net_tick_error", extra={"error": str(exc)})
                try:
                    await asyncio.wait_for(self._stop.wait(), timeout=self._interval)
                except TimeoutError:
                    pass
        finally:
            self._running = False

    async def stop(self) -> None:
        self._stop.set()

    def _outbound_conns(self) -> list[Any]:
        result: list[Any] = []
        for c in psutil.net_connections(kind="inet"):
            if c.status == psutil.CONN_LISTEN:
                continue
            if not c.raddr:
                continue
            rip = c.raddr.ip if hasattr(c.raddr, "ip") else c.raddr[0]
            if not _is_routable(rip):
                continue
            result.append(c)
        return result

    def _seed(self) -> None:
        for c in self._outbound_conns():
            self._known.add(self._key(c))

    @staticmethod
    def _key(c: Any) -> tuple[int | None, str, int, int]:
        rip = c.raddr.ip if hasattr(c.raddr, "ip") else c.raddr[0]
        rport = c.raddr.port if hasattr(c.raddr, "port") else c.raddr[1]
        lport = c.laddr.port if hasattr(c.laddr, "port") else c.laddr[1]
        return (c.pid, rip, int(rport), int(lport))

    async def _tick(self, bus: EventBus) -> None:
        now = time.monotonic()
        current = self._outbound_conns()
        current_keys = {self._key(c) for c in current}

        for c in current:
            key = self._key(c)
            if key in self._known:
                continue
            pid, rip, rport, _lport = key
            ev = Event(
                source="net",
                type="outbound_conn",
                host=self._host,
                pid=pid,
                user=None,
                raw={"status": c.status},
                indicators={
                    "remote_ip": rip,
                    "remote_port": rport,
                    "local_port": _lport,
                },
            )
            await bus.publish(ev)
            self._events_emitted += 1
            await self._track_beaconing(bus, pid, rip, now)

        self._known = current_keys

    async def _track_beaconing(
        self, bus: EventBus, pid: int | None, rip: str, now: float
    ) -> None:
        bkey = (pid, rip)
        hist = self._beacon_hist[bkey]
        hist.append(now)
        cutoff = now - self._beacon_window
        while hist and hist[0] < cutoff:
            hist.popleft()
        if len(hist) >= self._beacon_min and bkey not in self._beacon_alerted:
            self._beacon_alerted.add(bkey)
            ev = Event(
                source="net",
                type="beaconing_suspect",
                host=self._host,
                pid=pid,
                user=None,
                raw={"window_seconds": self._beacon_window},
                indicators={
                    "remote_ip": rip,
                    "connection_count": len(hist),
                },
            )
            await bus.publish(ev)
            self._events_emitted += 1
