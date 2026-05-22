from __future__ import annotations

import asyncio
from typing import Any

import psutil

from cerberus.collectors.base import Collector
from cerberus.core.event import Event
from cerberus.core.event_bus import EventBus
from cerberus.core.logger import get_logger

_log = get_logger("cerberus.collectors.proc")

_PROC_ATTRS = ["pid", "name", "cmdline", "username", "create_time", "exe"]


class ProcCollector(Collector):
    name = "proc"

    def __init__(self, host: str, poll_interval_seconds: float = 1.0) -> None:
        super().__init__()
        self._host = host
        self._interval = poll_interval_seconds
        self._known_pids: set[int] = set()
        self._known_meta: dict[int, dict[str, Any]] = {}
        self._stop = asyncio.Event()

    async def start(self, bus: EventBus) -> None:
        self._running = True
        self._stop.clear()
        try:
            await self._seed()
            while not self._stop.is_set():
                try:
                    await self._tick(bus)
                except Exception as exc:
                    self._last_error = repr(exc)
                    _log.error("proc_tick_error", extra={"error": str(exc)})
                try:
                    await asyncio.wait_for(self._stop.wait(), timeout=self._interval)
                except TimeoutError:
                    pass
        finally:
            self._running = False

    async def stop(self) -> None:
        self._stop.set()

    async def _seed(self) -> None:
        for proc in psutil.process_iter(attrs=_PROC_ATTRS):
            info = proc.info
            self._known_pids.add(info["pid"])
            self._known_meta[info["pid"]] = info

    async def _tick(self, bus: EventBus) -> None:
        current_meta: dict[int, dict[str, Any]] = {}
        current_pids: set[int] = set()
        for proc in psutil.process_iter(attrs=_PROC_ATTRS):
            info = proc.info
            current_meta[info["pid"]] = info
            current_pids.add(info["pid"])

        for pid in current_pids - self._known_pids:
            info = current_meta[pid]
            ev = Event(
                source="proc",
                type="new_process",
                host=self._host,
                pid=pid,
                user=info.get("username"),
                raw=info,
                indicators={
                    "name": info.get("name"),
                    "cmdline": " ".join(info.get("cmdline") or []),
                    "exe": info.get("exe"),
                },
            )
            await bus.publish(ev)
            self._events_emitted += 1

        for pid in self._known_pids - current_pids:
            info = self._known_meta.get(pid, {"pid": pid})
            ev = Event(
                source="proc",
                type="process_exit",
                host=self._host,
                pid=pid,
                user=info.get("username"),
                raw=info,
                indicators={"name": info.get("name")},
            )
            await bus.publish(ev)
            self._events_emitted += 1

        self._known_pids = current_pids
        self._known_meta = current_meta
