from __future__ import annotations

import asyncio
import math
import time
from collections import Counter, deque
from pathlib import Path
from typing import Any

from watchdog.events import (
    FileCreatedEvent,
    FileModifiedEvent,
    FileMovedEvent,
    FileSystemEvent,
    FileSystemEventHandler,
)
from watchdog.observers import Observer
from watchdog.observers.api import BaseObserver

from cerberus.collectors.base import Collector
from cerberus.core.event import Event
from cerberus.core.event_bus import EventBus
from cerberus.core.logger import get_logger

_log = get_logger("cerberus.collectors.fs")

_ENTROPY_SAMPLE_BYTES = 65536  # leer máx 64KB para estimar entropía


def shannon_entropy(data: bytes) -> float:
    """Entropía de Shannon en bits/byte (0.0–8.0). Vacío -> 0.0."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    entropy = 0.0
    for c in counts.values():
        p = c / length
        entropy -= p * math.log2(p)
    return entropy


class _Handler(FileSystemEventHandler):
    """Puente síncrono (hilo watchdog) -> asyncio loop del collector."""

    def __init__(self, collector: FsCollector, loop: asyncio.AbstractEventLoop) -> None:
        self._collector = collector
        self._loop = loop

    def _submit(self, coro: Any) -> None:
        asyncio.run_coroutine_threadsafe(coro, self._loop)

    def on_created(self, event: FileSystemEvent) -> None:
        if isinstance(event, FileCreatedEvent) and not event.is_directory:
            self._submit(self._collector._on_created(str(event.src_path)))

    def on_modified(self, event: FileSystemEvent) -> None:
        if isinstance(event, FileModifiedEvent) and not event.is_directory:
            self._submit(self._collector._on_modified(str(event.src_path)))

    def on_moved(self, event: FileSystemEvent) -> None:
        if isinstance(event, FileMovedEvent) and not event.is_directory:
            self._submit(
                self._collector._on_moved(str(event.src_path), str(event.dest_path))
            )


class FsCollector(Collector):
    """Vigila rutas con watchdog.

    Emite file_created / file_modified / mass_rename / high_entropy_write.
    """

    name = "fs"

    def __init__(
        self,
        host: str,
        watch_paths: list[Path],
        mass_rename_threshold: int = 20,
        mass_rename_window_seconds: int = 5,
        high_entropy_threshold: float = 7.5,
    ) -> None:
        super().__init__()
        self._host = host
        self._watch_paths = [Path(p) for p in watch_paths]
        self._mass_threshold = mass_rename_threshold
        self._mass_window = mass_rename_window_seconds
        self._entropy_threshold = high_entropy_threshold
        self._observer: BaseObserver | None = None
        self._bus: EventBus | None = None
        self._rename_hist: deque[float] = deque()
        self._mass_alerted_at: float = 0.0

    async def start(self, bus: EventBus) -> None:
        self._bus = bus
        loop = asyncio.get_running_loop()
        handler = _Handler(self, loop)
        observer = Observer()
        watched = 0
        for p in self._watch_paths:
            if p.exists():
                observer.schedule(handler, str(p), recursive=True)
                watched += 1
            else:
                _log.warning("fs_watch_path_missing", extra={"path": str(p)})
        if watched == 0:
            self._last_error = "no_valid_watch_paths"
            _log.error("fs_no_valid_paths")
            self._running = False
            return
        observer.start()
        self._observer = observer
        self._running = True
        _log.info("fs_collector_started", extra={"paths": watched})

    async def stop(self) -> None:
        if self._observer is not None:
            self._observer.stop()
            self._observer.join(timeout=5)
            self._observer = None
        self._running = False

    async def _publish(self, event: Event) -> None:
        if self._bus is not None:
            await self._bus.publish(event)
            self._events_emitted += 1

    async def _on_created(self, path: str) -> None:
        await self._publish(
            Event(source="fs", type="file_created", host=self._host, pid=None,
                  user=None, raw={"path": path}, indicators={"path": path})
        )

    async def _on_modified(self, path: str) -> None:
        await self._publish(
            Event(source="fs", type="file_modified", host=self._host, pid=None,
                  user=None, raw={"path": path}, indicators={"path": path})
        )
        await self._maybe_high_entropy(path)

    async def _on_moved(self, src: str, dest: str) -> None:
        now = time.monotonic()
        self._rename_hist.append(now)
        cutoff = now - self._mass_window
        while self._rename_hist and self._rename_hist[0] < cutoff:
            self._rename_hist.popleft()
        if (
            len(self._rename_hist) >= self._mass_threshold
            and now - self._mass_alerted_at > self._mass_window
        ):
            self._mass_alerted_at = now
            await self._publish(
                Event(
                    source="fs", type="mass_rename", host=self._host, pid=None,
                    user=None, raw={"latest_src": src, "latest_dest": dest},
                    indicators={"rename_count": len(self._rename_hist)},
                )
            )

    @staticmethod
    def _read_sample(path: str) -> bytes | None:
        try:
            with open(path, "rb") as fh:
                return fh.read(_ENTROPY_SAMPLE_BYTES)
        except OSError:
            return None

    async def _maybe_high_entropy(self, path: str) -> None:
        data = await asyncio.to_thread(self._read_sample, path)
        if data is None:
            return
        ent = shannon_entropy(data)
        if ent >= self._entropy_threshold and len(data) >= 256:
            await self._publish(
                Event(
                    source="fs", type="high_entropy_write", host=self._host, pid=None,
                    user=None, raw={"path": path, "bytes_sampled": len(data)},
                    indicators={"path": path, "entropy": round(ent, 3)},
                )
            )
