from __future__ import annotations

import asyncio
import time
from collections import defaultdict
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from cerberus.core.event import Event
from cerberus.core.event_bus import EventBus
from cerberus.core.finding import Finding
from cerberus.core.logger import get_logger

_log = get_logger("cerberus.detection.correlator")

OnFinding = Callable[[Finding], Awaitable[None] | None]

# clave de agrupación: (host, pid, user)
_ClusterKey = tuple[str, int | None, str | None]


@dataclass
class _TimedEvent:
    received_at: float
    event: Event


class Correlator:
    """Agrupa eventos por (host, pid, user) en una ventana deslizante y promueve
    clusters multi-fuente a Finding. 100% heurístico (sin LLM).

    El handler de bus solo acumula; la promoción ocurre en flush(), llamado
    periódicamente por run() o explícitamente (tests). Dedup por clave de cluster:
    un cluster se promueve una vez por ráfaga; al envejecer todos sus eventos la
    marca se limpia y una nueva ráfaga puede volver a promover.
    """

    def __init__(
        self,
        window_seconds: int,
        min_sources_for_finding: int,
        on_finding: OnFinding,
        flush_interval_seconds: float = 1.0,
    ) -> None:
        self._window = window_seconds
        self._min_sources = min_sources_for_finding
        self._on_finding = on_finding
        self._flush_interval = flush_interval_seconds
        self._buffer: list[_TimedEvent] = []
        self._promoted: set[_ClusterKey] = set()
        self._stop = asyncio.Event()
        # Tareas de manejo de hallazgos en vuelo. Se trackean para poder
        # esperarlas (join) antes de leer resultados o cerrar: sin esto las
        # tareas fire-and-forget podían perderse en un flush/cierre.
        self._pending: set[asyncio.Task] = set()

    def attach(self, bus: EventBus) -> None:
        bus.subscribe(self._on_event)

    def _on_event(self, event: Event) -> None:
        self._buffer.append(_TimedEvent(received_at=time.monotonic(), event=event))

    async def run(self) -> None:
        self._stop.clear()
        while not self._stop.is_set():
            try:
                await self.flush()
            except Exception as exc:
                _log.error("correlator_flush_error", extra={"error": str(exc)})
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self._flush_interval)
            except TimeoutError:
                pass

    async def stop(self) -> None:
        self._stop.set()

    async def join(self) -> None:
        """Espera a que terminen las tareas de manejo de hallazgos en vuelo.

        Debe llamarse tras un flush explícito (tests, cierre) antes de leer
        resultados o cerrar recursos, para no descartar hallazgos ni acciones.
        """
        while self._pending:
            batch = tuple(self._pending)
            self._pending.difference_update(batch)
            await asyncio.gather(*batch, return_exceptions=True)

    def _evict(self, now: float) -> None:
        cutoff = now - self._window
        self._buffer = [te for te in self._buffer if te.received_at >= cutoff]

    def _group(self) -> dict[_ClusterKey, list[Event]]:
        groups: dict[_ClusterKey, list[Event]] = defaultdict(list)
        for te in self._buffer:
            ev = te.event
            groups[(ev.host, ev.pid, ev.user)].append(ev)
        return groups

    async def flush(self) -> None:
        now = time.monotonic()
        self._evict(now)
        groups = self._group()
        # limpiar marcas de claves sin eventos vivos (ráfaga terminada)
        self._promoted &= set(groups.keys())
        for (host, pid, user), evs in groups.items():
            key: _ClusterKey = (host, pid, user)
            sources = {e.source for e in evs}
            if len(sources) < self._min_sources:
                continue
            if key in self._promoted:
                continue
            self._promoted.add(key)
            finding = Finding.from_cluster(host=host, pid=pid, user=user, evidence=evs)
            _log.info(
                "finding_promoted",
                extra={"finding_id": finding.id, "pid": pid,
                       "sources": sorted(sources)},
            )
            # Disparamos el procesamiento del hallazgo en una tarea de fondo,
            # trackeada para poder esperarla en join().
            task = asyncio.create_task(self._handle_finding(finding))
            self._pending.add(task)
            task.add_done_callback(self._pending.discard)

    async def _handle_finding(self, finding: Finding) -> None:
        try:
            result = self._on_finding(finding)
            if result is not None:
                await result
        except Exception as exc:
            _log.error("correlator_on_finding_error", extra={"error": str(exc), "finding_id": finding.id})
