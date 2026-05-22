from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from cerberus.collectors.base import Collector
from cerberus.core.event import Event
from cerberus.core.event_bus import EventBus
from cerberus.core.logger import get_logger

_log = get_logger("cerberus.collectors.evt")

# Mapeo Windows Event ID -> tipo normalizado del Event de Cerberus.
_EVENT_ID_MAP: dict[int, str] = {
    4625: "logon_failure",
    4697: "service_install",
    7045: "service_install",
    4698: "scheduled_task_create",
    4104: "ps_blocklist",
}
_GENERIC_TYPE = "win_event"


@dataclass(frozen=True)
class EvtRecord:
    """Registro crudo entregado por un EvtSource (ya extraído del canal)."""

    channel: str
    event_id: int
    raw: dict[str, Any] = field(default_factory=dict)


@runtime_checkable
class EvtSource(Protocol):
    def poll(self) -> list[EvtRecord]: ...


def _build_win32_source(channels: list[str]) -> EvtSource | None:
    """Construye el source real si pywin32 está disponible; si no, None."""
    try:
        import win32evtlog  # noqa: F401
    except Exception:
        return None
    return _Win32EvtSource(channels)


class _Win32EvtSource:
    """Source real basado en win32evtlog (solo Windows). Polling de canales.

    Nota: implementación de M2 hace lectura por canal vía EvtQuery/EvtNext.
    La suscripción push (EvtSubscribe) se evalúa en M4 junto al Windows Service.
    Mantener la API `poll()` estable.
    """

    def __init__(self, channels: list[str]) -> None:
        import win32evtlog

        self._win32evtlog = win32evtlog
        self._channels = channels

    def poll(self) -> list[EvtRecord]:
        records: list[EvtRecord] = []
        for channel in self._channels:
            try:
                records.extend(self._read_channel(channel))
            except Exception as exc:  # un canal inaccesible no rompe el resto
                _log.warning("evt_channel_error",
                             extra={"channel": channel, "error": str(exc)})
        return records

    def _read_channel(self, channel: str) -> list[EvtRecord]:
        w = self._win32evtlog
        flags = w.EvtQueryChannelPath | w.EvtQueryReverseDirection
        out: list[EvtRecord] = []
        try:
            handle = w.EvtQuery(channel, flags, None, None)
        except Exception:
            return out
        events = w.EvtNext(handle, 10)
        for ev in events:
            xml = w.EvtRender(ev, w.EvtRenderEventXml)
            event_id = _parse_event_id(xml)
            out.append(EvtRecord(channel=channel, event_id=event_id, raw={"xml": xml}))
        return out


def _parse_event_id(xml: str) -> int:
    """Extrae <EventID>N</EventID> del XML del evento. -1 si no se encuentra."""
    import re

    m = re.search(r"<EventID[^>]*>(\d+)</EventID>", xml)
    return int(m.group(1)) if m else -1


class EvtCollector(Collector):
    """Lee canales de Windows Event Log y emite Events normalizados.

    Degrada con gracia: si no hay source disponible (pywin32 ausente o no-Windows),
    arranca con running=False y deja correr al resto del sistema.
    """

    name = "evt"

    def __init__(
        self,
        host: str,
        channels: list[str],
        poll_interval_seconds: float = 2.0,
        source: EvtSource | str | None = None,
    ) -> None:
        super().__init__()
        self._host = host
        self._channels = list(channels)
        self._interval = poll_interval_seconds
        # source explícito (tests), "unavailable" para forzar degradación, o None=autodetect
        self._source_arg = source
        self._source: EvtSource | None = None
        self._stop = asyncio.Event()

    def _resolve_source(self) -> EvtSource | None:
        if self._source_arg == "unavailable":
            return None
        if self._source_arg is not None and not isinstance(self._source_arg, str):
            return self._source_arg
        return _build_win32_source(self._channels)

    async def start(self, bus: EventBus) -> None:
        self._source = self._resolve_source()
        if self._source is None:
            self._running = False
            self._last_error = "evt_source_unavailable"
            _log.info("evt_collector_unavailable", extra={"host": self._host})
            return
        self._running = True
        self._stop.clear()
        try:
            while not self._stop.is_set():
                try:
                    await self._tick(bus)
                except Exception as exc:
                    self._last_error = repr(exc)
                    _log.error("evt_tick_error", extra={"error": str(exc)})
                try:
                    await asyncio.wait_for(self._stop.wait(), timeout=self._interval)
                except TimeoutError:
                    pass
        finally:
            self._running = False

    async def stop(self) -> None:
        self._stop.set()

    async def _tick(self, bus: EventBus) -> None:
        assert self._source is not None
        for rec in self._source.poll():
            etype = _EVENT_ID_MAP.get(rec.event_id, _GENERIC_TYPE)
            ev = Event(
                source="evt",
                type=etype,
                host=self._host,
                pid=None,
                user=rec.raw.get("TargetUserName"),
                raw=rec.raw,
                indicators={"channel": rec.channel, "event_id": rec.event_id},
            )
            await bus.publish(ev)
            self._events_emitted += 1
