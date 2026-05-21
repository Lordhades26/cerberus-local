from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from cerberus.core.event_bus import EventBus


@dataclass
class CollectorHealth:
    name: str
    running: bool
    events_emitted: int
    last_error: str | None


class Collector(ABC):
    name: str = "collector"

    def __init__(self) -> None:
        self._events_emitted: int = 0
        self._last_error: str | None = None
        self._running: bool = False

    @abstractmethod
    async def start(self, bus: EventBus) -> None: ...

    @abstractmethod
    async def stop(self) -> None: ...

    def health(self) -> CollectorHealth:
        return CollectorHealth(
            name=self.name,
            running=self._running,
            events_emitted=self._events_emitted,
            last_error=self._last_error,
        )
