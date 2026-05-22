from __future__ import annotations

import asyncio
import inspect
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

from cerberus.core.event import Event
from cerberus.core.logger import get_logger

_log = get_logger("cerberus.core.event_bus")

Handler = Callable[[Event], Awaitable[None] | None]


@dataclass
class Subscription:
    handler: Handler
    source_filter: str | None
    _bus: EventBus
    _alive: bool = field(default=True, repr=False)

    def unsubscribe(self) -> None:
        if self._alive:
            self._bus._remove(self)
            self._alive = False


class EventBus:
    def __init__(self, maxsize: int = 10_000) -> None:
        self._queue: asyncio.Queue[Event] = asyncio.Queue(maxsize=maxsize)
        self._subs: list[Subscription] = []
        self._dispatcher: asyncio.Task[None] | None = None
        self._closed = False

    def subscribe(self, handler: Handler, source_filter: str | None = None) -> Subscription:
        sub = Subscription(handler=handler, source_filter=source_filter, _bus=self)
        self._subs.append(sub)
        return sub

    def _remove(self, sub: Subscription) -> None:
        try:
            self._subs.remove(sub)
        except ValueError:
            pass

    def start(self) -> None:
        if self._dispatcher is None:
            self._dispatcher = asyncio.create_task(self._run(), name="event_bus")

    async def publish(self, event: Event) -> None:
        if self._closed:
            raise RuntimeError("EventBus is closed")
        await self._queue.put(event)

    async def drain(self) -> None:
        await self._queue.join()

    async def stop(self) -> None:
        await self.drain()
        self._closed = True
        if self._dispatcher is not None:
            self._dispatcher.cancel()
            try:
                await self._dispatcher
            except asyncio.CancelledError:
                pass
            self._dispatcher = None

    async def _run(self) -> None:
        while True:
            event = await self._queue.get()
            try:
                await self._dispatch(event)
            finally:
                self._queue.task_done()

    async def _dispatch(self, event: Event) -> None:
        for sub in list(self._subs):
            if sub.source_filter and sub.source_filter != event.source:
                continue
            try:
                result = sub.handler(event)
                if inspect.isawaitable(result):
                    await result
            except Exception as exc:
                _log.error("handler_error", extra={"error": str(exc), "event_id": event.id})
