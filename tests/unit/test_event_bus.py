
from cerberus.core.event import Event
from cerberus.core.event_bus import EventBus


def _evt(source="proc", type_="new_process"):
    return Event(
        source=source, type=type_, host="h", pid=1,
        user=None, raw={}, indicators={},
    )


async def test_subscriber_receives_published_event():
    bus = EventBus()
    received: list[Event] = []

    async def handler(ev: Event) -> None:
        received.append(ev)

    bus.subscribe(handler)
    bus.start()
    await bus.publish(_evt())
    await bus.drain()
    assert len(received) == 1


async def test_filter_by_source():
    bus = EventBus()
    proc_events: list[Event] = []
    net_events: list[Event] = []

    bus.subscribe(lambda e: proc_events.append(e), source_filter="proc")
    bus.subscribe(lambda e: net_events.append(e), source_filter="net")
    bus.start()
    await bus.publish(_evt(source="proc"))
    await bus.publish(_evt(source="net"))
    await bus.drain()
    assert len(proc_events) == 1 and len(net_events) == 1


async def test_handler_exception_does_not_break_bus():
    bus = EventBus()

    async def bad(ev: Event) -> None:
        raise RuntimeError("boom")

    good_calls: list[Event] = []
    bus.subscribe(bad)
    bus.subscribe(lambda e: good_calls.append(e))
    bus.start()
    await bus.publish(_evt())
    await bus.drain()
    assert len(good_calls) == 1


async def test_unsubscribe():
    bus = EventBus()
    calls: list[Event] = []
    sub = bus.subscribe(lambda e: calls.append(e))
    bus.start()
    await bus.publish(_evt())
    await bus.drain()
    sub.unsubscribe()
    await bus.publish(_evt())
    await bus.drain()
    assert len(calls) == 1


async def test_stop_drains_pending():
    bus = EventBus()
    received: list[Event] = []
    bus.subscribe(lambda e: received.append(e))
    bus.start()
    for _ in range(5):
        await bus.publish(_evt())
    await bus.stop()
    assert len(received) == 5
