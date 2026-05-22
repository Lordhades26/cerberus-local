import asyncio
from pathlib import Path

import pytest

from cerberus.collectors.fs import FsCollector, shannon_entropy
from cerberus.core.event import Event
from cerberus.core.event_bus import EventBus


def test_shannon_entropy_uniform_random_is_high():
    data = bytes(range(256)) * 4  # distribución uniforme -> entropía máxima (8.0)
    assert shannon_entropy(data) > 7.9


def test_shannon_entropy_repetitive_is_low():
    data = b"AAAAAAAAAAAAAAAA" * 64
    assert shannon_entropy(data) < 1.0


def test_shannon_entropy_empty_is_zero():
    assert shannon_entropy(b"") == 0.0


async def _collect_events(bus: EventBus, target_count: int, wait_secs: float = 2.0) -> list[Event]:
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
async def test_fs_collector_emits_file_created(tmp_path: Path):
    bus = EventBus()
    c = FsCollector(
        host="H",
        watch_paths=[tmp_path],
        mass_rename_threshold=20,
        mass_rename_window_seconds=5,
        high_entropy_threshold=7.5,
    )
    await c.start(bus)
    try:
        # crear archivo tras arrancar el observer
        (tmp_path / "nuevo.txt").write_text("hola", encoding="utf-8")
        received = await _collect_events(bus, target_count=1, wait_secs=2.0)
    finally:
        await c.stop()

    created = [e for e in received if e.type == "file_created"]
    assert len(created) >= 1
    assert created[0].source == "fs"
    assert "nuevo.txt" in created[0].indicators["path"]


@pytest.mark.asyncio
async def test_fs_collector_emits_mass_rename(tmp_path: Path):
    bus = EventBus()
    c = FsCollector(
        host="H",
        watch_paths=[tmp_path],
        mass_rename_threshold=3,            # umbral bajo para el test
        mass_rename_window_seconds=5,
        high_entropy_threshold=7.5,
    )
    # pre-crear archivos
    files = []
    for i in range(5):
        f = tmp_path / f"f{i}.txt"
        f.write_text("x", encoding="utf-8")
        files.append(f)

    await c.start(bus)
    try:
        for i, f in enumerate(files):
            f.rename(tmp_path / f"f{i}.locked")
        received = await _collect_events(bus, target_count=1, wait_secs=4.0)
    finally:
        await c.stop()

    mass = [e for e in received if e.type == "mass_rename"]
    assert len(mass) >= 1
    assert mass[0].indicators["rename_count"] >= 3


def test_fs_collector_health_initial():
    c = FsCollector(host="H", watch_paths=[Path(".")])
    h = c.health()
    assert h.name == "fs"
    assert h.running is False
