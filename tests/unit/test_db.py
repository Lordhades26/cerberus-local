from datetime import UTC
from pathlib import Path

import pytest

from cerberus.core.db import EventStore
from cerberus.core.event import Event


@pytest.fixture
def store(tmp_path: Path) -> EventStore:
    s = EventStore(tmp_path / "events.db")
    s.init_schema()
    return s


def _evt(source="proc", type_="new_process") -> Event:
    return Event(
        source=source, type=type_, host="h", pid=1,
        user=None, raw={"name": "x.exe"}, indicators={"hash": "abc"},
    )


def test_init_schema_creates_table(store: EventStore):
    assert store.table_exists("events")


def test_insert_and_fetch(store: EventStore):
    ev = _evt()
    store.insert(ev)
    rows = store.fetch_all()
    assert len(rows) == 1
    assert rows[0]["id"] == ev.id
    assert rows[0]["source"] == "proc"


def test_fetch_by_source(store: EventStore):
    store.insert(_evt(source="proc"))
    store.insert(_evt(source="net"))
    proc_rows = store.fetch_by_source("proc")
    assert len(proc_rows) == 1


def test_count(store: EventStore):
    for _ in range(7):
        store.insert(_evt())
    assert store.count() == 7


def test_purge_older_than_days(store: EventStore, monkeypatch):
    from datetime import datetime, timedelta
    old = _evt()
    object.__setattr__(old, "timestamp", datetime.now(UTC) - timedelta(days=10))
    store.insert(old)
    store.insert(_evt())
    deleted = store.purge_older_than(days=7)
    assert deleted == 1
    assert store.count() == 1
