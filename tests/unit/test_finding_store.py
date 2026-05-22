from pathlib import Path

import pytest

from cerberus.core.event import Event, Severity
from cerberus.core.finding import Finding
from cerberus.detection.finding_store import FindingStore


def _ev(source="proc", type_="new_process", pid=10):
    return Event(source=source, type=type_, host="H", pid=pid,
                 user="u", raw={}, indicators={})


def _finding(pid=10):
    evs = [_ev("proc", "new_process", pid), _ev("net", "outbound_conn", pid)]
    return Finding.from_cluster(host="H", pid=pid, user="u", evidence=evs)


@pytest.fixture
def store(tmp_path: Path) -> FindingStore:
    s = FindingStore(tmp_path / "findings.db")
    s.init_schema()
    return s


def test_init_schema_creates_table(store: FindingStore):
    assert store.table_exists("findings")


def test_insert_and_count(store: FindingStore):
    store.insert(_finding())
    store.insert(_finding(pid=20))
    assert store.count() == 2


def test_fetch_all_roundtrips_fields(store: FindingStore):
    f = _finding()
    store.insert(f)
    rows = store.fetch_all()
    assert len(rows) == 1
    row = rows[0]
    assert row["id"] == f.id
    assert row["host"] == "H"
    assert row["severity"] == int(Severity.MEDIUM)
    assert "proc" in row["sources"] and "net" in row["sources"]


def test_fetch_by_min_severity(store: FindingStore):
    low = Finding.from_cluster(host="H", pid=1, user="u",
                               evidence=[_ev()], severity=Severity.LOW)
    crit = Finding.from_cluster(host="H", pid=2, user="u",
                                evidence=[_ev()], severity=Severity.CRITICAL)
    store.insert(low)
    store.insert(crit)
    high_only = store.fetch_by_min_severity(Severity.HIGH)
    assert len(high_only) == 1
    assert high_only[0]["id"] == crit.id


def test_purge_older_than_days(store: FindingStore):
    from datetime import UTC, datetime, timedelta
    old_evs = [_ev()]
    old = Finding(host="H", pid=1, user="u", evidence=tuple(old_evs),
                  timestamp=datetime.now(UTC) - timedelta(days=100))
    store.insert(old)
    store.insert(_finding())
    deleted = store.purge_older_than(days=90)
    assert deleted == 1
    assert store.count() == 1
