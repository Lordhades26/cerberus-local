from datetime import UTC

from cerberus.core.event import Event, Severity


def test_event_creates_with_required_fields():
    ev = Event(
        source="proc",
        type="new_process",
        host="DESKTOP-X",
        pid=1234,
        user="DESKTOP-X\\fabian",
        raw={"name": "notepad.exe"},
        indicators={"binary": "C:\\Windows\\notepad.exe"},
    )
    assert ev.source == "proc"
    assert ev.type == "new_process"
    assert isinstance(ev.id, str) and len(ev.id) == 36  # uuid4
    assert ev.timestamp.tzinfo == UTC


def test_event_id_unique():
    a = Event(source="proc", type="x", host="h", pid=None, user=None, raw={}, indicators={})
    b = Event(source="proc", type="x", host="h", pid=None, user=None, raw={}, indicators={})
    assert a.id != b.id


def test_event_to_dict_roundtrip():
    ev = Event(
        source="proc", type="new_process", host="h", pid=1,
        user=None, raw={"k": "v"}, indicators={},
    )
    d = ev.to_dict()
    assert d["source"] == "proc"
    assert d["raw"] == {"k": "v"}
    assert isinstance(d["timestamp"], str)  # ISO-8601


def test_event_invalid_source_raises():
    import pytest
    with pytest.raises(ValueError):
        Event(source="invalid", type="x", host="h", pid=None, user=None, raw={}, indicators={})


def test_severity_ordering():
    assert Severity.INFO < Severity.LOW < Severity.MEDIUM < Severity.HIGH < Severity.CRITICAL
