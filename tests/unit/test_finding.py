from datetime import UTC

from cerberus.core.event import Event, Severity
from cerberus.core.finding import Finding


def _ev(source="proc", type_="new_process", pid=10):
    return Event(
        source=source, type=type_, host="H", pid=pid,
        user="u", raw={}, indicators={"name": "x.exe"},
    )


def test_finding_from_cluster_basic():
    evs = [_ev("proc", "new_process"), _ev("net", "outbound_conn")]
    f = Finding.from_cluster(host="H", pid=10, user="u", evidence=evs)
    assert isinstance(f.id, str) and len(f.id) == 36
    assert f.timestamp.tzinfo == UTC
    assert f.host == "H"
    assert f.pid == 10
    assert f.severity == Severity.MEDIUM           # base heurística M2
    assert f.sources == {"proc", "net"}
    assert f.primary_event_id == evs[0].id         # primer evento del cluster


def test_finding_categories_derived_from_event_types():
    evs = [_ev("fs", "mass_rename"), _ev("proc", "new_process")]
    f = Finding.from_cluster(host="H", pid=5, user="u", evidence=evs)
    assert "mass_rename" in f.categories
    assert "new_process" in f.categories


def test_finding_to_dict_is_json_serializable():
    import json
    evs = [_ev("proc", "new_process"), _ev("net", "outbound_conn")]
    f = Finding.from_cluster(host="H", pid=10, user="u", evidence=evs)
    d = f.to_dict()
    assert d["host"] == "H"
    assert d["severity"] == int(Severity.MEDIUM)
    assert isinstance(d["timestamp"], str)
    assert isinstance(d["evidence"], list) and len(d["evidence"]) == 2
    json.dumps(d)  # no debe lanzar


def test_finding_empty_evidence_raises():
    import pytest
    with pytest.raises(ValueError):
        Finding.from_cluster(host="H", pid=1, user="u", evidence=[])
