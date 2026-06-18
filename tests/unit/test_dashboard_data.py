import dataclasses
from pathlib import Path

import pytest

from cerberus.core.config import load_config
from cerberus.core.db import EventStore
from cerberus.core.event import Event, Severity
from cerberus.core.finding import Finding
from cerberus.dashboard.data import DashboardData
from cerberus.detection.finding_store import FindingStore
from cerberus.response.action_store import ActionStore
from cerberus.response.actions import Action, ActionResult


def _cfg(tmp_path: Path):
    cfg_file = tmp_path / "c.yml"
    cfg_file.write_text(
        f"""
mode: dry_run
host_name: TESTHOST
paths:
  data_dir: {tmp_path.as_posix()}
  events_db: {(tmp_path / 'events.db').as_posix()}
  findings_db: {(tmp_path / 'findings.db').as_posix()}
  actions_db: {(tmp_path / 'actions.db').as_posix()}
  reports_dir: {(tmp_path / 'r').as_posix()}
  log_file: {(tmp_path / 'l.log').as_posix()}
  state_file: {(tmp_path / 'state.json').as_posix()}
collectors:
  proc: {{enabled: true, poll_interval_seconds: 1.0}}
  net:
    enabled: true
    poll_interval_seconds: 2.0
    beaconing_window_seconds: 60
    beaconing_min_connections: 10
  fs: {{enabled: false}}
  evt: {{enabled: false}}
reporting: {{interval_seconds: 60, retention_days: 1}}
""",
        encoding="utf-8",
    )
    return load_config(cfg_file)


def _seed(cfg):
    ev = EventStore(cfg.paths.events_db)
    ev.init_schema()
    for src, typ in [("proc", "new_process"), ("proc", "new_process"),
                     ("net", "outbound_conn"), ("fs", "mass_rename")]:
        ev.insert(Event(source=src, type=typ, host="H", pid=10, user="u",
                        raw={}, indicators={"remote_ip": "9.9.9.9"}))
    ev.close()

    fs = FindingStore(cfg.paths.findings_db)
    fs.init_schema()
    base = Finding.from_cluster(
        host="H", pid=4892, user="u",
        evidence=[Event(source="fs", type="mass_rename", host="H", pid=4892, user="u",
                        raw={}, indicators={})])
    enriched = dataclasses.replace(
        base, severity=Severity.CRITICAL, severity_base=Severity.CRITICAL,
        rule_ids=("ransomware_pattern_v1",),
        ai_triage={"family_guess": "lockbit", "confidence": 0.8})
    fs.insert(enriched)
    fs.close()

    ac = ActionStore(cfg.paths.actions_db)
    ac.init_schema()
    a = Action(type="kill_pid", params={"pid": 4892})
    ac.insert(ActionResult(action=a, executed=True, success=True, output="ok",
                           command="taskkill", reverted_command=None, reason="authorized"),
              finding_id="F1", policy_id="ransomware_response", mode="auto_critical")
    ac.insert(ActionResult(action=a, executed=False, success=False, output="",
                           command="taskkill", reverted_command=None, reason="dry_run"),
              finding_id="F2", policy_id="ransomware_response", mode="dry_run")
    ac.close()


@pytest.fixture
def data(tmp_path):
    cfg = _cfg(tmp_path)
    _seed(cfg)
    return DashboardData(cfg)


def test_status(data):
    s = data.status()
    assert s["host"] == "TESTHOST"
    assert s["mode"] == "dry_run"
    assert s["killswitch_active"] is False
    assert s["collectors"]["proc"] is True and s["collectors"]["fs"] is False


def test_summary_counts_and_severity(data):
    s = data.summary()
    assert s["events_total"] == 4
    assert s["findings_total"] == 1
    assert s["findings_by_severity"]["CRITICAL"] == 1
    assert s["actions_total"] == 2
    assert s["actions_executed"] == 1


def test_findings_payload(data):
    items = data.findings(limit=10)
    assert len(items) == 1
    assert items[0]["severity"] == "CRITICAL"
    assert "ransomware_pattern_v1" in items[0]["rule_ids"]
    assert items[0]["ai_family"] == "lockbit"


def test_events_breakdown(data):
    e = data.events()
    assert e["by_source"]["proc"] == 2
    assert e["by_source"]["net"] == 1
    assert isinstance(e["timeline"], list) and e["timeline"]


def test_actions_payload(data):
    items = data.actions(limit=10)
    assert len(items) == 2
    assert {a["action_type"] for a in items} == {"kill_pid"}
    assert any(a["executed"] for a in items)


def test_metrics(data):
    m = data.metrics()
    assert m["findings_total"] == 1
    assert m["distinct_rules"] == 1
    assert m["actions_total"] == 2
    assert m["auto_executed_pct"] == 50.0
    assert m["findings_with_ai"] == 1


def test_sysinfo(data):
    info = data.sysinfo()
    assert isinstance(info, dict)
    for key in ["cpu", "ram", "gpu", "disk", "temp", "fan"]:
        assert key in info
        assert isinstance(info[key], (int, float))


def test_set_mode(data):
    # Probar modos válidos
    assert data.set_mode("monitor") is True
    # Probar modo inválido
    assert data.set_mode("invalid_mode") is False


def test_processes(data):
    procs = data.processes(limit=5)
    assert isinstance(procs, list)
    assert len(procs) <= 5
    for p in procs:
        assert "pid" in p
        assert "name" in p
        assert "cpu_percent" in p
        assert isinstance(p["cpu_percent"], float)


def test_processes_with_exceptions(data, monkeypatch):
    import psutil
    class MockProcess:
        def __init__(self, pid):
            self.pid = pid
            self.info = {'pid': pid, 'name': 'test', 'cpu_percent': 10.0}

    def mock_process_iter(attrs=None):
        # Uno normal, uno que levanta NoSuchProcess, uno que levanta AccessDenied
        # Nota: iteraremos sobre esto, simulamos una propiedad o comportamiento del iterador
        class BadIter:
            def __iter__(self):
                yield MockProcess(123)
                # Simulamos excepciones al acceder a .info o al iterar
                # Pero en data.py el try/except está dentro del loop al acceder a p.info
                p_bad1 = MockProcess(999)
                del p_bad1.info  # Acceder levantará KeyError o AttributeError, pero podemos usar un property para lanzar excepciones específicas
                yield p_bad1
        return BadIter()

    # En su lugar, usemos propiedades reales que lancen psutil.NoSuchProcess
    class MockBadProcess1:
        def __init__(self, pid):
            self.pid = pid
        @property
        def info(self):
            raise psutil.NoSuchProcess(self.pid)

    class MockBadProcess2:
        def __init__(self, pid):
            self.pid = pid
        @property
        def info(self):
            raise psutil.AccessDenied(self.pid)

    class MockGoodProcess:
        def __init__(self, pid):
            self.pid = pid
            self.info = {'pid': pid, 'name': 'test', 'cpu_percent': 10.0}

    def mock_process_iter_v2(attrs=None):
        return [MockGoodProcess(123), MockBadProcess1(999), MockBadProcess2(998)]

    monkeypatch.setattr(psutil, "process_iter", mock_process_iter_v2)
    procs = data.processes(limit=5)
    assert len(procs) == 1
    assert procs[0]["pid"] == 123


def test_hour_bucket_value_error():
    from cerberus.dashboard.data import _hour_bucket
    assert _hour_bucket("invalid-date-string") == "unknown"


def test_generate_docx_report(data):
    import os
    filepath = data.generate_docx_report()
    assert filepath is not None
    assert os.path.exists(filepath)
    # Cleanup del reporte generado en tests
    try:
        os.remove(filepath)
    except Exception:
        pass


def test_generate_docx_report_import_error(data, monkeypatch):
    import sys
    # Forzar ImportError al importar docx
    monkeypatch.setitem(sys.modules, "docx", None)
    filepath = data.generate_docx_report()
    assert filepath is None


def test_sysinfo_exceptions(data, monkeypatch):
    import psutil
    def mock_cpu_percent(interval=None):
        raise RuntimeError("simulated error")
    monkeypatch.setattr(psutil, "cpu_percent", mock_cpu_percent)
    info = data.sysinfo()
    assert info["cpu"] == 0.0
    assert info["ram"] == 0.0
    assert info["disk"] == 0.0


def test_sysinfo_disk_fallback(data, monkeypatch):
    import psutil
    def mock_disk_usage(path):
        if "C:" in path:
            raise RuntimeError("Windows drive fail")
        class MockDisk:
            percent = 45.6
        return MockDisk()
    monkeypatch.setattr(psutil, "disk_usage", mock_disk_usage)
    info = data.sysinfo()
    assert info["disk"] == 45.6

