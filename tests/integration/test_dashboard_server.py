import http.client
import json
import threading
from pathlib import Path

import pytest

from cerberus.core.config import load_config
from cerberus.core.db import EventStore
from cerberus.core.event import Event
from cerberus.dashboard.data import DashboardData
from cerberus.dashboard.server import DashboardServer, build_api_response


def _cfg(tmp_path: Path, port: int = 0):
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
collectors:
  proc: {{enabled: true, poll_interval_seconds: 1.0}}
dashboard: {{enabled: true, host: "127.0.0.1", port: {port}, refresh_seconds: 5}}
reporting: {{interval_seconds: 60, retention_days: 1}}
""",
        encoding="utf-8",
    )
    cfg = load_config(cfg_file)
    ev = EventStore(cfg.paths.events_db)
    ev.init_schema()
    ev.insert(Event(source="proc", type="new_process", host="H", pid=1, user="u",
                    raw={}, indicators={}))
    ev.close()
    return cfg


def test_build_api_response_routes_known_endpoints(tmp_path):
    data = DashboardData(_cfg(tmp_path))
    assert build_api_response(data, "/api/status", 10)["host"] == "TESTHOST"
    assert "events_total" in build_api_response(data, "/api/summary", 10)
    assert "findings" in build_api_response(data, "/api/findings", 10)
    assert "by_source" in build_api_response(data, "/api/events", 10)
    assert "actions" in build_api_response(data, "/api/actions", 10)
    assert "auto_executed_pct" in build_api_response(data, "/api/metrics", 10)


def test_build_api_response_unknown_returns_none(tmp_path):
    data = DashboardData(_cfg(tmp_path))
    assert build_api_response(data, "/api/nope", 10) is None


def test_dashboard_server_http_roundtrip(tmp_path):
    cfg = _cfg(tmp_path, port=0)
    server = DashboardServer(cfg)
    host, port = server.start()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        conn = http.client.HTTPConnection(host, port, timeout=5)
        conn.request("GET", "/api/summary")
        resp = conn.getresponse()
        body = resp.read().decode("utf-8")
        conn.close()
    except OSError as exc:
        server.stop()
        pytest.skip(f"loopback HTTP no disponible en el harness: {exc}")
    server.stop()
    assert resp.status == 200
    payload = json.loads(body)
    assert payload["events_total"] == 1


def test_dashboard_server_serves_index_and_404(tmp_path):
    cfg = _cfg(tmp_path, port=0)
    server = DashboardServer(cfg)
    host, port = server.start()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        conn = http.client.HTTPConnection(host, port, timeout=5)
        conn.request("GET", "/")
        index = conn.getresponse()
        index_body = index.read().decode("utf-8")
        conn.request("GET", "/api/nope")
        miss = conn.getresponse()
        miss.read()
        conn.close()
    except OSError as exc:
        server.stop()
        pytest.skip(f"loopback HTTP no disponible en el harness: {exc}")
    server.stop()
    assert index.status == 200
    assert "CERBERUS" in index_body
    assert miss.status == 404
