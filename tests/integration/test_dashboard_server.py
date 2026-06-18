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


def test_build_api_response_mode_change(tmp_path):
    data = DashboardData(_cfg(tmp_path))
    # Cambio exitoso
    res = build_api_response(data, "/api/mode", 10, mode_value="auto_critical")
    assert res["status"] == "success"
    assert res["mode"] == "auto_critical"
    # Cambio fallido (modo inválido)
    res = build_api_response(data, "/api/mode", 10, mode_value="invalid")
    assert res["status"] == "error"


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


def test_dashboard_server_sets_security_headers(tmp_path):
    """CSP estricto + cabeceras de endurecimiento en respuestas estáticas y de API."""
    cfg = _cfg(tmp_path, port=0)
    server = DashboardServer(cfg)
    host, port = server.start()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        conn = http.client.HTTPConnection(host, port, timeout=5)
        conn.request("GET", "/")
        index = conn.getresponse()
        index.read()
        index_csp = index.getheader("Content-Security-Policy")
        index_ref = index.getheader("Referrer-Policy")
        index_xfo = index.getheader("X-Frame-Options")
        conn.request("GET", "/api/summary")
        api = conn.getresponse()
        api.read()
        api_csp = api.getheader("Content-Security-Policy")
        conn.close()
    except OSError as exc:
        server.stop()
        pytest.skip(f"loopback HTTP no disponible en el harness: {exc}")
    server.stop()
    # CSP deny-by-default, sin 'unsafe-inline'/'unsafe-eval' (defensa XSS real).
    assert index_csp is not None
    assert "default-src 'none'" in index_csp
    assert "script-src 'self'" in index_csp
    assert "frame-ancestors 'none'" in index_csp
    assert "unsafe-inline" not in index_csp
    assert "unsafe-eval" not in index_csp
    assert index_ref == "no-referrer"
    assert index_xfo == "DENY"
    # Cabeceras uniformes: la API también las lleva.
    assert api_csp == index_csp


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


def test_build_api_response_shutdown(tmp_path, monkeypatch):
    data = DashboardData(_cfg(tmp_path))

    # Mockear os.kill para evitar apagar el test runner de pytest
    killed_pid = None
    killed_sig = None
    def mock_kill(pid, sig):
        nonlocal killed_pid, killed_sig
        killed_pid = pid
        killed_sig = sig

    import os
    monkeypatch.setattr(os, "kill", mock_kill)

    # Mockear time.sleep para que la prueba corra instantáneamente
    import time
    monkeypatch.setattr(time, "sleep", lambda x: None)

    # Probar endpoint shutdown
    res = build_api_response(data, "/api/shutdown", 10)
    assert res == {"status": "shutdown_initiated"}

    # Dar tiempo al hilo delayed_shutdown
    time.sleep(0.1)
    import threading
    for t in threading.enumerate():
        if t.name.startswith("Thread") and t.is_alive():
            t.join(timeout=1.0)

    assert killed_pid == os.getpid()
    assert killed_sig == 2  # SIGINT


def test_build_api_response_extra_endpoints(tmp_path):
    data = DashboardData(_cfg(tmp_path))
    # /api/processes
    procs_resp = build_api_response(data, "/api/processes", limit=5)
    assert "processes" in procs_resp
    assert isinstance(procs_resp["processes"], list)

    # /api/sysinfo
    sysinfo_resp = build_api_response(data, "/api/sysinfo", limit=10)
    assert "cpu" in sysinfo_resp


def test_do_get_limit_invalid(tmp_path):
    cfg = _cfg(tmp_path, port=0)
    server = DashboardServer(cfg)
    host, port = server.start()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        conn = http.client.HTTPConnection(host, port, timeout=5)
        # Probamos limit inválido en Query string (ValueError)
        conn.request("GET", "/api/findings?limit=notanumber")
        resp = conn.getcall = conn.getresponse()
        body = resp.read().decode("utf-8")
        conn.close()
    except OSError as exc:
        server.stop()
        pytest.skip(f"loopback HTTP no disponible: {exc}")
    server.stop()
    assert resp.status == 200  # Debe responder usando el limit por defecto


def test_do_get_static_os_error(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, port=0)
    server = DashboardServer(cfg)
    host, port = server.start()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    from pathlib import Path
    orig_read_bytes = Path.read_bytes
    def mock_read_bytes(self):
        if self.name == "index.html":
            raise OSError("simulated file read error")
        return orig_read_bytes(self)

    monkeypatch.setattr(Path, "read_bytes", mock_read_bytes)

    try:
        conn = http.client.HTTPConnection(host, port, timeout=5)
        conn.request("GET", "/")
        resp = conn.getresponse()
        body = resp.read().decode("utf-8")
        conn.close()
    except OSError as exc:
        server.stop()
        pytest.skip(f"loopback HTTP no disponible: {exc}")
    server.stop()
    assert resp.status == 404
    assert "static file not found" in body


def test_do_get_api_internal_error(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, port=0)
    server = DashboardServer(cfg)
    host, port = server.start()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    # Hacemos que build_api_response lance excepción
    import cerberus.dashboard.server
    monkeypatch.setattr(cerberus.dashboard.server, "build_api_response", lambda *a, **k: 1 / 0)

    try:
        conn = http.client.HTTPConnection(host, port, timeout=5)
        conn.request("GET", "/api/status")
        resp = conn.getcall = conn.getresponse()
        body = resp.read().decode("utf-8")
        conn.close()
    except OSError as exc:
        server.stop()
        pytest.skip(f"loopback: {exc}")
    server.stop()
    assert resp.status == 500
    assert "internal error" in body


def test_do_post_generate_report_success(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, port=0)
    server = DashboardServer(cfg)
    host, port = server.start()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    def mock_generate(*args, **kwargs):
        return "informes/test_report.docx"
    monkeypatch.setattr(DashboardData, "generate_docx_report", mock_generate)

    try:
        conn = http.client.HTTPConnection(host, port, timeout=5)
        conn.request("POST", "/api/generate_report")
        resp = conn.getresponse()
        body = resp.read().decode("utf-8")
        conn.close()
    except OSError as exc:
        server.stop()
        pytest.skip(f"loopback: {exc}")
    server.stop()
    assert resp.status == 200
    payload = json.loads(body)
    assert payload["status"] == "success"
    assert payload["file"] == "informes/test_report.docx"


def test_do_post_generate_report_fail(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, port=0)
    server = DashboardServer(cfg)
    host, port = server.start()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    def mock_generate(*args, **kwargs):
        return None
    monkeypatch.setattr(DashboardData, "generate_docx_report", mock_generate)

    try:
        conn = http.client.HTTPConnection(host, port, timeout=5)
        conn.request("POST", "/api/generate_report")
        resp = conn.getresponse()
        body = resp.read().decode("utf-8")
        conn.close()
    except OSError as exc:
        server.stop()
        pytest.skip(f"loopback: {exc}")
    server.stop()
    assert resp.status == 500
    assert "docx library missing" in body


def test_do_post_generate_report_exception(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, port=0)
    server = DashboardServer(cfg)
    host, port = server.start()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    def mock_generate(*args, **kwargs):
        raise RuntimeError("catastrophic report error")
    monkeypatch.setattr(DashboardData, "generate_docx_report", mock_generate)

    try:
        conn = http.client.HTTPConnection(host, port, timeout=5)
        conn.request("POST", "/api/generate_report")
        resp = conn.getresponse()
        body = resp.read().decode("utf-8")
        conn.close()
    except OSError as exc:
        server.stop()
        pytest.skip(f"loopback: {exc}")
    server.stop()
    assert resp.status == 500
    assert "catastrophic report error" in body


def test_do_post_method_not_allowed(tmp_path):
    cfg = _cfg(tmp_path, port=0)
    server = DashboardServer(cfg)
    host, port = server.start()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        conn = http.client.HTTPConnection(host, port, timeout=5)
        conn.request("POST", "/api/other")
        resp = conn.getresponse()
        body = resp.read().decode("utf-8")
        conn.close()
    except OSError as exc:
        server.stop()
        pytest.skip(f"loopback: {exc}")
    server.stop()
    assert resp.status == 405
    assert "method not allowed" in body


def test_serve_forever_starts_server_if_none(tmp_path):
    cfg = _cfg(tmp_path, port=0)
    server = DashboardServer(cfg)
    assert server._server is None
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    import time
    time.sleep(0.5)

    assert server._server is not None
    host, port = server._server.server_address[0], server._server.server_address[1]

    try:
        conn = http.client.HTTPConnection(host, port, timeout=5)
        conn.request("GET", "/api/status")
        resp = conn.getresponse()
        resp.read()
        conn.close()
    except OSError as exc:
        server.stop()
        pytest.skip(f"loopback: {exc}")
    server.stop()
    assert resp.status == 200


def test_do_get_mode_value_query_param(tmp_path):
    cfg = _cfg(tmp_path, port=0)
    server = DashboardServer(cfg)
    host, port = server.start()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        conn = http.client.HTTPConnection(host, port, timeout=5)
        conn.request("GET", "/api/mode?value=monitor")
        resp = conn.getresponse()
        body = resp.read().decode("utf-8")
        conn.close()
    except OSError as exc:
        server.stop()
        pytest.skip(f"loopback HTTP no disponible: {exc}")
    server.stop()
    assert resp.status == 200
    payload = json.loads(body)
    assert payload["status"] == "success"
    assert payload["mode"] == "monitor"


def test_do_get_unknown_path_not_found(tmp_path):
    cfg = _cfg(tmp_path, port=0)
    server = DashboardServer(cfg)
    host, port = server.start()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        conn = http.client.HTTPConnection(host, port, timeout=5)
        conn.request("GET", "/foo/bar")
        resp = conn.getcall = conn.getresponse()
        body = resp.read().decode("utf-8")
        conn.close()
    except OSError as exc:
        server.stop()
        pytest.skip(f"loopback HTTP no disponible: {exc}")
    server.stop()
    assert resp.status == 404
    payload = json.loads(body)
    assert payload["error"] == "not found"


