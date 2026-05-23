from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from cerberus.core.config import CerberusConfig
from cerberus.core.logger import get_logger
from cerberus.dashboard.data import DashboardData

_log = get_logger("cerberus.dashboard.server")

_STATIC_DIR = Path(__file__).resolve().parent.parent.parent / "dashboard"
# Allowlist de archivos estáticos (evita path traversal).
_STATIC_FILES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/styles.css": ("styles.css", "text/css; charset=utf-8"),
    "/app.js": ("app.js", "application/javascript; charset=utf-8"),
}


def build_api_response(data: DashboardData, path: str, limit: int) -> dict[str, Any] | None:
    """Devuelve el dict JSON para una ruta /api/* o None si no existe (puro, testeable)."""
    if path == "/api/status":
        return data.status()
    if path == "/api/summary":
        return data.summary()
    if path == "/api/findings":
        return {"findings": data.findings(limit=limit)}
    if path == "/api/events":
        return data.events()
    if path == "/api/actions":
        return {"actions": data.actions(limit=limit)}
    if path == "/api/metrics":
        return data.metrics()
    return None


class _Handler(BaseHTTPRequestHandler):
    data: DashboardData  # inyectado por make_server

    def log_message(self, *_args: object) -> None:  # silenciar logging a stderr
        return

    def _send(self, code: int, body: bytes, content_type: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, code: int, payload: dict[str, Any]) -> None:
        self._send(code, json.dumps(payload).encode("utf-8"), "application/json; charset=utf-8")

    def do_GET(self) -> None:
        raw_path = self.path.split("?", 1)[0]
        query = self.path.split("?", 1)[1] if "?" in self.path else ""
        limit = 10
        for part in query.split("&"):
            if part.startswith("limit="):
                try:
                    limit = max(1, min(500, int(part[6:])))
                except ValueError:
                    pass

        if raw_path in _STATIC_FILES:
            fname, ctype = _STATIC_FILES[raw_path]
            fpath = _STATIC_DIR / fname
            try:
                self._send(200, fpath.read_bytes(), ctype)
            except OSError:
                self._send_json(404, {"error": "static file not found"})
            return

        if raw_path.startswith("/api/"):
            try:
                payload = build_api_response(self.data, raw_path, limit)
            except Exception as exc:  # un error de lectura no debe tumbar el server
                _log.error("dashboard_api_error", extra={"path": raw_path, "error": str(exc)})
                self._send_json(500, {"error": "internal error"})
                return
            if payload is None:
                self._send_json(404, {"error": f"unknown endpoint {raw_path}"})
            else:
                self._send_json(200, payload)
            return

        self._send_json(404, {"error": "not found"})

    def do_POST(self) -> None:  # dashboard es read-only
        self._send_json(405, {"error": "method not allowed (read-only dashboard)"})


def make_server(cfg: CerberusConfig) -> ThreadingHTTPServer:
    data = DashboardData(cfg)
    handler = type("_BoundHandler", (_Handler,), {"data": data})
    server = ThreadingHTTPServer((cfg.dashboard.host, cfg.dashboard.port), handler)
    return server


class DashboardServer:
    """Servidor HTTP read-only del dashboard. Bind por defecto a 127.0.0.1 (solo local)."""

    def __init__(self, cfg: CerberusConfig) -> None:
        self._cfg = cfg
        self._server: ThreadingHTTPServer | None = None

    def start(self) -> tuple[str, int]:
        self._server = make_server(self._cfg)
        host, port = self._server.server_address[0], self._server.server_address[1]
        _log.info("dashboard_listening", extra={"host": str(host), "port": port})
        return str(host), int(port)

    def serve_forever(self) -> None:
        if self._server is None:
            self.start()
        assert self._server is not None
        self._server.serve_forever()

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
