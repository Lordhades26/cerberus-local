from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any, Protocol

from cerberus.core.logger import get_logger

_log = get_logger("cerberus.service.ipc")

Handler = Callable[[dict[str, Any]], dict[str, Any]]


class IpcDispatcher:
    """Mapea command -> handler. Puro respecto al transporte; atrapa excepciones."""

    def __init__(self) -> None:
        self._handlers: dict[str, Handler] = {}

    def register(self, command: str, handler: Handler) -> None:
        self._handlers[command] = handler

    def handle(self, request: dict[str, Any]) -> dict[str, Any]:
        command = str(request.get("command", ""))
        args = request.get("args", {}) or {}
        handler = self._handlers.get(command)
        if handler is None:
            return {"ok": False, "data": None, "error": f"unknown command: {command}"}
        try:
            data = handler(args)
            return {"ok": True, "data": data, "error": None}
        except Exception as exc:
            _log.error("ipc_handler_error", extra={"command": command, "error": str(exc)})
            return {"ok": False, "data": None, "error": str(exc)}


class Transport(Protocol):
    def bind(self, on_request: Callable[[str], str]) -> None: ...
    def round_trip(self, raw_request: str) -> str: ...
    def stop(self) -> None: ...


class InMemoryTransport:
    """Transporte en proceso para tests: el cliente invoca el handler del servidor directo."""

    def __init__(self) -> None:
        self._on_request: Callable[[str], str] | None = None

    def bind(self, on_request: Callable[[str], str]) -> None:
        self._on_request = on_request

    def round_trip(self, raw_request: str) -> str:
        if self._on_request is None:
            raise RuntimeError("transport not bound")
        return self._on_request(raw_request)

    def stop(self) -> None:
        self._on_request = None


class IpcServer:
    def __init__(self, transport: Transport, dispatcher: IpcDispatcher) -> None:
        self._transport = transport
        self._dispatcher = dispatcher

    def _on_request(self, raw: str) -> str:
        try:
            request = json.loads(raw)
        except json.JSONDecodeError:
            return json.dumps({"ok": False, "data": None, "error": "invalid json"})
        return json.dumps(self._dispatcher.handle(request))

    def start(self) -> None:
        self._transport.bind(self._on_request)

    def stop(self) -> None:
        self._transport.stop()


class IpcClient:
    def __init__(self, transport: Transport) -> None:
        self._transport = transport

    def request(self, command: str, **args: Any) -> dict[str, Any]:
        raw = json.dumps({"command": command, "args": args})
        resp = self._transport.round_trip(raw)
        return dict(json.loads(resp))
