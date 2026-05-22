from __future__ import annotations

from collections.abc import Callable
from typing import Any

from cerberus.core.logger import get_logger

_log = get_logger("cerberus.service.named_pipe")


class IpcUnavailable(Exception):
    """El transporte named-pipe no está disponible (sin pywin32 / no-Windows)."""


def _load_pywin32() -> Any | None:
    try:
        import win32file
        import win32pipe
    except Exception:
        return None
    return (win32pipe, win32file)


class NamedPipeTransport:
    """Transporte named-pipe (pywin32). Lazy + degradación.

    La E/S real con el pipe se ejercita en M6 de campo (Windows + Service).
    Aquí garantizamos la degradación segura cuando pywin32 no está disponible.
    """

    def __init__(self, pipe_name: str) -> None:
        self._pipe_name = pipe_name
        self._win = _load_pywin32()
        self._on_request: Callable[[str], str] | None = None

    def available(self) -> bool:
        return self._win is not None

    def bind(self, on_request: Callable[[str], str]) -> None:
        self._on_request = on_request
        if not self.available():
            _log.info("ipc_unavailable", extra={"pipe": self._pipe_name})

    def round_trip(self, raw_request: str) -> str:
        if not self.available():
            raise IpcUnavailable("pywin32 no disponible")
        return self._client_round_trip(raw_request)  # pragma: no cover (M6 field)

    def _client_round_trip(self, raw_request: str) -> str:  # pragma: no cover
        assert self._win is not None
        win32pipe, win32file = self._win
        handle = win32file.CreateFile(
            self._pipe_name, win32file.GENERIC_READ | win32file.GENERIC_WRITE,
            0, None, win32file.OPEN_EXISTING, 0, None,
        )
        win32file.WriteFile(handle, raw_request.encode("utf-8"))
        _rc, data = win32file.ReadFile(handle, 65536)
        win32file.CloseHandle(handle)
        return bytes(data).decode("utf-8")

    def stop(self) -> None:
        self._on_request = None
