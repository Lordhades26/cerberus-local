from __future__ import annotations

from typing import Protocol


class ServiceController(Protocol):
    def install(self) -> None: ...
    def start(self) -> None: ...
    def stop(self) -> None: ...
    def status(self) -> str: ...


class ForegroundServiceController:
    """Controlador de servicio en primer plano (sin pywin32). El Windows Service
    real (`win32serviceutil.ServiceFramework`) se implementa en M6 de campo."""

    def __init__(self) -> None:
        self._running = False

    def install(self) -> None:
        # No-op en foreground; la instalación real (sc create / pywin32) es M6.
        return None

    def start(self) -> None:
        self._running = True

    def stop(self) -> None:
        self._running = False

    def status(self) -> str:
        return "running" if self._running else "stopped"
