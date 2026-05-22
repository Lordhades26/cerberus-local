from __future__ import annotations

import subprocess
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


class Win32ServiceController:
    """Controla el Windows Service vía sc.exe. Builders/parser puros (testeables);
    la ejecución real (subprocess, requiere admin) se valida en campo (M6)."""

    def __init__(self, service_name: str, python_exe: str, script: str) -> None:
        self._name = service_name
        self._python = python_exe
        self._script = script

    def build_install_argv(self) -> list[str]:
        bin_path = f'"{self._python}" "{self._script}"'
        return ["sc", "create", self._name, "binPath=", bin_path, "start=", "auto"]

    def build_start_argv(self) -> list[str]:
        return ["sc", "start", self._name]

    def build_stop_argv(self) -> list[str]:
        return ["sc", "stop", self._name]

    def build_status_argv(self) -> list[str]:
        return ["sc", "query", self._name]

    @staticmethod
    def parse_status(sc_query_output: str) -> str:
        text = sc_query_output.upper()
        if "RUNNING" in text:
            return "running"
        if "STOPPED" in text:
            return "stopped"
        return "unknown"

    def install(self) -> None:  # pragma: no cover (admin/SCM, M6 field)
        subprocess.run(self.build_install_argv(), shell=False, check=False)

    def start(self) -> None:  # pragma: no cover
        subprocess.run(self.build_start_argv(), shell=False, check=False)

    def stop(self) -> None:  # pragma: no cover
        subprocess.run(self.build_stop_argv(), shell=False, check=False)

    def status(self) -> str:  # pragma: no cover
        proc = subprocess.run(self.build_status_argv(), shell=False,
                              capture_output=True, text=True, check=False)
        return self.parse_status(proc.stdout)
