#!/usr/bin/env python3
"""CERBERUS-LOCAL Windows Service entry point (M6 — validar en campo).

Requiere pywin32 + privilegios admin. Registrar con:
    python cerberus_service.py install
    python cerberus_service.py start
o vía sc.exe / packaging/install_service.ps1 (ver docs/M6_FIELD_GUIDE.md).
NO se importa en la suite de tests (depende del SCM de Windows).
"""
from __future__ import annotations

import asyncio

try:  # pragma: no cover (pywin32 + SCM de Windows, validar en campo)
    import win32serviceutil

    from cerberus.cli.commands import _run_loop, resolve_config

    class CerberusService(win32serviceutil.ServiceFramework):  # type: ignore[misc]
        _svc_name_ = "Cerberus"
        _svc_display_name_ = "CERBERUS-LOCAL EDR"
        _svc_description_ = "EDR híbrido Windows con IA local (defensivo)."

        def __init__(self, args: object) -> None:
            super().__init__(args)
            self._cfg = resolve_config(None)

        def SvcStop(self) -> None:
            # M6: señalar el stop_event del loop vía killswitch/IPC y reportar stop.
            self.ReportServiceStatus(win32serviceutil.win32service.SERVICE_STOP_PENDING)

        def SvcDoRun(self) -> None:
            asyncio.run(_run_loop(self._cfg))

    if __name__ == "__main__":
        win32serviceutil.HandleCommandLine(CerberusService)

except ImportError:  # pragma: no cover
    if __name__ == "__main__":
        print("El Windows Service requiere pywin32 + Windows. "
              "Ver docs/M6_FIELD_GUIDE.md.")
