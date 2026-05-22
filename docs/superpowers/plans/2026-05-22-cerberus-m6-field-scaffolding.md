# CERBERUS-LOCAL · Plan M6 — Andamiaje de campo (código escribible aquí)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development o superpowers:executing-plans. Steps usan checkbox (`- [ ]`).

**Goal:** Escribir el **código y artefactos de M6 que SÍ son escribibles/testeables en el entorno de desarrollo**, dejando seams limpios para la integración real de Windows (que se ejecuta en campo). Concretamente: `PySharkProbe`/`dns_query` para NetCollector (source inyectable, degradación), `Win32ServiceController` (builders de `sc.exe` puros + parser de `sc query`), el `serve()` del named pipe con SDDL de seguridad puro, el scaffold `cerberus_service.py` (`win32serviceutil.ServiceFramework`), y los artefactos de empaquetado WiX (`.wxs` + `.ps1`).

**Architecture:** 100% heurístico — 0 LLM nuevo. **Honestidad de validación:** toda E/S real de SO (captura Npcap real, llamadas `sc.exe`, I/O del named pipe, registro del Service, build `.msi`) queda **`# pragma: no cover`** y se valida **en campo** (host Windows real). Lo testeable son los *seams* puros: source DNS inyectable (mock), argv builders, parser de `sc query`, SDDL del pipe, degradación sin pywin32/Npcap. Mismo patrón que la ruta `win32evtlog`/`SystemExecutor.build` de M3/M4.

**Tech Stack:** Python 3.11+, `pyshark` (opcional, extra `windows`/`capture`), `pywin32` (opcional), `subprocess`, `pytest`, `ruff`, `mypy`. WiX Toolset (build de campo). **Sin nuevas deps runtime obligatorias.**

**Reference:** `docs/M6_FIELD_GUIDE.md` (runbook de los pasos manuales) + spec §4.2/§4.11/§7.6/§9.

---

## Scope

**Escribible aquí (este plan, TDD donde hay seam):** PySharkProbe + dns_query, regla suspicious_dns, Win32ServiceController (builders/parser), named-pipe serve()+SDDL, cerberus_service.py scaffold, packaging WiX.

**Solo campo (NO en este plan — runbook `docs/M6_FIELD_GUIDE.md`):** instalar Npcap, registrar el Service real, build/firma del `.msi`, redteam en VM, ACLs/TakeOwnership, baseline 24h.

---

## Pre-flight
- [ ] `git checkout master && git status` → limpio, HEAD `e2dd978`, tag `v0.5.0-m5`.
- [ ] `.venv/Scripts/python -m pytest -p no:cacheprovider --no-cov -q --ignore=tests/integration/test_ollama_live.py > t.txt 2>&1; tail -2 t.txt; rm t.txt` → 181 passed.
- [ ] `git checkout -b m6/field-scaffolding`.

> **Harness:** redirigir a archivo temporal y `tail` para comandos largos.

---

## Task 1: Bump 0.6.0 + config `collectors.net.dns_capture`

**Files:** `cerberus/__init__.py`, `pyproject.toml`, `config/cerberus.default.yml`, `cerberus/core/config.py`, `tests/unit/test_config.py`, `tests/unit/test_cli_commands.py`

- [ ] **Step 1:** version `0.6.0` en `__init__.py` y `pyproject.toml`.
- [ ] **Step 2: Tests** — añadir a `tests/unit/test_config.py`:
```python
def test_net_dns_capture_default_false(tmp_path):
    cfg_file = tmp_path / "c.yml"
    cfg_file.write_text(
        """
mode: dry_run
host_name: null
paths: {data_dir: /tmp/c, events_db: /tmp/c/e.db, findings_db: /tmp/c/f.db, reports_dir: /tmp/c/r, log_file: /tmp/c/l.log}
collectors:
  proc: {enabled: true, poll_interval_seconds: 1.0}
  net: {enabled: true, poll_interval_seconds: 2.0, beaconing_window_seconds: 60, beaconing_min_connections: 10}
reporting: {interval_seconds: 60, retention_days: 1}
""",
        encoding="utf-8",
    )
    from cerberus.core.config import load_config
    cfg = load_config(cfg_file)
    assert cfg.collectors.net.dns_capture is False


def test_net_dns_capture_true(tmp_path):
    cfg_file = tmp_path / "c.yml"
    cfg_file.write_text(
        """
mode: dry_run
host_name: null
paths: {data_dir: /tmp/c, events_db: /tmp/c/e.db, findings_db: /tmp/c/f.db, reports_dir: /tmp/c/r, log_file: /tmp/c/l.log}
collectors:
  proc: {enabled: true, poll_interval_seconds: 1.0}
  net: {enabled: true, poll_interval_seconds: 2.0, beaconing_window_seconds: 60, beaconing_min_connections: 10, dns_capture: true}
reporting: {interval_seconds: 60, retention_days: 1}
""",
        encoding="utf-8",
    )
    from cerberus.core.config import load_config
    cfg = load_config(cfg_file)
    assert cfg.collectors.net.dns_capture is True
```
- [ ] **Step 3:** `cerberus/core/config.py` — `NetCollectorConfig` gana `dns_capture: bool`; `_net` lo lee con `bool(raw.get("dns_capture", False))`.
- [ ] **Step 4:** `config/cerberus.default.yml` — bajo `collectors.net:` añadir `dns_capture: false   # requiere Npcap (M6 campo)`.
- [ ] **Step 5:** `tests/unit/test_cli_commands.py::_make_cfg` — `NetCollectorConfig(..., dns_capture=False)`.
- [ ] **Step 6:** Verificar version 0.6.0 + config/cli tests + full suite (redirect). Commit:
```
git add -A && git commit -m "chore(m6): bump 0.6.0; add net.dns_capture config flag"
```
Trailer Co-Authored-By.

---

## Task 2: `DnsRecord` + `PySharkProbe` + NetCollector `dns_query`

**Files:** `cerberus/collectors/net.py`, `tests/unit/test_net_collector.py`

- [ ] **Step 1: Tests** — añadir a `tests/unit/test_net_collector.py`:
```python
@pytest.mark.asyncio
async def test_net_collector_emits_dns_query_from_injected_source():
    from cerberus.collectors.net import DnsRecord

    class _FakeDnsSource:
        def __init__(self):
            self._batches = iter([[DnsRecord(query_name="evil.example", query_type="A",
                                             remote_ip="9.9.9.9")]])

        def poll(self):
            try:
                return next(self._batches)
            except StopIteration:
                return []

    def fake_net_connections(kind="inet"):
        return []

    bus = EventBus()
    c = NetCollector(host="H", poll_interval_seconds=0.02,
                     beaconing_window_seconds=60, beaconing_min_connections=10,
                     dns_source=_FakeDnsSource())
    with patch("cerberus.collectors.net.psutil.net_connections",
               side_effect=fake_net_connections):
        task = asyncio.create_task(c.start(bus))
        received = await _collect_events(bus, target_count=1, wait_secs=1.0)
        await c.stop()
        task.cancel()
    dns = [e for e in received if e.type == "dns_query"]
    assert len(dns) >= 1
    assert dns[0].indicators["query_name"] == "evil.example"
    assert dns[0].indicators["remote_ip"] == "9.9.9.9"


@pytest.mark.asyncio
async def test_net_collector_no_dns_source_is_silent():
    def fake_net_connections(kind="inet"):
        return []
    bus = EventBus()
    c = NetCollector(host="H", poll_interval_seconds=0.02, dns_source="unavailable")
    with patch("cerberus.collectors.net.psutil.net_connections",
               side_effect=fake_net_connections):
        task = asyncio.create_task(c.start(bus))
        received = await _collect_events(bus, target_count=1, wait_secs=0.3)
        await c.stop()
        task.cancel()
    assert [e for e in received if e.type == "dns_query"] == []
```
- [ ] **Step 2:** Editar `cerberus/collectors/net.py`:

Añadir tras los imports:
```python
from dataclasses import dataclass
from typing import Protocol, runtime_checkable
```
Añadir el dataclass + protocol + source real (tras `_is_routable`):
```python
@dataclass(frozen=True)
class DnsRecord:
    query_name: str
    query_type: str
    remote_ip: str | None = None


@runtime_checkable
class DnsSource(Protocol):
    def poll(self) -> list[DnsRecord]: ...


def _build_pyshark_source(interface: str | None = None) -> DnsSource | None:  # pragma: no cover
    try:
        import pyshark  # noqa: F401
    except Exception:
        return None
    return _PySharkDnsSource(interface)


class _PySharkDnsSource:  # pragma: no cover (requiere Npcap; validar en campo)
    def __init__(self, interface: str | None) -> None:
        import pyshark
        self._cap = pyshark.LiveCapture(interface=interface, bpf_filter="udp port 53")

    def poll(self) -> list[DnsRecord]:
        out: list[DnsRecord] = []
        for pkt in self._cap.sniff_continuously(packet_count=10):
            try:
                dns = pkt.dns
                out.append(DnsRecord(query_name=str(dns.qry_name),
                                     query_type=str(getattr(dns, "qry_type", "")),
                                     remote_ip=str(getattr(pkt.ip, "dst", "")) or None))
            except AttributeError:
                continue
        return out
```
`NetCollector.__init__` gana `dns_source: DnsSource | str | None = None`; guardar `self._dns_source_arg = dns_source`, `self._dns_source: DnsSource | None = None`. Añadir resolver (como EvtCollector):
```python
    def _resolve_dns_source(self) -> DnsSource | None:
        if self._dns_source_arg == "unavailable":
            return None
        if self._dns_source_arg is not None and not isinstance(self._dns_source_arg, str):
            return self._dns_source_arg
        return _build_pyshark_source()
```
En `start()`, antes del while: `self._dns_source = self._resolve_dns_source()`. En `_tick`, tras procesar conexiones, si hay dns source:
```python
        if self._dns_source is not None:
            for rec in self._dns_source.poll():
                ev = Event(source="net", type="dns_query", host=self._host, pid=None,
                           user=None, raw={"query_type": rec.query_type},
                           indicators={"query_name": rec.query_name,
                                       "query_type": rec.query_type,
                                       "remote_ip": rec.remote_ip})
                await bus.publish(ev)
                self._events_emitted += 1
```
- [ ] **Step 3:** Tests verdes (redirect). ruff/mypy limpios. Commit:
```
git add cerberus/collectors/net.py tests/unit/test_net_collector.py
git commit -m "feat(collectors): add injectable DNS source and dns_query events to NetCollector"
```

---

## Task 3: Regla `suspicious_dns.yml`

**Files:** `rules/suspicious_dns.yml`, `tests/unit/test_default_rules.py`

- [ ] **Step 1:** `rules/suspicious_dns.yml`:
```yaml
id: suspicious_dns_v1
severity: MEDIUM
category: c2
condition:
  mode: any
  clauses:
    - source: net
      type: dns_query
```
- [ ] **Step 2:** Actualizar `tests/unit/test_default_rules.py::test_default_rules_all_load` → `assert count == 5`.
- [ ] **Step 3:** Tests verdes. Commit:
```
git add rules/suspicious_dns.yml tests/unit/test_default_rules.py
git commit -m "feat(detection): add suspicious_dns rule for dns_query findings"
```

---

## Task 4: `Win32ServiceController` (builders/parser puros)

**Files:** `cerberus/service/controller.py`, `tests/unit/test_controller.py`

- [ ] **Step 1: Tests** — `tests/unit/test_controller.py`:
```python
from cerberus.service.controller import (
    ForegroundServiceController,
    Win32ServiceController,
)


def test_install_argv_uses_sc_create():
    c = Win32ServiceController(service_name="Cerberus", python_exe="py.exe",
                               script="C:\\svc.py")
    argv = c.build_install_argv()
    assert argv[0] == "sc" and argv[1] == "create" and "Cerberus" in argv


def test_start_stop_status_argv():
    c = Win32ServiceController(service_name="Cerberus", python_exe="py.exe", script="s")
    assert c.build_start_argv() == ["sc", "start", "Cerberus"]
    assert c.build_stop_argv() == ["sc", "stop", "Cerberus"]
    assert c.build_status_argv() == ["sc", "query", "Cerberus"]


def test_parse_sc_query_running():
    out = "SERVICE_NAME: Cerberus\n    STATE : 4  RUNNING\n"
    assert Win32ServiceController.parse_status(out) == "running"


def test_parse_sc_query_stopped():
    out = "SERVICE_NAME: Cerberus\n    STATE : 1  STOPPED\n"
    assert Win32ServiceController.parse_status(out) == "stopped"


def test_parse_sc_query_unknown():
    assert Win32ServiceController.parse_status("garbage") == "unknown"


def test_foreground_controller_still_works():
    c = ForegroundServiceController()
    c.start()
    assert c.status() == "running"
```
- [ ] **Step 2:** Añadir a `cerberus/service/controller.py`:
```python
import subprocess


class Win32ServiceController:
    """Controla el Windows Service vía sc.exe. Builders/parser puros (testeables);
    la ejecución real (subprocess) requiere admin -> validar en campo (M6)."""

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
```
- [ ] **Step 3:** Tests verdes. ruff/mypy limpios. Commit:
```
git add cerberus/service/controller.py tests/unit/test_controller.py
git commit -m "feat(service): add Win32ServiceController (pure sc.exe builders + status parser)"
```

---

## Task 5: Named-pipe `serve()` + SDDL de seguridad

**Files:** `cerberus/service/named_pipe.py`, `tests/unit/test_named_pipe.py`

- [ ] **Step 1: Tests** — añadir a `tests/unit/test_named_pipe.py`:
```python
def test_pipe_sddl_restricts_to_system_and_admins():
    from cerberus.service.named_pipe import pipe_sddl
    sddl = pipe_sddl()
    # solo SYSTEM (SY) y Administrators (BA) con full access (GA)
    assert "(A;;GA;;;SY)" in sddl
    assert "(A;;GA;;;BA)" in sddl
    assert ";;;WD)" not in sddl   # nada para 'Everyone'


def test_serve_without_pywin32_raises(monkeypatch):
    import cerberus.service.named_pipe as mod
    monkeypatch.setattr(mod, "_load_pywin32", lambda: None)
    t = mod.NamedPipeTransport(pipe_name=r"\\.\pipe\cerberus_test")
    t.bind(lambda raw: raw)
    import pytest
    with pytest.raises(mod.IpcUnavailable):
        t.serve_once()
```
- [ ] **Step 2:** Editar `cerberus/service/named_pipe.py` — añadir función pura + `serve_once`:
```python
def pipe_sddl() -> str:
    """SDDL del named pipe: full access solo a SYSTEM (SY) y Administrators (BA)."""
    return "D:(A;;GA;;;SY)(A;;GA;;;BA)"
```
Añadir a `NamedPipeTransport`:
```python
    def serve_once(self) -> None:
        """Atiende una conexión del pipe (servidor). Real -> M6 de campo."""
        if not self.available():
            raise IpcUnavailable("pywin32 no disponible")
        self._serve_once_impl()  # pragma: no cover (M6 field)

    def _serve_once_impl(self) -> None:  # pragma: no cover
        assert self._win is not None and self._on_request is not None
        import win32security
        win32pipe, win32file = self._win
        sa = win32security.SECURITY_ATTRIBUTES()
        sa.SetSecurityDescriptorDacl(
            1, win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
                pipe_sddl(), win32security.SDDL_REVISION_1).GetSecurityDescriptorDacl(), 0)
        handle = win32pipe.CreateNamedPipe(
            self._pipe_name,
            win32pipe.PIPE_ACCESS_DUPLEX,
            win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_READMODE_MESSAGE | win32pipe.PIPE_WAIT,
            1, 65536, 65536, 0, sa)
        win32pipe.ConnectNamedPipe(handle, None)
        _rc, data = win32file.ReadFile(handle, 65536)
        resp = self._on_request(bytes(data).decode("utf-8"))
        win32file.WriteFile(handle, resp.encode("utf-8"))
        win32file.FlushFileBuffers(handle)
        win32pipe.DisconnectNamedPipe(handle)
        win32file.CloseHandle(handle)
```
(Añadir `win32security` al override de mypy en pyproject.)
- [ ] **Step 3:** Tests verdes. ruff/mypy limpios. Commit:
```
git add cerberus/service/named_pipe.py tests/unit/test_named_pipe.py pyproject.toml
git commit -m "feat(service): add named-pipe serve scaffold with SYSTEM/Admins SDDL"
```

---

## Task 6: `cerberus_service.py` (ServiceFramework scaffold)

**Files:** `cerberus_service.py` (raíz)

- [ ] **Step 1:** Crear `cerberus_service.py` (scaffold guarded; no se importa en tests; `# pragma: no cover`):
```python
#!/usr/bin/env python3
"""CERBERUS-LOCAL Windows Service entry point (M6 field).

Requiere pywin32 + privilegios admin. Registrar con:
    python cerberus_service.py install
    python cerberus_service.py start
o vía sc.exe (ver docs/M6_FIELD_GUIDE.md). No se importa en la suite de tests.
"""
from __future__ import annotations

import asyncio

try:  # pragma: no cover (pywin32 + SCM, validar en campo)
    import servicemanager
    import win32serviceutil

    from cerberus.cli.commands import _run_loop, resolve_config

    class CerberusService(win32serviceutil.ServiceFramework):  # type: ignore[misc]
        _svc_name_ = "Cerberus"
        _svc_display_name_ = "CERBERUS-LOCAL EDR"

        def __init__(self, args: object) -> None:
            super().__init__(args)
            self._cfg = resolve_config(None)

        def SvcStop(self) -> None:
            # En M6: señalar el stop_event del loop vía killswitch/IPC.
            self.ReportServiceStatus(win32serviceutil.win32service.SERVICE_STOP_PENDING)

        def SvcDoRun(self) -> None:
            asyncio.run(_run_loop(self._cfg))

    if __name__ == "__main__":
        win32serviceutil.HandleCommandLine(CerberusService)
except Exception:  # pragma: no cover
    if __name__ == "__main__":
        print("Windows Service requiere pywin32 + Windows. Ver docs/M6_FIELD_GUIDE.md.")
```
- [ ] **Step 2:** Verificar que NO rompe la suite (no se importa) y que `ruff check .` lo acepta. Commit:
```
git add cerberus_service.py
git commit -m "feat(service): add Windows Service entry-point scaffold (field-validated in M6)"
```

---

## Task 7: Packaging WiX (`.wxs` + `.ps1`)

**Files:** `packaging/cerberus.wxs`, `packaging/build_msi.ps1`, `packaging/install_service.ps1`

- [ ] **Step 1:** `packaging/cerberus.wxs` — estructura WiX mínima: `Product`, dirs `ProgramFilesFolder\Cerberus` y `CommonAppDataFolder\Cerberus`, `Component` del paquete, `ServiceInstall`+`ServiceControl` para `Cerberus`, `CustomAction` post-install `cerberus integrity snapshot`. (Plantilla autorada; placeholders de GUID claramente marcados para regenerar con `uuidgen` en build.)
- [ ] **Step 2:** `packaging/build_msi.ps1` — `heat dir` (harvest) → `candle` → `light`; luego `signtool sign`; generar SBOM (CycloneDX) y hashes SHA256. Comentado paso a paso.
- [ ] **Step 3:** `packaging/install_service.ps1` — `sc create Cerberus binPath= ...` + `sc failure Cerberus reset= 86400 actions= restart/10000/restart/60000/restart/300000` + `cerberus integrity snapshot`.
- [ ] **Step 4:** Commit:
```
git add packaging
git commit -m "build(packaging): add WiX .wxs and service/build PowerShell scripts (field)"
```

---

## Task 8: README/M6 status + tag v0.6.0-m6

**Files:** `README.md`, `docs/M6_FIELD_GUIDE.md`

- [ ] **Step 1:** Actualizar `README.md` (encabezado M6; aclarar: andamiaje de campo escrito; instalación real/Npcap/redteam = runbook). Actualizar `docs/M6_FIELD_GUIDE.md` para referenciar los nuevos artefactos (`cerberus_service.py`, `packaging/`, `Win32ServiceController`, `dns_capture`).
- [ ] **Step 2:** Build final verde (redirect): `pytest` ≥85%, `ruff check .`, `mypy cerberus cerberus_local.py`.
- [ ] **Step 3:** Auditoría `auditing-security` ligera (foco: SDDL del pipe restringe a SYSTEM/Admins; sc.exe vía argv `shell=False`; pyshark source no ejecuta nada; sin `shell=True` nuevo). Commit + tag:
```
git add README.md docs/M6_FIELD_GUIDE.md
git commit -m "docs: M6 field-scaffolding status; security audit pass"
git tag -a v0.6.0-m6 -m "M6 scaffolding: dns_query + Win32 service controller + pipe SDDL + WiX (field-validated)"
```

---

## Checklist final M6 (andamiaje)
- [ ] 8 tareas; tests verdes; coverage ≥85%; ruff/mypy limpios
- [ ] Seams testeados: dns_source inyectable, sc argv/parser, pipe SDDL, degradaciones
- [ ] E/S real (Npcap, sc.exe, pipe I/O, .msi, redteam) marcada `# pragma: no cover` y documentada como campo
- [ ] `cerberus_service.py` + `packaging/` autorados; `docs/M6_FIELD_GUIDE.md` actualizado
- [ ] Tag `v0.6.0-m6`

## Campo (ejecutar en Windows real — runbook `docs/M6_FIELD_GUIDE.md`)
Instalar Npcap · registrar Service (`packaging/install_service.ps1`) · build/firma `.msi` (`packaging/build_msi.ps1`) · validar named pipe + ACL · redteam en VM · baseline 24h · checklist pre-release §9.5.
