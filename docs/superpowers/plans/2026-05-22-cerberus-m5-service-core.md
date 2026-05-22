# CERBERUS-LOCAL · Plan M5 — Núcleo de servicio: IPC + hot-mode + anti-tampering + hardening

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Endurecer CERBERUS-LOCAL para operación como servicio: **IPC CLI↔Service** (protocolo JSON sobre transporte abstracto), **persistencia de `mode` en caliente** (cambiar el modo sin reiniciar), **anti-tampering por checksum SHA256** (manifest de integridad; mismatch → fuerza `dry_run`), **hardening del LOW de NetCollector** (purga de claves beacon obsoletas), y **scaffolding del Service** (abstracción `ServiceController`). Todo en Python con TDD; la integración real de SO/empaquetado se difiere a M6.

**Architecture:** 100% heurístico — 0 LLM nuevo. La capa que toca pywin32/named-pipes está aislada tras abstracciones (`Transport`, `ServiceController`) con implementación real lazy (no-Windows degrada con gracia, no-unit-tested como la ruta `win32evtlog` de M3) y una implementación en-memoria para tests. El IPC dispatcher es puro respecto al transporte. El `IntegrityVerifier` solo lee archivos y calcula hashes (sin ejecución). El cambio de modo en caliente se hace vía `RuntimeState` (archivo JSON atómico) + `ResponseEngine.set_mode()` aditivo (no rompe M4).

**Tech Stack:** Python 3.11+, `asyncio`, `hashlib`/`json`/`os` stdlib, `pywin32` (named pipe + service, lazy, opcional), `pytest`, `pytest-asyncio`, `ruff`, `mypy`. **Ninguna dependencia runtime nueva** (pywin32 ya es extra `windows`).

**Reference spec:** `2026-05-21-cerberus-local-edr-design.md` (§4.11 CerberusService/named pipe, §7.3 rollback, §7.4 killswitch, §7.6 anti-tampering, §8 CLI).

---

## Scope (decisiones aprobadas 2026-05-22)

1. **M5 = núcleo Python testeable** (TDD aquí, como M1–M4): IPC named-pipe sobre transporte abstracto (pywin32 mockeado), persistencia de `mode` en caliente, anti-tampering por checksum SHA256 + manifest, hardening del LOW de NetCollector (purga de claves beacon), scaffolding del Service vía `ServiceController`.
2. **Diferido a M6 (campo, manual en Windows real):** instalador `.msi` (WiX), registro real del Windows Service (`win32serviceutil`), Npcap + `pyshark`/`dns_query`, redteam en VM, ACLs/TakeOwnership de la cuarentena.
3. **La capa pywin32 (named pipe real, Service real) queda fina y NO unit-tested** (igual que la ruta `win32evtlog` real de M3); se ejercita en M6 de campo. Se prueba la **ruta de degradación** (sin pywin32 → no-op con log).

---

## File Structure (M5)

```
cerberus-local/
├── pyproject.toml                       # MODIFICAR: version 0.5.0
├── config/cerberus.default.yml          # MODIFICAR: paths.state_file/manifest_path; ipc; integrity
├── cerberus/
│   ├── __init__.py                      # MODIFICAR: 0.5.0
│   ├── core/
│   │   ├── config.py                    # MODIFICAR: paths +state_file/manifest_path; IpcConfig; IntegrityConfig
│   │   └── runtime_state.py             # CREAR: RuntimeState (state.json, mode atómico)
│   ├── collectors/net.py                # MODIFICAR: purga de claves beacon obsoletas (LOW M2)
│   ├── response/engine.py               # MODIFICAR: set_mode() (hot-mode)
│   ├── service/
│   │   ├── __init__.py                  # CREAR
│   │   ├── integrity.py                 # CREAR: IntegrityVerifier (manifest SHA256)
│   │   ├── ipc.py                       # CREAR: protocolo + Transport + InMemoryTransport + IpcServer/IpcClient + IpcDispatcher
│   │   ├── named_pipe.py                # CREAR: NamedPipeTransport (pywin32 lazy, degradación)
│   │   └── controller.py                # CREAR: ServiceController (abstracción + ForegroundController)
│   └── cli/commands.py                  # MODIFICAR: wire IPC server, integrity en arranque, hot-mode watcher, cmd_mode escribe state, status/findings vía IPC fallback, cmd_integrity
└── tests/
    ├── unit/
    │   ├── test_config.py               # MODIFICAR: ipc/integrity/state_file
    │   ├── test_cli_commands.py         # MODIFICAR: _make_cfg con paths/ipc/integrity nuevos
    │   ├── test_net_collector.py        # MODIFICAR: test de purga de claves beacon
    │   ├── test_runtime_state.py        # CREAR
    │   ├── test_response_set_mode.py    # CREAR
    │   ├── test_integrity.py            # CREAR
    │   ├── test_ipc.py                  # CREAR
    │   └── test_named_pipe.py           # CREAR (degradación)
    └── integration/
        └── test_service_m5.py           # CREAR: IPC round-trip + hot-mode + integrity mismatch
└── docs/
    └── M6_FIELD_GUIDE.md                # CREAR: pasos manuales Windows (msi/service/npcap/redteam)
```

**Out of scope (M6 campo):** `.msi` WiX, `win32serviceutil` install real, Npcap+pyshark/`dns_query`, redteam VM, ACLs cuarentena.

---

## Pre-flight

- [ ] **Step 1:** `git checkout master && git status` → limpio, HEAD `c32c4fc`, tag `v0.4.0-m4`.
- [ ] **Step 2:** `.venv/Scripts/python -m pytest -p no:cacheprovider -q --ignore=tests/integration/test_ollama_live.py > t.txt 2>&1; tail -2 t.txt; rm t.txt` → 152 passed.
- [ ] **Step 3:** `git checkout -b m5/service-core`.

> **Nota de harness (recurrente):** pytest/ruff/mypy largos o chained se "encolan" en background sin volcar salida. **Workaround:** redirigir a archivo temporal y `cat`/`tail` (`cmd > t.txt 2>&1; tail t.txt; rm t.txt`). Comandos cortos individuales sí retornan síncronos.

---

## Task 1: Bump 0.5.0 + config (ipc, integrity, state_file)

**Files:** `cerberus/__init__.py`, `pyproject.toml`, `config/cerberus.default.yml`, `cerberus/core/config.py`, `tests/unit/test_config.py`, `tests/unit/test_cli_commands.py`

- [ ] **Step 1:** `cerberus/__init__.py` → `__version__ = "0.5.0"`. `pyproject.toml` → `version = "0.5.0"`.

- [ ] **Step 2: Añadir tests a `tests/unit/test_config.py`** (al final):
```python
def test_load_ipc_and_integrity_config(tmp_path):
    cfg_file = tmp_path / "c.yml"
    cfg_file.write_text(
        """
mode: dry_run
host_name: null
paths:
  data_dir: /tmp/c
  events_db: /tmp/c/e.db
  findings_db: /tmp/c/f.db
  reports_dir: /tmp/c/r
  log_file: /tmp/c/l.log
  state_file: /tmp/c/state.json
  manifest_path: /tmp/c/manifest.json
collectors: {proc: {enabled: true, poll_interval_seconds: 1.0}}
ipc:
  enabled: true
  pipe_name: "\\\\\\\\.\\\\pipe\\\\cerberus"
integrity:
  enabled: true
reporting: {interval_seconds: 60, retention_days: 1}
""",
        encoding="utf-8",
    )
    from cerberus.core.config import load_config
    cfg = load_config(cfg_file)
    from pathlib import Path
    assert cfg.paths.state_file == Path("/tmp/c/state.json")
    assert cfg.paths.manifest_path == Path("/tmp/c/manifest.json")
    assert cfg.ipc.enabled is True
    assert "pipe" in cfg.ipc.pipe_name
    assert cfg.integrity.enabled is True


def test_ipc_integrity_defaults_when_absent(tmp_path):
    cfg_file = tmp_path / "c.yml"
    cfg_file.write_text(
        """
mode: dry_run
host_name: null
paths:
  data_dir: /tmp/c
  events_db: /tmp/c/e.db
  findings_db: /tmp/c/f.db
  reports_dir: /tmp/c/r
  log_file: /tmp/c/l.log
collectors: {proc: {enabled: true, poll_interval_seconds: 1.0}}
reporting: {interval_seconds: 60, retention_days: 1}
""",
        encoding="utf-8",
    )
    from cerberus.core.config import load_config
    cfg = load_config(cfg_file)
    assert cfg.ipc.enabled is True
    assert cfg.ipc.pipe_name
    assert cfg.integrity.enabled is True
    assert str(cfg.paths.state_file).endswith("state.json")
    assert str(cfg.paths.manifest_path).endswith("manifest.json")
```

- [ ] **Step 3:** Editar `cerberus/core/config.py`:

(a) `PathsConfig` — añadir `state_file: Path` y `manifest_path: Path` (al final):
```python
@dataclass(frozen=True)
class PathsConfig:
    data_dir: Path
    events_db: Path
    findings_db: Path
    actions_db: Path
    reports_dir: Path
    log_file: Path
    killswitch_path: Path
    quarantine_dir: Path
    state_file: Path
    manifest_path: Path
```

(b) Nuevas dataclasses (tras `ResponseConfig`):
```python
@dataclass(frozen=True)
class IpcConfig:
    enabled: bool
    pipe_name: str


@dataclass(frozen=True)
class IntegrityConfig:
    enabled: bool
```

(c) `CerberusConfig` — añadir `ipc: IpcConfig` y `integrity: IntegrityConfig` (tras `response`).

(d) En `load_config`, dentro del bloque `paths`, añadir:
```python
        state_file=Path(paths_raw.get("state_file") or (data_dir / "state.json")),
        manifest_path=Path(paths_raw.get("manifest_path") or (data_dir / "manifest.json")),
```

(e) Tras `response = _response(...)`:
```python
    ipc_raw = raw.get("ipc", {})
    ipc = IpcConfig(
        enabled=bool(ipc_raw.get("enabled", True)),
        pipe_name=str(ipc_raw.get("pipe_name", r"\\.\pipe\cerberus")),
    )
    integrity_raw = raw.get("integrity", {})
    integrity = IntegrityConfig(enabled=bool(integrity_raw.get("enabled", True)))
```
y pasar `ipc=ipc, integrity=integrity` al `CerberusConfig(...)`.

- [ ] **Step 4:** `config/cerberus.default.yml` — añadir bajo `paths:`:
```yaml
  state_file: "C:\\ProgramData\\Cerberus\\state.json"
  manifest_path: "C:\\ProgramData\\Cerberus\\manifest.json"
```
y antes de `reporting:`:
```yaml
ipc:
  enabled: true
  pipe_name: "\\\\.\\pipe\\cerberus"

integrity:
  enabled: true
```

- [ ] **Step 5:** Editar `tests/unit/test_cli_commands.py::_make_cfg`: importar `IpcConfig, IntegrityConfig`; añadir a `PathsConfig(...)`:
```python
            state_file=tmp_path / "state.json",
            manifest_path=tmp_path / "manifest.json",
```
y tras `response=...`:
```python
        ipc=IpcConfig(enabled=False, pipe_name=r"\\.\pipe\cerberus_test"),
        integrity=IntegrityConfig(enabled=False),
```
(ipc/integrity disabled en unit tests del CLI.)

- [ ] **Step 6:** Verificar: `.venv/Scripts/python -c "import cerberus; print(cerberus.__version__)"` → `0.5.0`; tests config+cli verdes; full suite verde (usar workaround de redirect).

- [ ] **Step 7:** Commit:
```bash
git add pyproject.toml cerberus/__init__.py config/cerberus.default.yml cerberus/core/config.py tests/unit/test_config.py tests/unit/test_cli_commands.py
git commit -m "chore(m5): bump to 0.5.0; add ipc/integrity config and state_file/manifest paths"
```
Trailer: `Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>`

---

## Task 2: NetCollector — purga de claves beacon obsoletas (cierra LOW de M2)

**Files:** `cerberus/collectors/net.py`, `tests/unit/test_net_collector.py`

- [ ] **Step 1: Añadir test a `tests/unit/test_net_collector.py`** (al final):
```python
@pytest.mark.asyncio
async def test_net_collector_purges_stale_beacon_keys(monkeypatch):
    import cerberus.collectors.net as netmod
    clock = {"t": 1000.0}
    monkeypatch.setattr(netmod.time, "monotonic", lambda: clock["t"])

    def make_conn(pid, ip, lport):
        return _SConn(fd=lport, family=2, type=1,
                      laddr=_Addr("192.168.1.5", lport),
                      raddr=_Addr(ip, 443), status="ESTABLISHED", pid=pid)

    seq = iter([[], [make_conn(2000, "9.9.9.9", 50001)]])

    def fake_net_connections(kind="inet"):
        try:
            return next(seq)
        except StopIteration:
            return []

    bus = EventBus()
    c = NetCollector(host="H", poll_interval_seconds=0.02,
                     beaconing_window_seconds=60, beaconing_min_connections=10)
    with patch("cerberus.collectors.net.psutil.net_connections",
               side_effect=fake_net_connections):
        task = asyncio.create_task(c.start(bus))
        await _collect_events(bus, target_count=1, wait_secs=0.5)
        # avanzar el reloj mas alla de la ventana de beaconing
        clock["t"] += 120.0
        c.purge_stale()
        await c.stop()
        task.cancel()

    # tras la purga, no quedan claves (pid,ip) obsoletas en los dicts internos
    assert c.beacon_key_count() == 0
```

- [ ] **Step 2:** Editar `cerberus/collectors/net.py`:

En `_track_beaconing`, tras el `while hist and hist[0] < cutoff: hist.popleft()`, añadir limpieza inmediata de la clave si su deque queda vacío:
```python
        if not hist:
            self._beacon_hist.pop(bkey, None)
            self._beacon_alerted.discard(bkey)
            return
```
(colocar ese bloque ANTES del chequeo de umbral; si el deque quedó vacío no hay nada que alertar).

Añadir dos métodos públicos a `NetCollector`:
```python
    def purge_stale(self) -> None:
        """Elimina claves (pid, ip) cuyo historial beacon ya envejeció por completo."""
        now = time.monotonic()
        cutoff = now - self._beacon_window
        for bkey in list(self._beacon_hist.keys()):
            hist = self._beacon_hist[bkey]
            while hist and hist[0] < cutoff:
                hist.popleft()
            if not hist:
                del self._beacon_hist[bkey]
                self._beacon_alerted.discard(bkey)

    def beacon_key_count(self) -> int:
        return len(self._beacon_hist)
```

Y en el bucle `start()`, tras cada `_tick`, llamar `self.purge_stale()` periódicamente (basta cada tick):
```python
                try:
                    await self._tick(bus)
                    self.purge_stale()
                except Exception as exc:
                    ...
```

- [ ] **Step 3:** `pytest tests/unit/test_net_collector.py -v` (redirect) → todos pasan (4 previos + 1 nuevo).

- [ ] **Step 4:** Commit:
```bash
git add cerberus/collectors/net.py tests/unit/test_net_collector.py
git commit -m "fix(collectors): purge stale beacon keys in NetCollector (closes M2 LOW)"
```
Trailer: `Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>`

---

## Task 3: `RuntimeState` (state.json, modo atómico)

**Files:** `cerberus/core/runtime_state.py`, `tests/unit/test_runtime_state.py`

- [ ] **Step 1: Tests** — `tests/unit/test_runtime_state.py`:
```python
from pathlib import Path

from cerberus.core.runtime_state import RuntimeState


def test_get_mode_default_when_missing(tmp_path: Path):
    rs = RuntimeState(tmp_path / "state.json")
    assert rs.get_mode(default="dry_run") == "dry_run"


def test_set_then_get_mode(tmp_path: Path):
    rs = RuntimeState(tmp_path / "state.json")
    rs.set_mode("auto_critical")
    assert rs.get_mode(default="dry_run") == "auto_critical"
    # nueva instancia lee el mismo archivo
    rs2 = RuntimeState(tmp_path / "state.json")
    assert rs2.get_mode(default="dry_run") == "auto_critical"


def test_set_mode_rejects_invalid(tmp_path: Path):
    import pytest
    rs = RuntimeState(tmp_path / "state.json")
    with pytest.raises(ValueError):
        rs.set_mode("nuke")


def test_corrupt_state_falls_back_to_default(tmp_path: Path):
    p = tmp_path / "state.json"
    p.write_text("{not json", encoding="utf-8")
    rs = RuntimeState(p)
    assert rs.get_mode(default="monitor") == "monitor"
```

- [ ] **Step 2:** `pytest tests/unit/test_runtime_state.py -v` → FAIL.

- [ ] **Step 3:** Implementar `cerberus/core/runtime_state.py`:
```python
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from cerberus.core.config import _VALID_MODES
from cerberus.core.logger import get_logger

_log = get_logger("cerberus.core.runtime_state")


class RuntimeState:
    """Estado de runtime persistido en JSON (atómico). Fuente del `mode` en caliente."""

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)

    def _read(self) -> dict[str, object]:
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}

    def _write(self, data: dict[str, object]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=str(self.path.parent), suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(data, fh)
            os.replace(tmp, self.path)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)

    def get_mode(self, default: str) -> str:
        mode = self._read().get("mode")
        if isinstance(mode, str) and mode in _VALID_MODES:
            return mode
        return default

    def set_mode(self, mode: str) -> None:
        if mode not in _VALID_MODES:
            raise ValueError(f"Invalid mode {mode!r}; valid: {sorted(_VALID_MODES)}")
        data = self._read()
        data["mode"] = mode
        self._write(data)
        _log.info("mode_persisted", extra={"mode": mode})
```

- [ ] **Step 4:** `pytest tests/unit/test_runtime_state.py -v` → 4 passed.

- [ ] **Step 5:** Commit:
```bash
git add cerberus/core/runtime_state.py tests/unit/test_runtime_state.py
git commit -m "feat(core): add RuntimeState for atomic hot-mode persistence"
```
Trailer: `Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>`

---

## Task 4: `ResponseEngine.set_mode` (hot-mode)

**Files:** `cerberus/response/engine.py`, `tests/unit/test_response_set_mode.py`

- [ ] **Step 1: Tests** — `tests/unit/test_response_set_mode.py`:
```python
import dataclasses
from pathlib import Path

import pytest

from cerberus.core.event import Event, Severity
from cerberus.core.finding import Finding
from cerberus.response.action_store import ActionStore
from cerberus.response.actions import Action, ActionResult, PolicyDecision
from cerberus.response.engine import ResponseEngine
from cerberus.response.rate_limiter import RateLimiter


class _FakePolicy:
    def decide(self, finding):
        return [PolicyDecision(Action("kill_pid", {"pid": 1}), "p1", False)]


class _FakeExecutor:
    def __init__(self):
        self.runs = 0

    def build(self, action):
        from cerberus.response.executor import _Built
        return _Built("CMD", "REV", True, "ok")

    def run(self, action):
        self.runs += 1
        return ActionResult(action=action, executed=True, success=True, output="",
                            command="CMD", reverted_command="REV", reason="authorized")


def _finding():
    evs = [Event(source="fs", type="mass_rename", host="H", pid=1, user="u",
                 raw={}, indicators={})]
    f = Finding.from_cluster(host="H", pid=1, user="u", evidence=evs)
    return dataclasses.replace(f, severity=Severity.CRITICAL, severity_base=Severity.CRITICAL)


def _engine(tmp_path, mode, executor):
    store = ActionStore(tmp_path / "a.db")
    store.init_schema()
    return ResponseEngine(
        policy_engine=_FakePolicy(), executor=executor, action_store=store,
        rate_limiter=RateLimiter(10, 1), mode=mode,
        killswitch_path=tmp_path / "KS",
        auto_critical_categories=frozenset({"mass_rename"}),
    )


@pytest.mark.asyncio
async def test_set_mode_changes_gate_behavior(tmp_path):
    ex = _FakeExecutor()
    eng = _engine(tmp_path, "dry_run", ex)
    await eng.handle(_finding())
    assert ex.runs == 0          # dry_run no ejecuta
    eng.set_mode("auto_all")
    await eng.handle(_finding())
    assert ex.runs == 1          # tras hot-switch, ejecuta


def test_set_mode_rejects_invalid(tmp_path):
    eng = _engine(tmp_path, "dry_run", _FakeExecutor())
    with pytest.raises(ValueError):
        eng.set_mode("nuke")
```

- [ ] **Step 2:** `pytest tests/unit/test_response_set_mode.py -v` → FAIL.

- [ ] **Step 3:** Editar `cerberus/response/engine.py` — añadir método (tras `__init__`):
```python
    def set_mode(self, mode: str) -> None:
        from cerberus.core.config import _VALID_MODES
        if mode not in _VALID_MODES:
            raise ValueError(f"Invalid mode {mode!r}")
        if mode != self._mode:
            _log.info("mode_changed", extra={"from": self._mode, "to": mode})
        self._mode = mode

    @property
    def mode(self) -> str:
        return self._mode
```

- [ ] **Step 4:** `pytest tests/unit/test_response_set_mode.py -v` → 2 passed. Confirmar que M4 `test_response_engine.py` sigue verde.

- [ ] **Step 5:** Commit:
```bash
git add cerberus/response/engine.py tests/unit/test_response_set_mode.py
git commit -m "feat(response): add ResponseEngine.set_mode for hot mode switching"
```
Trailer: `Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>`

---

## Task 5: `IntegrityVerifier` (anti-tampering por checksum)

**Files:** `cerberus/service/__init__.py` (vacío), `cerberus/service/integrity.py`, `tests/unit/test_integrity.py`

- [ ] **Step 1:** Crear `cerberus/service/__init__.py` vacío.

- [ ] **Step 2: Tests** — `tests/unit/test_integrity.py`:
```python
from pathlib import Path

from cerberus.service.integrity import IntegrityVerifier


def _mk(root: Path, rel: str, text: str) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


def test_build_manifest_hashes_py_files(tmp_path: Path):
    _mk(tmp_path, "pkg/a.py", "print('a')")
    _mk(tmp_path, "pkg/sub/b.py", "print('b')")
    _mk(tmp_path, "pkg/notes.txt", "ignore me")
    v = IntegrityVerifier()
    manifest = v.build_manifest(tmp_path, subdir="pkg")
    assert set(manifest.keys()) == {"pkg/a.py", "pkg/sub/b.py"}
    assert all(len(h) == 64 for h in manifest.values())  # sha256 hex


def test_verify_detects_no_tampering(tmp_path: Path):
    _mk(tmp_path, "pkg/a.py", "x = 1")
    v = IntegrityVerifier()
    manifest = v.build_manifest(tmp_path, subdir="pkg")
    result = v.verify(tmp_path, manifest, subdir="pkg")
    assert result.ok is True
    assert result.mismatched == [] and result.missing == [] and result.extra == []


def test_verify_detects_modified_file(tmp_path: Path):
    _mk(tmp_path, "pkg/a.py", "x = 1")
    v = IntegrityVerifier()
    manifest = v.build_manifest(tmp_path, subdir="pkg")
    _mk(tmp_path, "pkg/a.py", "x = 2  # tampered")
    result = v.verify(tmp_path, manifest, subdir="pkg")
    assert result.ok is False
    assert "pkg/a.py" in result.mismatched


def test_verify_detects_missing_and_extra(tmp_path: Path):
    _mk(tmp_path, "pkg/a.py", "x = 1")
    v = IntegrityVerifier()
    manifest = v.build_manifest(tmp_path, subdir="pkg")
    (tmp_path / "pkg" / "a.py").unlink()
    _mk(tmp_path, "pkg/c.py", "y = 9")
    result = v.verify(tmp_path, manifest, subdir="pkg")
    assert result.ok is False
    assert "pkg/a.py" in result.missing
    assert "pkg/c.py" in result.extra


def test_write_and_load_manifest_roundtrip(tmp_path: Path):
    _mk(tmp_path, "pkg/a.py", "x = 1")
    v = IntegrityVerifier()
    manifest = v.build_manifest(tmp_path, subdir="pkg")
    mp = tmp_path / "manifest.json"
    v.write_manifest(mp, manifest)
    loaded = v.load_manifest(mp)
    assert loaded == manifest
```

- [ ] **Step 3:** `pytest tests/unit/test_integrity.py -v` → FAIL.

- [ ] **Step 4:** Implementar `cerberus/service/integrity.py`:
```python
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

_CHUNK = 65536


@dataclass(frozen=True)
class IntegrityResult:
    ok: bool
    mismatched: list[str]
    missing: list[str]
    extra: list[str]


class IntegrityVerifier:
    """Anti-tampering por checksum SHA256 sobre los .py del paquete. Solo lee archivos."""

    @staticmethod
    def _sha256(path: Path) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            while chunk := fh.read(_CHUNK):
                h.update(chunk)
        return h.hexdigest()

    def build_manifest(self, root: Path | str, subdir: str = "cerberus") -> dict[str, str]:
        root = Path(root)
        base = root / subdir
        manifest: dict[str, str] = {}
        for path in sorted(base.rglob("*.py")):
            rel = path.relative_to(root).as_posix()
            manifest[rel] = self._sha256(path)
        return manifest

    def write_manifest(self, path: Path | str, manifest: dict[str, str]) -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(json.dumps(manifest, indent=2, sort_keys=True),
                              encoding="utf-8")

    def load_manifest(self, path: Path | str) -> dict[str, str]:
        return dict(json.loads(Path(path).read_text(encoding="utf-8")))

    def verify(self, root: Path | str, manifest: dict[str, str],
               subdir: str = "cerberus") -> IntegrityResult:
        current = self.build_manifest(root, subdir=subdir)
        cur_keys, exp_keys = set(current), set(manifest)
        missing = sorted(exp_keys - cur_keys)
        extra = sorted(cur_keys - exp_keys)
        mismatched = sorted(k for k in (cur_keys & exp_keys) if current[k] != manifest[k])
        ok = not (missing or extra or mismatched)
        return IntegrityResult(ok=ok, mismatched=mismatched, missing=missing, extra=extra)
```

- [ ] **Step 5:** `pytest tests/unit/test_integrity.py -v` → 5 passed.

- [ ] **Step 6:** Commit:
```bash
git add cerberus/service/__init__.py cerberus/service/integrity.py tests/unit/test_integrity.py
git commit -m "feat(service): add IntegrityVerifier (SHA256 manifest anti-tampering)"
```
Trailer: `Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>`

---

## Task 6: IPC core (protocolo + transporte en memoria + server/client/dispatcher)

**Files:** `cerberus/service/ipc.py`, `tests/unit/test_ipc.py`

- [ ] **Step 1: Tests** — `tests/unit/test_ipc.py`:
```python
from cerberus.service.ipc import (
    InMemoryTransport,
    IpcClient,
    IpcDispatcher,
    IpcServer,
)


def _dispatcher():
    state = {"mode": "dry_run"}

    def status(args):
        return {"events": 3, "findings": 1, "mode": state["mode"]}

    def set_mode(args):
        state["mode"] = args["mode"]
        return {"mode": state["mode"]}

    d = IpcDispatcher()
    d.register("status", status)
    d.register("mode", set_mode)
    return d, state


def test_dispatcher_routes_command():
    d, _ = _dispatcher()
    resp = d.handle({"command": "status", "args": {}})
    assert resp["ok"] is True
    assert resp["data"]["events"] == 3


def test_dispatcher_unknown_command():
    d, _ = _dispatcher()
    resp = d.handle({"command": "nope", "args": {}})
    assert resp["ok"] is False
    assert "unknown" in resp["error"].lower()


def test_dispatcher_handler_exception_is_caught():
    d = IpcDispatcher()
    def boom(args):
        raise RuntimeError("x")
    d.register("boom", boom)
    resp = d.handle({"command": "boom", "args": {}})
    assert resp["ok"] is False
    assert resp["error"]


def test_inmemory_roundtrip_client_server():
    d, state = _dispatcher()
    transport = InMemoryTransport()
    server = IpcServer(transport, d)
    server.start()
    client = IpcClient(transport)
    r1 = client.request("status")
    assert r1["ok"] and r1["data"]["mode"] == "dry_run"
    r2 = client.request("mode", mode="auto_all")
    assert r2["ok"] and r2["data"]["mode"] == "auto_all"
    r3 = client.request("status")
    assert r3["data"]["mode"] == "auto_all"
    server.stop()


def test_client_request_serializes_json():
    import json
    d, _ = _dispatcher()
    transport = InMemoryTransport()
    IpcServer(transport, d).start()
    # el transporte transporta strings JSON
    raw = transport.round_trip(json.dumps({"command": "status", "args": {}}))
    assert json.loads(raw)["ok"] is True
```

- [ ] **Step 2:** `pytest tests/unit/test_ipc.py -v` → FAIL.

- [ ] **Step 3:** Implementar `cerberus/service/ipc.py`:
```python
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
```

- [ ] **Step 4:** `pytest tests/unit/test_ipc.py -v` → 5 passed.

- [ ] **Step 5:** Commit:
```bash
git add cerberus/service/ipc.py tests/unit/test_ipc.py
git commit -m "feat(service): add IPC core (dispatcher, in-memory transport, server/client)"
```
Trailer: `Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>`

---

## Task 7: `NamedPipeTransport` (pywin32 lazy, degradación) + `ServiceController`

**Files:** `cerberus/service/named_pipe.py`, `cerberus/service/controller.py`, `tests/unit/test_named_pipe.py`

> La ruta real de named pipe (pywin32) NO se unit-testea (como `win32evtlog` real en M3). Se prueba la **degradación**: sin pywin32 → `available()` False y `round_trip` levanta `IpcUnavailable`.

- [ ] **Step 1: Tests** — `tests/unit/test_named_pipe.py`:
```python
from cerberus.service.controller import ForegroundServiceController, ServiceController
from cerberus.service.named_pipe import IpcUnavailable, NamedPipeTransport


def test_named_pipe_degrades_without_pywin32(monkeypatch):
    # forzar ausencia de pywin32
    import cerberus.service.named_pipe as mod
    monkeypatch.setattr(mod, "_load_pywin32", lambda: None)
    t = NamedPipeTransport(pipe_name=r"\\.\pipe\cerberus_test")
    assert t.available() is False


def test_named_pipe_round_trip_unavailable_raises(monkeypatch):
    import cerberus.service.named_pipe as mod
    monkeypatch.setattr(mod, "_load_pywin32", lambda: None)
    t = NamedPipeTransport(pipe_name=r"\\.\pipe\cerberus_test")
    import pytest
    with pytest.raises(IpcUnavailable):
        t.round_trip('{"command": "status", "args": {}}')


def test_foreground_controller_status():
    c: ServiceController = ForegroundServiceController()
    assert c.status() in ("stopped", "running")
    c.start()
    assert c.status() == "running"
    c.stop()
    assert c.status() == "stopped"
```

- [ ] **Step 2:** `pytest tests/unit/test_named_pipe.py -v` → FAIL.

- [ ] **Step 3:** Implementar `cerberus/service/named_pipe.py`:
```python
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
        # Lado cliente: conecta al pipe y hace request/response.
        if not self.available():
            raise IpcUnavailable("pywin32 no disponible")
        return self._client_round_trip(raw_request)  # pragma: no cover (M6 field)

    def _client_round_trip(self, raw_request: str) -> str:  # pragma: no cover
        win32pipe, win32file = self._win  # type: ignore[misc]
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
```

- [ ] **Step 4:** Implementar `cerberus/service/controller.py`:
```python
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
        pass

    def start(self) -> None:
        self._running = True

    def stop(self) -> None:
        self._running = False

    def status(self) -> str:
        return "running" if self._running else "stopped"
```

- [ ] **Step 5:** `pytest tests/unit/test_named_pipe.py -v` → 3 passed.

- [ ] **Step 6:** Commit:
```bash
git add cerberus/service/named_pipe.py cerberus/service/controller.py tests/unit/test_named_pipe.py
git commit -m "feat(service): add NamedPipeTransport (lazy/degrading) and ServiceController scaffold"
```
Trailer: `Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>`

---

## Task 8: Wiring CLI (IPC server, integridad en arranque, hot-mode, comandos)

**Files:** `cerberus/cli/commands.py`, `cerberus_local.py`, `tests/unit/test_cli_commands.py`

- [ ] **Step 1:** En `cerberus/cli/commands.py` añadir imports:
```python
from cerberus.core.runtime_state import RuntimeState
from cerberus.service.integrity import IntegrityVerifier
from cerberus.service.ipc import IpcDispatcher, IpcServer
from cerberus.service.named_pipe import NamedPipeTransport
```

- [ ] **Step 2:** Cambiar `cmd_mode` para que PERSISTA vía RuntimeState (en vez de solo imprimir):
```python
def cmd_mode(cfg: CerberusConfig, new_mode: str) -> int:
    from cerberus.core.config import _VALID_MODES
    if new_mode not in _VALID_MODES:
        print(f"Modo inválido: {new_mode}. Válidos: {sorted(_VALID_MODES)}")
        return 2
    RuntimeState(cfg.paths.state_file).set_mode(new_mode)
    print(f"Modo persistido: {new_mode}. Un agente en ejecución lo aplicará en caliente.")
    return 0
```

- [ ] **Step 3:** Añadir `cmd_integrity`:
```python
def cmd_integrity(cfg: CerberusConfig, action: str) -> int:
    repo_root = Path(__file__).resolve().parent.parent.parent
    v = IntegrityVerifier()
    if action == "snapshot":
        manifest = v.build_manifest(repo_root)
        v.write_manifest(cfg.paths.manifest_path, manifest)
        print(f"Manifest escrito ({len(manifest)} archivos) en {cfg.paths.manifest_path}")
        return 0
    if action == "verify":
        if not cfg.paths.manifest_path.exists():
            print("No hay manifest. Ejecuta 'integrity snapshot' primero.")
            return 2
        manifest = v.load_manifest(cfg.paths.manifest_path)
        result = v.verify(repo_root, manifest)
        if result.ok:
            print("Integridad OK")
            return 0
        print(f"VIOLACIÓN DE INTEGRIDAD: mismatched={result.mismatched} "
              f"missing={result.missing} extra={result.extra}")
        return 1
    print(f"Acción inválida: {action} (usa snapshot|verify)")
    return 2
```

- [ ] **Step 4:** En `_run_loop`, tras construir `response_engine`:
  (a) modo efectivo desde RuntimeState y chequeo de integridad en arranque:
```python
    runtime_state = RuntimeState(cfg.paths.state_file)
    effective_mode = runtime_state.get_mode(default=cfg.mode)
    if response_engine is not None:
        response_engine.set_mode(effective_mode)
        # anti-tampering: si hay manifest y no verifica -> forzar dry_run
        if cfg.integrity.enabled and cfg.paths.manifest_path.exists():
            repo_root = Path(__file__).resolve().parent.parent.parent
            verifier = IntegrityVerifier()
            res = verifier.verify(repo_root, verifier.load_manifest(cfg.paths.manifest_path))
            if not res.ok:
                _log.critical("integrity_violation",
                              extra={"mismatched": res.mismatched, "missing": res.missing,
                                     "extra": res.extra})
                response_engine.set_mode("dry_run")
```
  (b) arrancar IPC server (si habilitado) con un dispatcher mínimo:
```python
    ipc_server: IpcServer | None = None
    if cfg.ipc.enabled:
        transport = NamedPipeTransport(pipe_name=cfg.ipc.pipe_name)
        dispatcher = IpcDispatcher()
        dispatcher.register("status", lambda a: {
            "events": store.count(), "findings": fstore.count(),
            "mode": response_engine.mode if response_engine else cfg.mode})
        dispatcher.register("mode", lambda a: _ipc_set_mode(
            runtime_state, response_engine, str(a.get("mode", ""))))
        ipc_server = IpcServer(transport, dispatcher)
        ipc_server.start()
        if not transport.available():
            _log.info("ipc_disabled_no_pywin32")
```
  (c) en el bucle del reporter o un watcher, re-leer el modo en caliente. Más simple: en `_report_loop`, cada intervalo, aplicar el modo persistido. Pasar `runtime_state` y `response_engine` a `_report_loop` y al inicio del while:
```python
        persisted = runtime_state.get_mode(default=cfg.mode)
        if response_engine is not None and persisted != response_engine.mode:
            response_engine.set_mode(persisted)
```
  (d) en el `finally`, `if ipc_server is not None: ipc_server.stop()`.

Añadir helper:
```python
def _ipc_set_mode(runtime_state: RuntimeState, response_engine: ResponseEngine | None,
                  mode: str) -> dict[str, str]:
    from cerberus.core.config import _VALID_MODES
    if mode not in _VALID_MODES:
        return {"error": f"invalid mode {mode}"}
    runtime_state.set_mode(mode)
    if response_engine is not None:
        response_engine.set_mode(mode)
    return {"mode": mode}
```

> Nota: el watcher de hot-mode en `_report_loop` corre cada `reporting.interval_seconds`. Para reacción más rápida en producción, M6 puede añadir un poll dedicado; para M5 el intervalo del reporter es suficiente y testeable.

- [ ] **Step 5:** En `cerberus_local.py`, añadir subcomando `integrity`:
```python
    ig = sub.add_parser("integrity")
    ig.add_argument("action", choices=["snapshot", "verify"])
    ig.add_argument("--config", type=Path, default=None)
```
y en `main`: `if args.command == "integrity": return cmd_integrity(cfg, args.action)` (importar `cmd_integrity`).

- [ ] **Step 6:** Tests en `tests/unit/test_cli_commands.py`:
```python
def test_cmd_mode_persists_to_state(tmp_path: Path) -> None:
    from cerberus.cli.commands import cmd_mode
    from cerberus.core.runtime_state import RuntimeState
    cfg = _make_cfg(tmp_path)
    assert cmd_mode(cfg, "auto_all") == 0
    assert RuntimeState(cfg.paths.state_file).get_mode(default="dry_run") == "auto_all"


def test_cmd_integrity_snapshot_then_verify(tmp_path: Path) -> None:
    from cerberus.cli.commands import cmd_integrity
    cfg = _make_cfg(tmp_path)
    assert cmd_integrity(cfg, "snapshot") == 0
    assert cfg.paths.manifest_path.exists()
    assert cmd_integrity(cfg, "verify") == 0


def test_cmd_integrity_verify_without_manifest(tmp_path: Path) -> None:
    from cerberus.cli.commands import cmd_integrity
    assert cmd_integrity(_make_cfg(tmp_path), "verify") == 2
```
> Nota: `_make_cfg` debe usar `manifest_path = tmp_path / "manifest.json"` (ya añadido en Task 1) para que snapshot/verify operen en tmp.

- [ ] **Step 7:** Gates (redirect): `pytest tests/unit/test_cli_commands.py`, full suite, `ruff check .`, `mypy cerberus cerberus_local.py`, `cerberus_local.py version` → 0.5.0. Aplicar `ruff --fix` si hay orden de imports.

- [ ] **Step 8:** Commit:
```bash
git add cerberus/cli/commands.py cerberus_local.py tests/unit/test_cli_commands.py
git commit -m "feat(cli): wire IPC server, startup integrity check, hot-mode watcher, integrity cmd"
```
Trailer: `Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>`

---

## Task 9: Integration test M5

**Files:** `tests/integration/test_service_m5.py`

- [ ] **Step 1:** `tests/integration/test_service_m5.py`:
```python
import dataclasses
from pathlib import Path

import pytest

from cerberus.core.event import Event, Severity
from cerberus.core.finding import Finding
from cerberus.core.runtime_state import RuntimeState
from cerberus.response.action_store import ActionStore
from cerberus.response.actions import Action, ActionResult, PolicyDecision
from cerberus.response.engine import ResponseEngine
from cerberus.response.rate_limiter import RateLimiter
from cerberus.service.integrity import IntegrityVerifier
from cerberus.service.ipc import IpcClient, IpcDispatcher, IpcServer, InMemoryTransport


class _FakePolicy:
    def decide(self, finding):
        return [PolicyDecision(Action("kill_pid", {"pid": 1}), "p1", False)]


class _FakeExecutor:
    def __init__(self): self.runs = 0
    def build(self, action):
        from cerberus.response.executor import _Built
        return _Built("CMD", "REV", True, "ok")
    def run(self, action):
        self.runs += 1
        return ActionResult(action=action, executed=True, success=True, output="",
                            command="CMD", reverted_command="REV", reason="authorized")


def _finding():
    evs = [Event(source="fs", type="mass_rename", host="H", pid=1, user="u",
                 raw={}, indicators={})]
    f = Finding.from_cluster(host="H", pid=1, user="u", evidence=evs)
    return dataclasses.replace(f, severity=Severity.CRITICAL, severity_base=Severity.CRITICAL)


def _engine(tmp_path, mode):
    store = ActionStore(tmp_path / "a.db"); store.init_schema()
    ex = _FakeExecutor()
    eng = ResponseEngine(
        policy_engine=_FakePolicy(), executor=ex, action_store=store,
        rate_limiter=RateLimiter(10, 1), mode=mode, killswitch_path=tmp_path / "KS",
        auto_critical_categories=frozenset({"mass_rename"}))
    return eng, ex


@pytest.mark.asyncio
async def test_m5_hot_mode_via_ipc_changes_execution(tmp_path):
    eng, ex = _engine(tmp_path, "dry_run")
    rs = RuntimeState(tmp_path / "state.json")
    # IPC server con handler que cambia el modo en caliente
    d = IpcDispatcher()
    def set_mode(args):
        rs.set_mode(args["mode"]); eng.set_mode(args["mode"]); return {"mode": args["mode"]}
    d.register("mode", set_mode)
    server = IpcServer(InMemoryTransport(), d); server.start()
    client = IpcClient(server._transport)  # mismo transporte

    await eng.handle(_finding())
    assert ex.runs == 0                       # dry_run
    resp = client.request("mode", mode="auto_all")
    assert resp["ok"] and resp["data"]["mode"] == "auto_all"
    await eng.handle(_finding())
    assert ex.runs == 1                       # tras IPC hot-switch, ejecuta
    assert rs.get_mode(default="dry_run") == "auto_all"   # persistido
    server.stop()


def test_m5_integrity_snapshot_and_tamper_detection(tmp_path):
    # construir manifest de un arbol falso, alterar, detectar
    (tmp_path / "cerberus").mkdir()
    (tmp_path / "cerberus" / "x.py").write_text("a = 1", encoding="utf-8")
    v = IntegrityVerifier()
    manifest = v.build_manifest(tmp_path)
    assert v.verify(tmp_path, manifest).ok is True
    (tmp_path / "cerberus" / "x.py").write_text("a = 2", encoding="utf-8")
    assert v.verify(tmp_path, manifest).ok is False
```

- [ ] **Step 2:** `pytest tests/integration/test_service_m5.py -v` (redirect) → 2 passed.

- [ ] **Step 3:** Full gate (redirect): `pytest` con coverage ≥85%, `ruff check .`, `mypy cerberus cerberus_local.py` limpios.

- [ ] **Step 4:** Commit:
```bash
git add tests/integration/test_service_m5.py
git commit -m "test(integration): add M5 service core (IPC hot-mode + integrity tamper detection)"
```
Trailer: `Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>`

---

## Task 10: Guía de campo M6 + README M5

**Files:** `docs/M6_FIELD_GUIDE.md`, `README.md`

- [ ] **Step 1:** Crear `docs/M6_FIELD_GUIDE.md` documentando los pasos manuales (no automatizables en este entorno) para producción en Windows real:
  - **Windows Service:** envolver `cerberus_local.py start` en una subclase `win32serviceutil.ServiceFramework` (esqueleto), `sc create Cerberus binPath= ...` / instalación pywin32, `failure_actions=restart`.
  - **Named pipe real:** verificar `NamedPipeTransport.available()` True con pywin32; el server del pipe corre dentro del Service; `cerberus status` se conecta vía `\\.\pipe\cerberus`.
  - **Anti-tampering:** `cerberus integrity snapshot` tras instalar (firma el árbol); el Service verifica al arrancar; ACL `SYSTEM:F` sobre binarios y cuarentena (icacls / TakeOwnership).
  - **Npcap + pyshark/dns_query:** instalar Npcap; añadir `PySharkProbe` a NetCollector (emite `dns_query`); degradación si ausente.
  - **`.msi` (WiX):** estructura del `.wxs`, harvesting, firma del instalador, SBOM + hashes SHA256.
  - **Redteam (VM aislada):** TTPs MITRE (T1059.001, T1071.001, T1486, T1078, T1543.003); snapshot/restore; métricas MTTD/FP; `tests/redteam_reports/`.
  - **Checklist pre-release** (del spec §9.5): N1+N2 CI verde, N3 en VM, install/uninstall limpios, killswitch verificado, baseline CPU<5%/RAM<200MB 24h, auditoría `auditing-security`.

- [ ] **Step 2:** Reemplazar `README.md` (encabezado M5, componentes de servicio, comandos `mode`/`integrity`, hot-mode, anti-tampering, IPC; nota de que el Service/.msi/Npcap/redteam son M6 de campo; estado de tests; aviso legal).

- [ ] **Step 3:** Commit:
```bash
git add docs/M6_FIELD_GUIDE.md README.md
git commit -m "docs: add M6 field guide (service/.msi/npcap/redteam) and M5 README"
```
Trailer: `Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>`

---

## Task 11: Auditoría de seguridad + tag v0.5.0-m5

> **Antes de cerrar:** invocar `auditing-security` con foco en la nueva superficie (IPC, integridad, state file).

- [ ] **Step 1: Auditoría `auditing-security`** — checklist:
- **IPC:** el dispatcher valida `command` contra handlers registrados (deny-by-default: comando desconocido → error, no ejecuta nada). `mode` valida contra `_VALID_MODES`. El named pipe real (M6) debe restringir ACL del pipe a admin/SYSTEM (documentado en field guide). El transporte JSON no deserializa objetos arbitrarios (`json.loads`, no `pickle`). ✓
- **Integridad:** `IntegrityVerifier` solo lee archivos + sha256; no ejecuta. La acción ante mismatch es **fail-safe** (forzar `dry_run`, no abrir). ✓
- **RuntimeState:** escritura atómica (`os.replace`), `json.loads` (no eval); modo inválido rechazado. El archivo state.json no contiene secretos. ✓
- **A05/inyección:** ningún `shell=True` nuevo; named_pipe no construye comandos. ✓
- **Hot-mode no bypassa gates:** cambiar a `auto_*` sigue pasando por killswitch/confirmation/rate-limit del ResponseEngine (G3 intacto). ✓
- **NetCollector hardening:** la purga solo elimina estado en memoria; sin impacto de seguridad. ✓
Registrar resultado en el commit. Aplicar fixes con su test si surge algo.

- [ ] **Step 2:** Build final verde (redirect): `pytest` ≥85%, `ruff check .`, `mypy cerberus cerberus_local.py`.

- [ ] **Step 3:** Commit (si hubo fixes) + tag:
```bash
git commit -m "docs: M5 security audit pass (deny-by-default IPC, fail-safe integrity, atomic state)"
git tag -a v0.5.0-m5 -m "M5: IPC + hot-mode + anti-tampering + NetCollector hardening (service core)"
```

---

## Checklist final M5
- [ ] Pre-flight: rama `m5/service-core` desde `master`@`v0.4.0-m4`
- [ ] 11 tareas completadas (tests verdes por tarea)
- [ ] Coverage ≥ 85%, `ruff` limpio, `mypy --strict` limpio
- [ ] LOW de M2 cerrado (NetCollector purga claves beacon)
- [ ] Hot-mode: `cerberus mode <m>` persiste y un agente corriendo lo aplica; integridad fuerza dry_run on mismatch (fail-safe); G3 intacto
- [ ] IPC testeable (dispatcher + InMemoryTransport); named pipe real degrada con gracia
- [ ] Capa pywin32 (named pipe real, Service real) NO unit-tested (M6 de campo), degradación probada
- [ ] `docs/M6_FIELD_GUIDE.md` con los pasos manuales de Windows
- [ ] Auditoría `auditing-security` ejecutada
- [ ] Tag `v0.5.0-m5` creado

## Próximo (M6 — campo, manual en Windows real)
`.msi` WiX · registro real del Windows Service (`win32serviceutil`) · Npcap + pyshark/`dns_query` · redteam en VM aislada · ACLs/TakeOwnership cuarentena · persistencia/poll dedicado de hot-mode. Ver `docs/M6_FIELD_GUIDE.md`.
