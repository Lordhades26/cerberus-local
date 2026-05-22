# CERBERUS-LOCAL · Plan M2 — Collectors restantes + Correlator

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Completar la **Cabeza 1 (Telemetría)** con tres collectors nuevos (`NetCollector`, `FsCollector`, `EvtCollector`) corriendo en paralelo con el `ProcCollector` de M1, y arrancar la **Cabeza 2 (Detección)** con un `Correlator` heurístico que agrupa eventos en `Finding`s por ventana temporal, los persiste en `findings.db` y los incluye en el reporte Markdown. Sin reglas Sigma, sin IA, sin respuesta automática — solo telemetría multi-fuente → bus → correlación → persistencia → reporte.

**Architecture:** Capa 100% heurística (ningún LLM en M2 — respeta el invariante ≥80% heurístico del spec §10.5). Los cuatro collectors emiten `Event` normalizados al `EventBus` existente. El `Correlator` se suscribe al bus, mantiene una ventana deslizante de eventos, agrupa por `(host, pid, user)` y promueve clusters multi-fuente a `Finding`. Cada `Finding` se persiste vía `FindingStore` (nueva tabla SQLite) y se inyecta al buffer del `MarkdownReportWriter`. En M3, el `RuleEngine` se insertará en la cadena entre el `Correlator` y el store sin romper interfaces.

**Tech Stack:** Python 3.11+, `asyncio`, `psutil` (red por polling), `watchdog` (FS, cross-platform), `pywin32`/`win32evtlog` (event log, solo Windows — degrada con gracia en otros SO), `pyyaml`, `pytest`, `pytest-asyncio`, SQLite stdlib, `ruff`, `mypy`.

**Reference spec:** `docs/superpowers/specs/2026-05-21-cerberus-local-edr-design.md`

---

## Scope refinement vs spec (decisiones aprobadas 2026-05-21)

1. **NetCollector usa polling `psutil.net_connections()` en M2, NO pyshark.** El spec §4.2 mapea NetCollector a `pyshark.LiveCapture + Npcap`. pyshark añade dependencia de Wireshark/tshark, instalador Npcap y privilegios admin, e impide testear cross-platform. **El spec §7.2 ya contempla la ausencia de Npcap como degradación válida.** En M2, NetCollector emite `outbound_conn` y `beaconing_suspect` por heurística sobre conexiones observadas con `psutil`. La captura de paquetes (`dns_query`, enriquecimiento por payload) se difiere a **M3**, donde aterriza junto al `RuleEngine` que es quien más se beneficia de inspección profunda.

2. **El Correlator persiste cada `Finding` en `findings.db` (nueva tabla) y lo añade al buffer del reporte.** No hay `RuleEngine` ni `AIAnalyst` en M2; el `Finding` lleva `severity_base = MEDIUM` fijo (placeholder heurístico hasta que M3 introduzca reglas con severidad propia). La interfaz `on_finding` permite insertar el `RuleEngine` en M3 sin reescribir el Correlator.

3. **`EvtCollector` degrada con gracia fuera de Windows.** Si `win32evtlog` no se puede importar (Linux/macOS dev, o pywin32 ausente), el collector arranca con `health.running=False`, loguea `INFO evt_collector_unavailable` y el resto del sistema sigue. Esto permite ejecutar toda la suite M2 en CI cross-platform; los tests del path real Windows usan un subscriber falso inyectable.

---

## File Structure (qué se crea/modifica en M2)

```
cerberus-local/
├── pyproject.toml                       # MODIFICAR: version 0.2.0, +watchdog, +pywin32 (extra windows)
├── config/
│   └── cerberus.default.yml             # MODIFICAR: bloques net/fs/evt/correlator + findings_db
├── cerberus/
│   ├── __init__.py                      # MODIFICAR: __version__ = "0.2.0"
│   ├── core/
│   │   ├── config.py                    # MODIFICAR: dataclasses Net/Fs/Evt/Correlator config
│   │   ├── finding.py                   # CREAR: Finding dataclass
│   │   └── db.py                        # SIN CAMBIOS (events.db). findings.db va en finding_store.py
│   ├── collectors/
│   │   ├── net.py                       # CREAR: NetCollector (psutil polling + beaconing heurístico)
│   │   ├── fs.py                        # CREAR: FsCollector (watchdog)
│   │   └── evt.py                       # CREAR: EvtCollector (win32evtlog, subscriber inyectable)
│   ├── detection/
│   │   ├── __init__.py                  # CREAR (paquete nuevo)
│   │   ├── correlator.py                # CREAR: Correlator (ventana deslizante)
│   │   └── finding_store.py             # CREAR: FindingStore (SQLite findings.db)
│   ├── reporting/
│   │   └── markdown.py                  # MODIFICAR: sección de findings en el reporte
│   └── cli/
│       └── commands.py                  # MODIFICAR: arrancar 4 collectors + correlator; status muestra findings
└── tests/
    ├── unit/
    │   ├── test_finding.py              # CREAR
    │   ├── test_finding_store.py        # CREAR
    │   ├── test_net_collector.py        # CREAR
    │   ├── test_fs_collector.py         # CREAR
    │   ├── test_evt_collector.py        # CREAR
    │   ├── test_correlator.py           # CREAR
    │   ├── test_config.py               # MODIFICAR: cubrir nuevas secciones de config
    │   └── test_report_markdown.py      # MODIFICAR: cubrir sección findings
    └── integration/
        └── test_pipeline_m2.py          # CREAR: E2E 4 collectors → correlator → findings → DB → markdown
```

**Out of scope (vienen en hitos posteriores):**
- M3: `pyshark`/Npcap packet capture, `dns_query`; `RuleEngine`, `AIAnalyst`, `OllamaClient`, `PolicyEngine`, `ResponseEngine`, acciones, rollback, guardrails LLM.
- M4: `CerberusService` (Windows Service), named pipe IPC, `.msi`, killswitch, anti-tampering, redteam tests.

---

## Pre-flight (antes de la Task 1)

> Hay un diff de lint/typing sin commitear sobre el tag `v0.1.0-m1` (ajustes `datetime.UTC`, `collections.abc`, etc.). Consolidarlo primero para que M2 arranque desde un árbol limpio.

- [ ] **Step 1: Revisar y commitear el diff de M1 pendiente**

Run: `git status`
Expected: lista de modificados en `cerberus/` y `tests/`.

Run: `pytest && ruff check . && mypy cerberus cerberus_local.py`
Expected: todo verde (35 tests passed, coverage ≥ 85%).

```bash
git add cerberus tests cerberus_local.py docs
git commit -m "chore(m1): consolidate lint/typing fixups and add specs/plans docs"
```

- [ ] **Step 2: Verificar baseline limpio**

Run: `git status`
Expected: `nothing to commit, working tree clean`.

---

## Task 1: Bump de versión, dependencias y config base

**Files:**
- Modify: `pyproject.toml`
- Modify: `cerberus/__init__.py`
- Modify: `config/cerberus.default.yml`

- [ ] **Step 1: Subir versión en `cerberus/__init__.py`**

Reemplazar el contenido completo por:
```python
__version__ = "0.2.0"
```

- [ ] **Step 2: Actualizar `pyproject.toml`**

Cambiar la línea `version = "0.1.0"` por `version = "0.2.0"`.

Reemplazar el bloque `dependencies` y añadir un extra `windows`:
```toml
dependencies = [
    "psutil>=5.9.8",
    "pyyaml>=6.0.1",
    "watchdog>=4.0.0",
]

[project.optional-dependencies]
windows = [
    "pywin32>=306",
]
dev = [
    "pytest>=8.0",
    "pytest-asyncio>=0.23",
    "pytest-cov>=4.1",
    "ruff>=0.4",
    "mypy>=1.10",
]
```

El gate de coverage en `[tool.pytest.ini_options]` se mantiene en `--cov-fail-under=85` (los nuevos módulos con APIs de SO degradable no deben bajar el global).

Añadir AL FINAL del `pyproject.toml` los overrides de mypy para librerías sin stubs de tipos (evita errores `import-untyped` bajo `strict`):
```toml
[[tool.mypy.overrides]]
module = ["watchdog.*", "win32evtlog", "win32evtlogutil", "psutil"]
ignore_missing_imports = true
```

- [ ] **Step 3: Extender `config/cerberus.default.yml`**

Reemplazar el contenido completo por:
```yaml
# Cerberus M2 default config
mode: dry_run                       # dry_run | monitor (auto_* vienen en M3)
host_name: null                     # null = autodetect

paths:
  data_dir: "C:\\ProgramData\\Cerberus"
  events_db: "C:\\ProgramData\\Cerberus\\db\\events.db"
  findings_db: "C:\\ProgramData\\Cerberus\\db\\findings.db"
  reports_dir: "C:\\Users\\Public\\cerberus_reports"
  log_file: "C:\\ProgramData\\Cerberus\\logs\\cerberus.log"

collectors:
  proc:
    enabled: true
    poll_interval_seconds: 1.0
  net:
    enabled: true
    poll_interval_seconds: 2.0
    beaconing_window_seconds: 60
    beaconing_min_connections: 10
  fs:
    enabled: true
    watch_paths:
      - "C:\\Users\\Public"
    mass_rename_threshold: 20
    mass_rename_window_seconds: 5
    high_entropy_threshold: 7.5
  evt:
    enabled: true                   # auto-deshabilitado si win32evtlog no está disponible
    channels:
      - "Security"
      - "Microsoft-Windows-Sysmon/Operational"
      - "Microsoft-Windows-PowerShell/Operational"

correlator:
  window_seconds: 10
  min_sources_for_finding: 2

reporting:
  interval_seconds: 300              # 5 minutos
  retention_days: 7
```

- [ ] **Step 4: Reinstalar deps y verificar versión**

Run: `pip install -e ".[dev]"`
Expected: instala `watchdog`, sin errores.

Run: `python -c "import cerberus; print(cerberus.__version__)"`
Expected: `0.2.0`

- [ ] **Step 5: Commit**

```bash
git add pyproject.toml cerberus/__init__.py config/cerberus.default.yml
git commit -m "chore(m2): bump to 0.2.0, add watchdog/pywin32 deps and collector config"
```

---

## Task 2: `Finding` dataclass

**Files:**
- Create: `cerberus/core/finding.py`
- Test: `tests/unit/test_finding.py`

- [ ] **Step 1: Escribir tests fallidos**

`tests/unit/test_finding.py`:
```python
from datetime import UTC, datetime

from cerberus.core.event import Event, Severity
from cerberus.core.finding import Finding


def _ev(source="proc", type_="new_process", pid=10):
    return Event(
        source=source, type=type_, host="H", pid=pid,
        user="u", raw={}, indicators={"name": "x.exe"},
    )


def test_finding_from_cluster_basic():
    evs = [_ev("proc", "new_process"), _ev("net", "outbound_conn")]
    f = Finding.from_cluster(host="H", pid=10, user="u", evidence=evs)
    assert isinstance(f.id, str) and len(f.id) == 36
    assert f.timestamp.tzinfo == UTC
    assert f.host == "H"
    assert f.pid == 10
    assert f.severity == Severity.MEDIUM           # base heurística M2
    assert f.sources == {"proc", "net"}
    assert f.primary_event_id == evs[0].id         # primer evento del cluster


def test_finding_categories_derived_from_event_types():
    evs = [_ev("fs", "mass_rename"), _ev("proc", "new_process")]
    f = Finding.from_cluster(host="H", pid=5, user="u", evidence=evs)
    assert "mass_rename" in f.categories
    assert "new_process" in f.categories


def test_finding_to_dict_is_json_serializable():
    import json
    evs = [_ev("proc", "new_process"), _ev("net", "outbound_conn")]
    f = Finding.from_cluster(host="H", pid=10, user="u", evidence=evs)
    d = f.to_dict()
    assert d["host"] == "H"
    assert d["severity"] == int(Severity.MEDIUM)
    assert isinstance(d["timestamp"], str)
    assert isinstance(d["evidence"], list) and len(d["evidence"]) == 2
    json.dumps(d)  # no debe lanzar


def test_finding_empty_evidence_raises():
    import pytest
    with pytest.raises(ValueError):
        Finding.from_cluster(host="H", pid=1, user="u", evidence=[])
```

- [ ] **Step 2: Correr y verificar fallo**

Run: `pytest tests/unit/test_finding.py -v`
Expected: FAIL con `ModuleNotFoundError: cerberus.core.finding`.

- [ ] **Step 3: Implementar `cerberus/core/finding.py`**

```python
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from cerberus.core.event import Event, Severity


@dataclass(frozen=True)
class Finding:
    """Cluster de eventos correlacionados promovido por el Correlator.

    En M2 la severidad es siempre MEDIUM (base heurística). En M3 el RuleEngine
    ajustará `severity` según reglas Sigma-like y el AIAnalyst la afinará ±1 nivel.
    """

    host: str
    pid: int | None
    user: str | None
    evidence: tuple[Event, ...]
    severity: Severity = Severity.MEDIUM
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))

    @classmethod
    def from_cluster(
        cls,
        host: str,
        pid: int | None,
        user: str | None,
        evidence: list[Event],
        severity: Severity = Severity.MEDIUM,
    ) -> Finding:
        if not evidence:
            raise ValueError("Finding requires at least one evidence event")
        return cls(
            host=host,
            pid=pid,
            user=user,
            evidence=tuple(evidence),
            severity=severity,
        )

    @property
    def sources(self) -> set[str]:
        return {ev.source for ev in self.evidence}

    @property
    def categories(self) -> set[str]:
        return {ev.type for ev in self.evidence}

    @property
    def primary_event_id(self) -> str:
        return self.evidence[0].id

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "host": self.host,
            "pid": self.pid,
            "user": self.user,
            "severity": int(self.severity),
            "sources": sorted(self.sources),
            "categories": sorted(self.categories),
            "primary_event_id": self.primary_event_id,
            "evidence": [ev.to_dict() for ev in self.evidence],
        }
```

- [ ] **Step 4: Correr tests, verificar que pasan**

Run: `pytest tests/unit/test_finding.py -v`
Expected: 4 passed.

- [ ] **Step 5: Commit**

```bash
git add cerberus/core/finding.py tests/unit/test_finding.py
git commit -m "feat(core): add Finding dataclass for correlated event clusters"
```

---

## Task 3: `FindingStore` (SQLite findings.db)

**Files:**
- Create: `cerberus/detection/__init__.py`
- Create: `cerberus/detection/finding_store.py`
- Test: `tests/unit/test_finding_store.py`

- [ ] **Step 1: Crear `cerberus/detection/__init__.py` vacío**

Archivo de 0 bytes.

- [ ] **Step 2: Escribir tests fallidos**

`tests/unit/test_finding_store.py`:
```python
from pathlib import Path

import pytest

from cerberus.core.event import Event, Severity
from cerberus.core.finding import Finding
from cerberus.detection.finding_store import FindingStore


def _ev(source="proc", type_="new_process", pid=10):
    return Event(source=source, type=type_, host="H", pid=pid,
                 user="u", raw={}, indicators={})


def _finding(pid=10):
    evs = [_ev("proc", "new_process", pid), _ev("net", "outbound_conn", pid)]
    return Finding.from_cluster(host="H", pid=pid, user="u", evidence=evs)


@pytest.fixture
def store(tmp_path: Path) -> FindingStore:
    s = FindingStore(tmp_path / "findings.db")
    s.init_schema()
    return s


def test_init_schema_creates_table(store: FindingStore):
    assert store.table_exists("findings")


def test_insert_and_count(store: FindingStore):
    store.insert(_finding())
    store.insert(_finding(pid=20))
    assert store.count() == 2


def test_fetch_all_roundtrips_fields(store: FindingStore):
    f = _finding()
    store.insert(f)
    rows = store.fetch_all()
    assert len(rows) == 1
    row = rows[0]
    assert row["id"] == f.id
    assert row["host"] == "H"
    assert row["severity"] == int(Severity.MEDIUM)
    assert "proc" in row["sources"] and "net" in row["sources"]


def test_fetch_by_min_severity(store: FindingStore):
    low = Finding.from_cluster(host="H", pid=1, user="u",
                               evidence=[_ev()], severity=Severity.LOW)
    crit = Finding.from_cluster(host="H", pid=2, user="u",
                                evidence=[_ev()], severity=Severity.CRITICAL)
    store.insert(low)
    store.insert(crit)
    high_only = store.fetch_by_min_severity(Severity.HIGH)
    assert len(high_only) == 1
    assert high_only[0]["id"] == crit.id


def test_purge_older_than_days(store: FindingStore):
    from datetime import UTC, datetime, timedelta
    old_evs = [_ev()]
    old = Finding(host="H", pid=1, user="u", evidence=tuple(old_evs),
                  timestamp=datetime.now(UTC) - timedelta(days=100))
    store.insert(old)
    store.insert(_finding())
    deleted = store.purge_older_than(days=90)
    assert deleted == 1
    assert store.count() == 1
```

- [ ] **Step 3: Correr y verificar fallo**

Run: `pytest tests/unit/test_finding_store.py -v`
Expected: FAIL con `ModuleNotFoundError`.

- [ ] **Step 4: Implementar `cerberus/detection/finding_store.py`**

```python
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from cerberus.core.event import Severity
from cerberus.core.finding import Finding

_SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    id                TEXT PRIMARY KEY,
    timestamp         TEXT NOT NULL,
    host              TEXT NOT NULL,
    pid               INTEGER,
    user              TEXT,
    severity          INTEGER NOT NULL,
    sources           TEXT NOT NULL,
    categories        TEXT NOT NULL,
    primary_event_id  TEXT NOT NULL,
    evidence          TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_timestamp ON findings(timestamp);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
"""


class FindingStore:
    def __init__(self, path: Path | str) -> None:
        import sqlite3

        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.path, isolation_level=None)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.row_factory = sqlite3.Row

    def init_schema(self) -> None:
        self._conn.executescript(_SCHEMA)

    def table_exists(self, name: str) -> bool:
        row = self._conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
            (name,),
        ).fetchone()
        return row is not None

    def insert(self, finding: Finding) -> None:
        d = finding.to_dict()
        self._conn.execute(
            """
            INSERT INTO findings(
                id, timestamp, host, pid, user, severity,
                sources, categories, primary_event_id, evidence
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                d["id"],
                d["timestamp"],
                d["host"],
                d["pid"],
                d["user"],
                d["severity"],
                json.dumps(d["sources"]),
                json.dumps(d["categories"]),
                d["primary_event_id"],
                json.dumps(d["evidence"]),
            ),
        )

    def _row_to_dict(self, row: Any) -> dict[str, Any]:
        d = dict(row)
        d["sources"] = json.loads(d["sources"])
        d["categories"] = json.loads(d["categories"])
        d["evidence"] = json.loads(d["evidence"])
        return d

    def fetch_all(self) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT * FROM findings ORDER BY timestamp"
        ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def fetch_by_min_severity(self, severity: Severity) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT * FROM findings WHERE severity >= ? ORDER BY timestamp",
            (int(severity),),
        ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def count(self) -> int:
        row = self._conn.execute("SELECT COUNT(*) AS n FROM findings").fetchone()
        return int(row["n"])

    def purge_older_than(self, days: int) -> int:
        cutoff = (datetime.now(UTC) - timedelta(days=days)).isoformat()
        cur = self._conn.execute(
            "DELETE FROM findings WHERE timestamp < ?", (cutoff,)
        )
        return cur.rowcount

    def close(self) -> None:
        self._conn.close()
```

- [ ] **Step 5: Correr tests**

Run: `pytest tests/unit/test_finding_store.py -v`
Expected: 5 passed.

- [ ] **Step 6: Commit**

```bash
git add cerberus/detection/__init__.py cerberus/detection/finding_store.py tests/unit/test_finding_store.py
git commit -m "feat(detection): add FindingStore with SQLite WAL persistence"
```

---

## Task 4: Extender `config.py` para net/fs/evt/correlator

**Files:**
- Modify: `cerberus/core/config.py`
- Modify: `tests/unit/test_config.py`

- [ ] **Step 1: Añadir tests fallidos a `tests/unit/test_config.py`**

Añadir AL FINAL del archivo existente:
```python
def test_load_m2_collectors_and_correlator(tmp_path):
    from pathlib import Path
    cfg_file = tmp_path / "c.yml"
    cfg_file.write_text(
        """
mode: dry_run
host_name: null
paths:
  data_dir: /tmp/cerberus
  events_db: /tmp/cerberus/events.db
  findings_db: /tmp/cerberus/findings.db
  reports_dir: /tmp/cerberus_reports
  log_file: /tmp/cerberus.log
collectors:
  proc: {enabled: true, poll_interval_seconds: 1.0}
  net:
    enabled: true
    poll_interval_seconds: 2.0
    beaconing_window_seconds: 60
    beaconing_min_connections: 10
  fs:
    enabled: true
    watch_paths: ["/tmp/watch"]
    mass_rename_threshold: 20
    mass_rename_window_seconds: 5
    high_entropy_threshold: 7.5
  evt:
    enabled: true
    channels: ["Security"]
correlator:
  window_seconds: 10
  min_sources_for_finding: 2
reporting:
  interval_seconds: 300
  retention_days: 7
""",
        encoding="utf-8",
    )
    from cerberus.core.config import load_config
    cfg = load_config(cfg_file)
    assert cfg.paths.findings_db == Path("/tmp/cerberus/findings.db")
    assert cfg.collectors.net.beaconing_min_connections == 10
    assert cfg.collectors.fs.watch_paths == [Path("/tmp/watch")]
    assert cfg.collectors.fs.high_entropy_threshold == 7.5
    assert cfg.collectors.evt.channels == ["Security"]
    assert cfg.correlator.window_seconds == 10
    assert cfg.correlator.min_sources_for_finding == 2


def test_m2_collectors_have_defaults_when_absent(tmp_path):
    cfg_file = tmp_path / "c.yml"
    cfg_file.write_text(
        """
mode: dry_run
host_name: null
paths: {data_dir: /tmp/c, events_db: /tmp/c.db, findings_db: /tmp/f.db, reports_dir: /tmp/r, log_file: /tmp/l}
collectors: {proc: {enabled: true, poll_interval_seconds: 1.0}}
reporting: {interval_seconds: 60, retention_days: 1}
""",
        encoding="utf-8",
    )
    from cerberus.core.config import load_config
    cfg = load_config(cfg_file)
    # net/fs/evt/correlator ausentes → defaults razonables, enabled según default
    assert cfg.collectors.net.enabled is True
    assert cfg.collectors.fs.mass_rename_threshold == 20
    assert cfg.collectors.evt.channels  # lista no vacía por defecto
    assert cfg.correlator.window_seconds == 10
```

- [ ] **Step 2: Correr y verificar fallo**

Run: `pytest tests/unit/test_config.py -v`
Expected: FAIL en los dos tests nuevos (atributos inexistentes).

- [ ] **Step 3: Reemplazar `cerberus/core/config.py` completo**

```python
from __future__ import annotations

import socket
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

import yaml

Mode = Literal["dry_run", "monitor"]
_VALID_MODES = {"dry_run", "monitor"}

_DEFAULT_EVT_CHANNELS = [
    "Security",
    "Microsoft-Windows-Sysmon/Operational",
    "Microsoft-Windows-PowerShell/Operational",
]


@dataclass(frozen=True)
class ProcCollectorConfig:
    enabled: bool
    poll_interval_seconds: float


@dataclass(frozen=True)
class NetCollectorConfig:
    enabled: bool
    poll_interval_seconds: float
    beaconing_window_seconds: int
    beaconing_min_connections: int


@dataclass(frozen=True)
class FsCollectorConfig:
    enabled: bool
    watch_paths: list[Path]
    mass_rename_threshold: int
    mass_rename_window_seconds: int
    high_entropy_threshold: float


@dataclass(frozen=True)
class EvtCollectorConfig:
    enabled: bool
    channels: list[str]


@dataclass(frozen=True)
class CollectorsConfig:
    proc: ProcCollectorConfig
    net: NetCollectorConfig
    fs: FsCollectorConfig
    evt: EvtCollectorConfig


@dataclass(frozen=True)
class CorrelatorConfig:
    window_seconds: int
    min_sources_for_finding: int


@dataclass(frozen=True)
class PathsConfig:
    data_dir: Path
    events_db: Path
    findings_db: Path
    reports_dir: Path
    log_file: Path


@dataclass(frozen=True)
class ReportingConfig:
    interval_seconds: int
    retention_days: int


@dataclass(frozen=True)
class CerberusConfig:
    mode: Mode
    host_name: str
    paths: PathsConfig
    collectors: CollectorsConfig
    correlator: CorrelatorConfig
    reporting: ReportingConfig


def _proc(raw: dict[str, Any]) -> ProcCollectorConfig:
    return ProcCollectorConfig(
        enabled=bool(raw.get("enabled", True)),
        poll_interval_seconds=float(raw.get("poll_interval_seconds", 1.0)),
    )


def _net(raw: dict[str, Any]) -> NetCollectorConfig:
    return NetCollectorConfig(
        enabled=bool(raw.get("enabled", True)),
        poll_interval_seconds=float(raw.get("poll_interval_seconds", 2.0)),
        beaconing_window_seconds=int(raw.get("beaconing_window_seconds", 60)),
        beaconing_min_connections=int(raw.get("beaconing_min_connections", 10)),
    )


def _fs(raw: dict[str, Any]) -> FsCollectorConfig:
    return FsCollectorConfig(
        enabled=bool(raw.get("enabled", True)),
        watch_paths=[Path(p) for p in raw.get("watch_paths", [])],
        mass_rename_threshold=int(raw.get("mass_rename_threshold", 20)),
        mass_rename_window_seconds=int(raw.get("mass_rename_window_seconds", 5)),
        high_entropy_threshold=float(raw.get("high_entropy_threshold", 7.5)),
    )


def _evt(raw: dict[str, Any]) -> EvtCollectorConfig:
    channels = raw.get("channels") or list(_DEFAULT_EVT_CHANNELS)
    return EvtCollectorConfig(
        enabled=bool(raw.get("enabled", True)),
        channels=list(channels),
    )


def load_config(path: Path | str) -> CerberusConfig:
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    mode = raw.get("mode", "dry_run")
    if mode not in _VALID_MODES:
        raise ValueError(f"Invalid mode {mode!r}; valid: {sorted(_VALID_MODES)}")
    host = raw.get("host_name") or socket.gethostname()

    paths_raw = raw.get("paths", {})
    paths = PathsConfig(
        data_dir=Path(paths_raw.get("data_dir", "")),
        events_db=Path(paths_raw.get("events_db", "")),
        findings_db=Path(paths_raw.get("findings_db", "")),
        reports_dir=Path(paths_raw.get("reports_dir", "")),
        log_file=Path(paths_raw.get("log_file", "")),
    )

    coll_raw = raw.get("collectors", {})
    collectors = CollectorsConfig(
        proc=_proc(coll_raw.get("proc", {})),
        net=_net(coll_raw.get("net", {})),
        fs=_fs(coll_raw.get("fs", {})),
        evt=_evt(coll_raw.get("evt", {})),
    )

    corr_raw = raw.get("correlator", {})
    correlator = CorrelatorConfig(
        window_seconds=int(corr_raw.get("window_seconds", 10)),
        min_sources_for_finding=int(corr_raw.get("min_sources_for_finding", 2)),
    )

    rep_raw = raw.get("reporting", {})
    reporting = ReportingConfig(
        interval_seconds=int(rep_raw.get("interval_seconds", 300)),
        retention_days=int(rep_raw.get("retention_days", 7)),
    )

    return CerberusConfig(
        mode=mode,
        host_name=host,
        paths=paths,
        collectors=collectors,
        correlator=correlator,
        reporting=reporting,
    )
```

- [ ] **Step 4: Correr tests de config**

Run: `pytest tests/unit/test_config.py -v`
Expected: todos los tests de config pasan (los 3 de M1 + 2 nuevos).

- [ ] **Step 5: Commit**

```bash
git add cerberus/core/config.py tests/unit/test_config.py
git commit -m "feat(core): extend config with net/fs/evt/correlator and findings_db"
```

---

## Task 5: `NetCollector` (psutil polling + beaconing heurístico)

> **Antes de codear este módulo:** invocar skill `using-context7` para verificar la API actual de `psutil.net_connections(kind=...)` y la forma de `sconn` (`laddr`, `raddr`, `status`, `pid`) en psutil v5.9.8+.

**Files:**
- Create: `cerberus/collectors/net.py`
- Test: `tests/unit/test_net_collector.py`

- [ ] **Step 1: Escribir tests fallidos con mocks de psutil**

`tests/unit/test_net_collector.py`:
```python
import asyncio
from collections import namedtuple
from unittest.mock import patch

import pytest

from cerberus.collectors.net import NetCollector
from cerberus.core.event import Event
from cerberus.core.event_bus import EventBus

_Addr = namedtuple("_Addr", ["ip", "port"])
_SConn = namedtuple("_SConn", ["fd", "family", "type", "laddr", "raddr", "status", "pid"])


def _conn(pid, rip, rport, status="ESTABLISHED"):
    return _SConn(
        fd=1, family=2, type=1,
        laddr=_Addr("192.168.1.5", 50000),
        raddr=_Addr(rip, rport),
        status=status, pid=pid,
    )


async def _collect_events(bus: EventBus, target_count: int, timeout: float = 1.5) -> list[Event]:
    received: list[Event] = []
    done = asyncio.Event()

    async def handler(ev: Event) -> None:
        received.append(ev)
        if len(received) >= target_count:
            done.set()

    bus.subscribe(handler)
    bus.start()
    try:
        await asyncio.wait_for(done.wait(), timeout=timeout)
    except TimeoutError:
        pass
    await bus.stop()
    return received


@pytest.mark.asyncio
async def test_net_collector_emits_outbound_conn_for_new_connection():
    seq = iter([
        [],  # seed: sin conexiones
        [_conn(1000, "185.10.10.10", 443)],  # aparece una nueva
    ])

    def fake_net_connections(kind="inet"):
        try:
            return next(seq)
        except StopIteration:
            return [_conn(1000, "185.10.10.10", 443)]

    bus = EventBus()
    c = NetCollector(host="H", poll_interval_seconds=0.05,
                     beaconing_window_seconds=60, beaconing_min_connections=10)
    with patch("cerberus.collectors.net.psutil.net_connections",
               side_effect=fake_net_connections):
        task = asyncio.create_task(c.start(bus))
        received = await _collect_events(bus, target_count=1, timeout=1.0)
        await c.stop()
        task.cancel()

    outbound = [e for e in received if e.type == "outbound_conn"]
    assert len(outbound) >= 1
    ev = outbound[0]
    assert ev.source == "net"
    assert ev.indicators["remote_ip"] == "185.10.10.10"
    assert ev.indicators["remote_port"] == 443
    assert ev.pid == 1000


@pytest.mark.asyncio
async def test_net_collector_skips_loopback_and_listening():
    loop_conn = _SConn(fd=1, family=2, type=1,
                       laddr=_Addr("127.0.0.1", 1), raddr=_Addr("127.0.0.1", 2),
                       status="ESTABLISHED", pid=1)
    listen_conn = _SConn(fd=2, family=2, type=1,
                         laddr=_Addr("0.0.0.0", 80), raddr=(),
                         status="LISTEN", pid=2)
    seq = iter([[], [loop_conn, listen_conn]])

    def fake_net_connections(kind="inet"):
        try:
            return next(seq)
        except StopIteration:
            return [loop_conn, listen_conn]

    bus = EventBus()
    c = NetCollector(host="H", poll_interval_seconds=0.05,
                     beaconing_window_seconds=60, beaconing_min_connections=10)
    with patch("cerberus.collectors.net.psutil.net_connections",
               side_effect=fake_net_connections):
        task = asyncio.create_task(c.start(bus))
        received = await _collect_events(bus, target_count=1, timeout=0.5)
        await c.stop()
        task.cancel()

    assert [e for e in received if e.type == "outbound_conn"] == []


@pytest.mark.asyncio
async def test_net_collector_emits_beaconing_suspect():
    # mismo destino repetido supera el umbral → beaconing_suspect
    base = [_conn(2000, "9.9.9.9", 443)]
    # cada tick devuelve una conexión "nueva" al mismo destino (raddr distinto lport)
    def make_conn(i):
        return _SConn(fd=i, family=2, type=1,
                      laddr=_Addr("192.168.1.5", 50000 + i),
                      raddr=_Addr("9.9.9.9", 443),
                      status="ESTABLISHED", pid=2000)
    ticks = [[]] + [[make_conn(i)] for i in range(1, 6)]
    seq = iter(ticks)

    def fake_net_connections(kind="inet"):
        try:
            return next(seq)
        except StopIteration:
            return []

    bus = EventBus()
    c = NetCollector(host="H", poll_interval_seconds=0.02,
                     beaconing_window_seconds=60, beaconing_min_connections=3)
    with patch("cerberus.collectors.net.psutil.net_connections",
               side_effect=fake_net_connections):
        task = asyncio.create_task(c.start(bus))
        received = await _collect_events(bus, target_count=6, timeout=1.0)
        await c.stop()
        task.cancel()

    beacons = [e for e in received if e.type == "beaconing_suspect"]
    assert len(beacons) >= 1
    assert beacons[0].indicators["remote_ip"] == "9.9.9.9"
    assert beacons[0].indicators["connection_count"] >= 3


def test_net_collector_health_initial():
    c = NetCollector(host="H")
    h = c.health()
    assert h.name == "net"
    assert h.running is False
    assert h.events_emitted == 0
```

- [ ] **Step 2: Correr y verificar fallo**

Run: `pytest tests/unit/test_net_collector.py -v`
Expected: FAIL con `ModuleNotFoundError`.

- [ ] **Step 3: Implementar `cerberus/collectors/net.py`**

```python
from __future__ import annotations

import asyncio
import ipaddress
import time
from collections import defaultdict, deque
from typing import Any

import psutil

from cerberus.collectors.base import Collector
from cerberus.core.event import Event
from cerberus.core.event_bus import EventBus
from cerberus.core.logger import get_logger

_log = get_logger("cerberus.collectors.net")


def _is_routable(ip: str) -> bool:
    """True si la IP no es loopback/link-local/no especificada."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (addr.is_loopback or addr.is_link_local or addr.is_unspecified)


class NetCollector(Collector):
    """Detecta conexiones salientes y patrones de beaconing por polling psutil.

    M2: sin captura de paquetes (pyshark/Npcap se difiere a M3). Solo observa el
    estado de las conexiones del host con psutil.net_connections().
    """

    name = "net"

    def __init__(
        self,
        host: str,
        poll_interval_seconds: float = 2.0,
        beaconing_window_seconds: int = 60,
        beaconing_min_connections: int = 10,
    ) -> None:
        super().__init__()
        self._host = host
        self._interval = poll_interval_seconds
        self._beacon_window = beaconing_window_seconds
        self._beacon_min = beaconing_min_connections
        # clave de conexión vista: (pid, remote_ip, remote_port, lport)
        self._known: set[tuple[int | None, str, int, int]] = set()
        # historial de timestamps por (pid, remote_ip) para detectar beaconing
        self._beacon_hist: dict[tuple[int | None, str], deque[float]] = defaultdict(deque)
        self._beacon_alerted: set[tuple[int | None, str]] = set()
        self._stop = asyncio.Event()

    async def start(self, bus: EventBus) -> None:
        self._running = True
        self._stop.clear()
        try:
            self._seed()
            while not self._stop.is_set():
                try:
                    await self._tick(bus)
                except Exception as exc:
                    self._last_error = repr(exc)
                    _log.error("net_tick_error", extra={"error": str(exc)})
                try:
                    await asyncio.wait_for(self._stop.wait(), timeout=self._interval)
                except TimeoutError:
                    pass
        finally:
            self._running = False

    async def stop(self) -> None:
        self._stop.set()

    def _outbound_conns(self) -> list[Any]:
        result: list[Any] = []
        for c in psutil.net_connections(kind="inet"):
            if c.status == psutil.CONN_LISTEN:
                continue
            if not c.raddr:
                continue
            rip = c.raddr.ip if hasattr(c.raddr, "ip") else c.raddr[0]
            if not _is_routable(rip):
                continue
            result.append(c)
        return result

    def _seed(self) -> None:
        for c in self._outbound_conns():
            self._known.add(self._key(c))

    @staticmethod
    def _key(c: Any) -> tuple[int | None, str, int, int]:
        rip = c.raddr.ip if hasattr(c.raddr, "ip") else c.raddr[0]
        rport = c.raddr.port if hasattr(c.raddr, "port") else c.raddr[1]
        lport = c.laddr.port if hasattr(c.laddr, "port") else c.laddr[1]
        return (c.pid, rip, int(rport), int(lport))

    async def _tick(self, bus: EventBus) -> None:
        now = time.monotonic()
        current = self._outbound_conns()
        current_keys = {self._key(c) for c in current}

        for c in current:
            key = self._key(c)
            if key in self._known:
                continue
            pid, rip, rport, _lport = key
            ev = Event(
                source="net",
                type="outbound_conn",
                host=self._host,
                pid=pid,
                user=None,
                raw={"status": c.status},
                indicators={
                    "remote_ip": rip,
                    "remote_port": rport,
                    "local_port": _lport,
                },
            )
            await bus.publish(ev)
            self._events_emitted += 1
            await self._track_beaconing(bus, pid, rip, now)

        self._known = current_keys

    async def _track_beaconing(
        self, bus: EventBus, pid: int | None, rip: str, now: float
    ) -> None:
        bkey = (pid, rip)
        hist = self._beacon_hist[bkey]
        hist.append(now)
        cutoff = now - self._beacon_window
        while hist and hist[0] < cutoff:
            hist.popleft()
        if len(hist) >= self._beacon_min and bkey not in self._beacon_alerted:
            self._beacon_alerted.add(bkey)
            ev = Event(
                source="net",
                type="beaconing_suspect",
                host=self._host,
                pid=pid,
                user=None,
                raw={"window_seconds": self._beacon_window},
                indicators={
                    "remote_ip": rip,
                    "connection_count": len(hist),
                },
            )
            await bus.publish(ev)
            self._events_emitted += 1
```

- [ ] **Step 4: Correr tests**

Run: `pytest tests/unit/test_net_collector.py -v`
Expected: 4 passed.

- [ ] **Step 5: Commit**

```bash
git add cerberus/collectors/net.py tests/unit/test_net_collector.py
git commit -m "feat(collectors): add NetCollector with psutil polling and beaconing heuristic"
```

---

## Task 6: `FsCollector` (watchdog)

> **Antes de codear este módulo:** invocar skill `using-context7` para verificar la API actual de `watchdog` v4+ (`Observer`, `FileSystemEventHandler`, eventos `on_created`/`on_modified`/`on_moved`).

**Files:**
- Create: `cerberus/collectors/fs.py`
- Test: `tests/unit/test_fs_collector.py`

- [ ] **Step 1: Escribir tests fallidos**

`tests/unit/test_fs_collector.py`:
```python
import asyncio
import math
from pathlib import Path

import pytest

from cerberus.collectors.fs import FsCollector, shannon_entropy
from cerberus.core.event import Event
from cerberus.core.event_bus import EventBus


def test_shannon_entropy_uniform_random_is_high():
    data = bytes(range(256)) * 4  # distribución uniforme → entropía máxima (8.0)
    assert shannon_entropy(data) > 7.9


def test_shannon_entropy_repetitive_is_low():
    data = b"AAAAAAAAAAAAAAAA" * 64
    assert shannon_entropy(data) < 1.0


def test_shannon_entropy_empty_is_zero():
    assert shannon_entropy(b"") == 0.0


async def _collect_events(bus: EventBus, target_count: int, timeout: float = 2.0) -> list[Event]:
    received: list[Event] = []
    done = asyncio.Event()

    async def handler(ev: Event) -> None:
        received.append(ev)
        if len(received) >= target_count:
            done.set()

    bus.subscribe(handler)
    bus.start()
    try:
        await asyncio.wait_for(done.wait(), timeout=timeout)
    except TimeoutError:
        pass
    await bus.stop()
    return received


@pytest.mark.asyncio
async def test_fs_collector_emits_file_created(tmp_path: Path):
    bus = EventBus()
    c = FsCollector(
        host="H",
        watch_paths=[tmp_path],
        mass_rename_threshold=20,
        mass_rename_window_seconds=5,
        high_entropy_threshold=7.5,
    )
    await c.start(bus)
    try:
        # crear archivo tras arrancar el observer
        (tmp_path / "nuevo.txt").write_text("hola", encoding="utf-8")
        received = await _collect_events(bus, target_count=1, timeout=2.0)
    finally:
        await c.stop()

    created = [e for e in received if e.type == "file_created"]
    assert len(created) >= 1
    assert created[0].source == "fs"
    assert "nuevo.txt" in created[0].indicators["path"]


@pytest.mark.asyncio
async def test_fs_collector_emits_mass_rename(tmp_path: Path):
    bus = EventBus()
    c = FsCollector(
        host="H",
        watch_paths=[tmp_path],
        mass_rename_threshold=3,            # umbral bajo para el test
        mass_rename_window_seconds=5,
        high_entropy_threshold=7.5,
    )
    # pre-crear archivos
    files = []
    for i in range(5):
        f = tmp_path / f"f{i}.txt"
        f.write_text("x", encoding="utf-8")
        files.append(f)

    await c.start(bus)
    try:
        for i, f in enumerate(files):
            f.rename(tmp_path / f"f{i}.locked")
        received = await _collect_events(bus, target_count=1, timeout=3.0)
    finally:
        await c.stop()

    mass = [e for e in received if e.type == "mass_rename"]
    assert len(mass) >= 1
    assert mass[0].indicators["rename_count"] >= 3


def test_fs_collector_health_initial():
    c = FsCollector(host="H", watch_paths=[Path(".")])
    h = c.health()
    assert h.name == "fs"
    assert h.running is False
```

- [ ] **Step 2: Correr y verificar fallo**

Run: `pytest tests/unit/test_fs_collector.py -v`
Expected: FAIL con `ModuleNotFoundError`.

- [ ] **Step 3: Implementar `cerberus/collectors/fs.py`**

```python
from __future__ import annotations

import asyncio
import math
import time
from collections import Counter, deque
from pathlib import Path
from typing import Any

from watchdog.events import (
    FileCreatedEvent,
    FileModifiedEvent,
    FileMovedEvent,
    FileSystemEvent,
    FileSystemEventHandler,
)
from watchdog.observers import Observer

from cerberus.collectors.base import Collector
from cerberus.core.event import Event
from cerberus.core.event_bus import EventBus
from cerberus.core.logger import get_logger

_log = get_logger("cerberus.collectors.fs")

_ENTROPY_SAMPLE_BYTES = 65536  # leer máx 64KB para estimar entropía


def shannon_entropy(data: bytes) -> float:
    """Entropía de Shannon en bits/byte (0.0–8.0). Vacío → 0.0."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    entropy = 0.0
    for c in counts.values():
        p = c / length
        entropy -= p * math.log2(p)
    return entropy


class _Handler(FileSystemEventHandler):
    """Puente síncrono (hilo watchdog) → asyncio loop del collector."""

    def __init__(self, collector: FsCollector, loop: asyncio.AbstractEventLoop) -> None:
        self._collector = collector
        self._loop = loop

    def _submit(self, coro: Any) -> None:
        asyncio.run_coroutine_threadsafe(coro, self._loop)

    def on_created(self, event: FileSystemEvent) -> None:
        if isinstance(event, FileCreatedEvent) and not event.is_directory:
            self._submit(self._collector._on_created(str(event.src_path)))

    def on_modified(self, event: FileSystemEvent) -> None:
        if isinstance(event, FileModifiedEvent) and not event.is_directory:
            self._submit(self._collector._on_modified(str(event.src_path)))

    def on_moved(self, event: FileSystemEvent) -> None:
        if isinstance(event, FileMovedEvent) and not event.is_directory:
            self._submit(
                self._collector._on_moved(str(event.src_path), str(event.dest_path))
            )


class FsCollector(Collector):
    """Vigila rutas con watchdog. Emite file_created/file_modified/mass_rename/high_entropy_write."""

    name = "fs"

    def __init__(
        self,
        host: str,
        watch_paths: list[Path],
        mass_rename_threshold: int = 20,
        mass_rename_window_seconds: int = 5,
        high_entropy_threshold: float = 7.5,
    ) -> None:
        super().__init__()
        self._host = host
        self._watch_paths = [Path(p) for p in watch_paths]
        self._mass_threshold = mass_rename_threshold
        self._mass_window = mass_rename_window_seconds
        self._entropy_threshold = high_entropy_threshold
        self._observer: Observer | None = None
        self._bus: EventBus | None = None
        self._rename_hist: deque[float] = deque()
        self._mass_alerted_at: float = 0.0

    async def start(self, bus: EventBus) -> None:
        self._bus = bus
        loop = asyncio.get_running_loop()
        handler = _Handler(self, loop)
        observer = Observer()
        watched = 0
        for p in self._watch_paths:
            if p.exists():
                observer.schedule(handler, str(p), recursive=True)
                watched += 1
            else:
                _log.warning("fs_watch_path_missing", extra={"path": str(p)})
        if watched == 0:
            self._last_error = "no_valid_watch_paths"
            _log.error("fs_no_valid_paths")
            self._running = False
            return
        observer.start()
        self._observer = observer
        self._running = True
        _log.info("fs_collector_started", extra={"paths": watched})

    async def stop(self) -> None:
        if self._observer is not None:
            self._observer.stop()
            self._observer.join(timeout=5)
            self._observer = None
        self._running = False

    async def _publish(self, event: Event) -> None:
        if self._bus is not None:
            await self._bus.publish(event)
            self._events_emitted += 1

    async def _on_created(self, path: str) -> None:
        await self._publish(
            Event(source="fs", type="file_created", host=self._host, pid=None,
                  user=None, raw={"path": path}, indicators={"path": path})
        )

    async def _on_modified(self, path: str) -> None:
        await self._publish(
            Event(source="fs", type="file_modified", host=self._host, pid=None,
                  user=None, raw={"path": path}, indicators={"path": path})
        )
        await self._maybe_high_entropy(path)

    async def _on_moved(self, src: str, dest: str) -> None:
        now = time.monotonic()
        self._rename_hist.append(now)
        cutoff = now - self._mass_window
        while self._rename_hist and self._rename_hist[0] < cutoff:
            self._rename_hist.popleft()
        if (
            len(self._rename_hist) >= self._mass_threshold
            and now - self._mass_alerted_at > self._mass_window
        ):
            self._mass_alerted_at = now
            await self._publish(
                Event(
                    source="fs", type="mass_rename", host=self._host, pid=None,
                    user=None, raw={"latest_src": src, "latest_dest": dest},
                    indicators={"rename_count": len(self._rename_hist)},
                )
            )

    async def _maybe_high_entropy(self, path: str) -> None:
        try:
            with open(path, "rb") as fh:
                data = fh.read(_ENTROPY_SAMPLE_BYTES)
        except OSError:
            return
        ent = shannon_entropy(data)
        if ent >= self._entropy_threshold and len(data) >= 256:
            await self._publish(
                Event(
                    source="fs", type="high_entropy_write", host=self._host, pid=None,
                    user=None, raw={"path": path, "bytes_sampled": len(data)},
                    indicators={"path": path, "entropy": round(ent, 3)},
                )
            )
```

- [ ] **Step 4: Correr tests**

Run: `pytest tests/unit/test_fs_collector.py -v`
Expected: 6 passed. (Si `test_fs_collector_emits_mass_rename` es flaky por timing del observer, subir el `timeout` de `_collect_events` a 4.0; no bajar el umbral lógico.)

- [ ] **Step 5: Commit**

```bash
git add cerberus/collectors/fs.py tests/unit/test_fs_collector.py
git commit -m "feat(collectors): add FsCollector with watchdog and entropy/mass-rename heuristics"
```

---

## Task 7: `EvtCollector` (win32evtlog con subscriber inyectable)

> **Antes de codear este módulo:** invocar skill `using-context7` para verificar la API actual de `win32evtlog.EvtSubscribe`, `EvtRender` y el parseo de eventos XML en pywin32 v306+.

**Files:**
- Create: `cerberus/collectors/evt.py`
- Test: `tests/unit/test_evt_collector.py`

**Diseño:** El collector NO depende de tener pywin32 instalado para importarse. Define un `Protocol` `EvtSource` con un método `poll() -> list[dict]` que devuelve eventos normalizados `{channel, event_id, xml, ...}`. La implementación real (`Win32EvtSource`) se construye solo si `win32evtlog` se importa con éxito; si falla, `EvtCollector.start()` marca `health.running=False` y retorna sin error. Los tests inyectan un `FakeEvtSource`.

- [ ] **Step 1: Escribir tests fallidos**

`tests/unit/test_evt_collector.py`:
```python
import asyncio

import pytest

from cerberus.collectors.evt import EvtCollector, EvtRecord
from cerberus.core.event import Event
from cerberus.core.event_bus import EventBus


class FakeEvtSource:
    """Source inyectable: entrega lotes predefinidos y luego vacío."""

    def __init__(self, batches: list[list[EvtRecord]]) -> None:
        self._batches = iter(batches)

    def poll(self) -> list[EvtRecord]:
        try:
            return next(self._batches)
        except StopIteration:
            return []


async def _collect_events(bus: EventBus, target_count: int, timeout: float = 1.5) -> list[Event]:
    received: list[Event] = []
    done = asyncio.Event()

    async def handler(ev: Event) -> None:
        received.append(ev)
        if len(received) >= target_count:
            done.set()

    bus.subscribe(handler)
    bus.start()
    try:
        await asyncio.wait_for(done.wait(), timeout=timeout)
    except TimeoutError:
        pass
    await bus.stop()
    return received


@pytest.mark.asyncio
async def test_evt_collector_maps_logon_failure():
    rec = EvtRecord(channel="Security", event_id=4625,
                    raw={"TargetUserName": "admin"})
    bus = EventBus()
    c = EvtCollector(host="H", channels=["Security"], poll_interval_seconds=0.05,
                     source=FakeEvtSource([[rec]]))
    task = asyncio.create_task(c.start(bus))
    received = await _collect_events(bus, target_count=1, timeout=1.0)
    await c.stop()
    task.cancel()

    logon = [e for e in received if e.type == "logon_failure"]
    assert len(logon) == 1
    assert logon[0].source == "evt"
    assert logon[0].indicators["event_id"] == 4625
    assert logon[0].indicators["channel"] == "Security"


@pytest.mark.asyncio
async def test_evt_collector_maps_known_ids():
    recs = [
        EvtRecord(channel="Security", event_id=4697, raw={}),
        EvtRecord(channel="Security", event_id=4698, raw={}),
        EvtRecord(channel="Microsoft-Windows-PowerShell/Operational",
                  event_id=4104, raw={}),
    ]
    bus = EventBus()
    c = EvtCollector(host="H", channels=["Security"], poll_interval_seconds=0.05,
                     source=FakeEvtSource([recs]))
    task = asyncio.create_task(c.start(bus))
    received = await _collect_events(bus, target_count=3, timeout=1.0)
    await c.stop()
    task.cancel()

    types = {e.type for e in received}
    assert "service_install" in types
    assert "scheduled_task_create" in types
    assert "ps_blocklist" in types


@pytest.mark.asyncio
async def test_evt_collector_unknown_id_emits_generic():
    rec = EvtRecord(channel="Security", event_id=9999, raw={})
    bus = EventBus()
    c = EvtCollector(host="H", channels=["Security"], poll_interval_seconds=0.05,
                     source=FakeEvtSource([[rec]]))
    task = asyncio.create_task(c.start(bus))
    received = await _collect_events(bus, target_count=1, timeout=1.0)
    await c.stop()
    task.cancel()

    assert len(received) == 1
    assert received[0].type == "win_event"   # tipo genérico para IDs no mapeados
    assert received[0].indicators["event_id"] == 9999


@pytest.mark.asyncio
async def test_evt_collector_disabled_when_no_source_available():
    # source=None y win32evtlog no disponible → health.running=False, sin excepción
    bus = EventBus()
    c = EvtCollector(host="H", channels=["Security"], poll_interval_seconds=0.05,
                     source="unavailable")
    await c.start(bus)
    h = c.health()
    assert h.running is False
    assert h.last_error == "evt_source_unavailable"
    await c.stop()


def test_evt_collector_health_initial():
    c = EvtCollector(host="H", channels=["Security"], source="unavailable")
    h = c.health()
    assert h.name == "evt"
    assert h.running is False
```

- [ ] **Step 2: Correr y verificar fallo**

Run: `pytest tests/unit/test_evt_collector.py -v`
Expected: FAIL con `ModuleNotFoundError`.

- [ ] **Step 3: Implementar `cerberus/collectors/evt.py`**

```python
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from cerberus.collectors.base import Collector
from cerberus.core.event import Event
from cerberus.core.event_bus import EventBus
from cerberus.core.logger import get_logger

_log = get_logger("cerberus.collectors.evt")

# Mapeo Windows Event ID → tipo normalizado del Event de Cerberus.
_EVENT_ID_MAP: dict[int, str] = {
    4625: "logon_failure",
    4697: "service_install",
    7045: "service_install",
    4698: "scheduled_task_create",
    4104: "ps_blocklist",
}
_GENERIC_TYPE = "win_event"


@dataclass(frozen=True)
class EvtRecord:
    """Registro crudo entregado por un EvtSource (ya extraído del canal)."""

    channel: str
    event_id: int
    raw: dict[str, Any] = field(default_factory=dict)


@runtime_checkable
class EvtSource(Protocol):
    def poll(self) -> list[EvtRecord]: ...


def _build_win32_source(channels: list[str]) -> EvtSource | None:
    """Construye el source real si pywin32 está disponible; si no, None."""
    try:
        import win32evtlog  # noqa: F401
    except Exception:
        return None
    return _Win32EvtSource(channels)


class _Win32EvtSource:
    """Source real basado en win32evtlog (solo Windows). Polling de canales.

    Nota: implementación de M2 hace lectura incremental por canal vía
    EvtQuery/EvtNext. La suscripción push (EvtSubscribe) se evalúa en M4 junto
    al Windows Service. Mantener la API `poll()` estable.
    """

    def __init__(self, channels: list[str]) -> None:
        import win32evtlog

        self._win32evtlog = win32evtlog
        self._channels = channels
        self._bookmarks: dict[str, Any] = {}

    def poll(self) -> list[EvtRecord]:
        records: list[EvtRecord] = []
        for channel in self._channels:
            try:
                records.extend(self._read_channel(channel))
            except Exception as exc:  # un canal inaccesible no rompe el resto
                _log.warning("evt_channel_error",
                             extra={"channel": channel, "error": str(exc)})
        return records

    def _read_channel(self, channel: str) -> list[EvtRecord]:
        w = self._win32evtlog
        flags = w.EvtQueryChannelPath | w.EvtQueryReverseDirection
        out: list[EvtRecord] = []
        try:
            handle = w.EvtQuery(channel, flags, None, None)
        except Exception:
            return out
        events = w.EvtNext(handle, 10)
        for ev in events:
            xml = w.EvtRender(ev, w.EvtRenderEventXml)
            event_id = _parse_event_id(xml)
            out.append(EvtRecord(channel=channel, event_id=event_id, raw={"xml": xml}))
        return out


def _parse_event_id(xml: str) -> int:
    """Extrae <EventID>N</EventID> del XML del evento. -1 si no se encuentra."""
    import re

    m = re.search(r"<EventID[^>]*>(\d+)</EventID>", xml)
    return int(m.group(1)) if m else -1


class EvtCollector(Collector):
    """Lee canales de Windows Event Log y emite Events normalizados.

    Degrada con gracia: si no hay source disponible (pywin32 ausente o no-Windows),
    arranca con running=False y deja correr al resto del sistema.
    """

    name = "evt"

    def __init__(
        self,
        host: str,
        channels: list[str],
        poll_interval_seconds: float = 2.0,
        source: EvtSource | str | None = None,
    ) -> None:
        super().__init__()
        self._host = host
        self._channels = list(channels)
        self._interval = poll_interval_seconds
        # source explícito (tests), "unavailable" para forzar degradación, o None=autodetect
        self._source_arg = source
        self._source: EvtSource | None = None
        self._stop = asyncio.Event()

    def _resolve_source(self) -> EvtSource | None:
        if self._source_arg == "unavailable":
            return None
        if self._source_arg is not None and not isinstance(self._source_arg, str):
            return self._source_arg
        return _build_win32_source(self._channels)

    async def start(self, bus: EventBus) -> None:
        self._source = self._resolve_source()
        if self._source is None:
            self._running = False
            self._last_error = "evt_source_unavailable"
            _log.info("evt_collector_unavailable", extra={"host": self._host})
            return
        self._running = True
        self._stop.clear()
        try:
            while not self._stop.is_set():
                try:
                    await self._tick(bus)
                except Exception as exc:
                    self._last_error = repr(exc)
                    _log.error("evt_tick_error", extra={"error": str(exc)})
                try:
                    await asyncio.wait_for(self._stop.wait(), timeout=self._interval)
                except TimeoutError:
                    pass
        finally:
            self._running = False

    async def stop(self) -> None:
        self._stop.set()

    async def _tick(self, bus: EventBus) -> None:
        assert self._source is not None
        for rec in self._source.poll():
            etype = _EVENT_ID_MAP.get(rec.event_id, _GENERIC_TYPE)
            ev = Event(
                source="evt",
                type=etype,
                host=self._host,
                pid=None,
                user=rec.raw.get("TargetUserName"),
                raw=rec.raw,
                indicators={"channel": rec.channel, "event_id": rec.event_id},
            )
            await bus.publish(ev)
            self._events_emitted += 1
```

- [ ] **Step 4: Correr tests**

Run: `pytest tests/unit/test_evt_collector.py -v`
Expected: 5 passed.

- [ ] **Step 5: Commit**

```bash
git add cerberus/collectors/evt.py tests/unit/test_evt_collector.py
git commit -m "feat(collectors): add EvtCollector with injectable source and graceful degradation"
```

---

## Task 8: `Correlator` (ventana deslizante → Finding)

**Files:**
- Create: `cerberus/detection/correlator.py`
- Test: `tests/unit/test_correlator.py`

**Diseño:** El `Correlator` se suscribe al `EventBus` (sin filtro). Su handler `_on_event` SOLO acumula eventos en un buffer con su timestamp de llegada (no promueve en cada publish — eso captaría clusters a medias). La promoción ocurre en `flush()`, que corre periódicamente vía la corrutina `run()` (en producción, cada `flush_interval_seconds`) o se invoca explícitamente en tests. En cada `flush()`: descarta eventos más viejos que `window_seconds`, agrupa los vivos por clave `(host, pid, user)`, y promueve a `Finding` cualquier cluster con `len(distinct sources) >= min_sources_for_finding`. **La deduplicación es por clave de cluster `(host, pid, user)`**, no por firma de eventos: un cluster se promueve UNA vez por ráfaga de actividad. Cuando todos los eventos de una clave envejecen y salen de la ventana, su marca se limpia, permitiendo un nuevo `Finding` si el proceso vuelve a estar activo. El `Finding` resultante se entrega al callback `on_finding`.

- [ ] **Step 1: Escribir tests fallidos**

`tests/unit/test_correlator.py`:
```python
import asyncio

import pytest

from cerberus.core.event import Event
from cerberus.core.event_bus import EventBus
from cerberus.core.finding import Finding
from cerberus.detection.correlator import Correlator


def _ev(source, type_, pid=10, user="u", host="H"):
    return Event(source=source, type=type_, host=host, pid=pid,
                 user=user, raw={}, indicators={})


@pytest.mark.asyncio
async def test_correlator_promotes_multi_source_cluster():
    findings: list[Finding] = []

    async def on_finding(f: Finding) -> None:
        findings.append(f)

    bus = EventBus()
    corr = Correlator(window_seconds=10, min_sources_for_finding=2, on_finding=on_finding)
    corr.attach(bus)
    bus.start()

    await bus.publish(_ev("proc", "new_process", pid=10))
    await bus.publish(_ev("net", "outbound_conn", pid=10))
    await bus.drain()
    await corr.flush()
    await bus.stop()

    assert len(findings) == 1
    f = findings[0]
    assert f.pid == 10
    assert f.sources == {"proc", "net"}


@pytest.mark.asyncio
async def test_correlator_single_source_does_not_promote():
    findings: list[Finding] = []

    async def on_finding(f: Finding) -> None:
        findings.append(f)

    bus = EventBus()
    corr = Correlator(window_seconds=10, min_sources_for_finding=2, on_finding=on_finding)
    corr.attach(bus)
    bus.start()

    await bus.publish(_ev("proc", "new_process", pid=10))
    await bus.publish(_ev("proc", "process_exit", pid=10))
    await bus.drain()
    await corr.flush()
    await bus.stop()

    assert findings == []


@pytest.mark.asyncio
async def test_correlator_groups_by_pid():
    findings: list[Finding] = []

    async def on_finding(f: Finding) -> None:
        findings.append(f)

    bus = EventBus()
    corr = Correlator(window_seconds=10, min_sources_for_finding=2, on_finding=on_finding)
    corr.attach(bus)
    bus.start()

    # pid 10 multi-fuente → finding; pid 20 single-source → no
    await bus.publish(_ev("proc", "new_process", pid=10))
    await bus.publish(_ev("fs", "file_created", pid=10))
    await bus.publish(_ev("net", "outbound_conn", pid=20))
    await bus.drain()
    await corr.flush()
    await bus.stop()

    assert len(findings) == 1
    assert findings[0].pid == 10


@pytest.mark.asyncio
async def test_correlator_promotes_cluster_only_once():
    findings: list[Finding] = []

    async def on_finding(f: Finding) -> None:
        findings.append(f)

    bus = EventBus()
    corr = Correlator(window_seconds=10, min_sources_for_finding=2, on_finding=on_finding)
    corr.attach(bus)
    bus.start()

    await bus.publish(_ev("proc", "new_process", pid=10))
    await bus.publish(_ev("net", "outbound_conn", pid=10))
    await bus.drain()
    await corr.flush()
    await corr.flush()   # segundo flush no debe re-promover el mismo cluster
    await bus.stop()

    assert len(findings) == 1


@pytest.mark.asyncio
async def test_correlator_evicts_events_outside_window():
    findings: list[Finding] = []

    async def on_finding(f: Finding) -> None:
        findings.append(f)

    bus = EventBus()
    # ventana de 0 segundos → todo evento envejece inmediatamente; sin clusters vivos
    corr = Correlator(window_seconds=0, min_sources_for_finding=2, on_finding=on_finding)
    corr.attach(bus)
    bus.start()

    await bus.publish(_ev("proc", "new_process", pid=10))
    await bus.publish(_ev("net", "outbound_conn", pid=10))
    await bus.drain()
    await asyncio.sleep(0.01)
    await corr.flush()
    await bus.stop()

    assert findings == []
```

- [ ] **Step 2: Correr y verificar fallo**

Run: `pytest tests/unit/test_correlator.py -v`
Expected: FAIL con `ModuleNotFoundError`.

- [ ] **Step 3: Implementar `cerberus/detection/correlator.py`**

```python
from __future__ import annotations

import asyncio
import time
from collections import defaultdict
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from cerberus.core.event import Event
from cerberus.core.event_bus import EventBus
from cerberus.core.finding import Finding
from cerberus.core.logger import get_logger

_log = get_logger("cerberus.detection.correlator")

OnFinding = Callable[[Finding], Awaitable[None] | None]

# clave de agrupación: (host, pid, user)
_ClusterKey = tuple[str, int | None, str | None]


@dataclass
class _TimedEvent:
    received_at: float
    event: Event


class Correlator:
    """Agrupa eventos por (host, pid, user) en una ventana deslizante y promueve
    clusters multi-fuente a Finding. 100% heurístico (sin LLM).

    El handler de bus solo acumula; la promoción ocurre en flush(), llamado
    periódicamente por run() o explícitamente (tests). Dedup por clave de cluster:
    un cluster se promueve una vez por ráfaga; al envejecer todos sus eventos la
    marca se limpia y una nueva ráfaga puede volver a promover.
    """

    def __init__(
        self,
        window_seconds: int,
        min_sources_for_finding: int,
        on_finding: OnFinding,
        flush_interval_seconds: float = 1.0,
    ) -> None:
        self._window = window_seconds
        self._min_sources = min_sources_for_finding
        self._on_finding = on_finding
        self._flush_interval = flush_interval_seconds
        self._buffer: list[_TimedEvent] = []
        self._promoted: set[_ClusterKey] = set()
        self._stop = asyncio.Event()

    def attach(self, bus: EventBus) -> None:
        bus.subscribe(self._on_event)

    def _on_event(self, event: Event) -> None:
        self._buffer.append(_TimedEvent(received_at=time.monotonic(), event=event))

    async def run(self) -> None:
        self._stop.clear()
        while not self._stop.is_set():
            try:
                await self.flush()
            except Exception as exc:
                _log.error("correlator_flush_error", extra={"error": str(exc)})
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self._flush_interval)
            except TimeoutError:
                pass

    async def stop(self) -> None:
        self._stop.set()

    def _evict(self, now: float) -> None:
        cutoff = now - self._window
        self._buffer = [te for te in self._buffer if te.received_at >= cutoff]

    def _group(self) -> dict[_ClusterKey, list[Event]]:
        groups: dict[_ClusterKey, list[Event]] = defaultdict(list)
        for te in self._buffer:
            ev = te.event
            groups[(ev.host, ev.pid, ev.user)].append(ev)
        return groups

    async def flush(self) -> None:
        now = time.monotonic()
        self._evict(now)
        groups = self._group()
        # limpiar marcas de claves sin eventos vivos (ráfaga terminada)
        self._promoted &= set(groups.keys())
        for (host, pid, user), evs in groups.items():
            key: _ClusterKey = (host, pid, user)
            sources = {e.source for e in evs}
            if len(sources) < self._min_sources:
                continue
            if key in self._promoted:
                continue
            self._promoted.add(key)
            finding = Finding.from_cluster(host=host, pid=pid, user=user, evidence=evs)
            _log.info(
                "finding_promoted",
                extra={"finding_id": finding.id, "pid": pid,
                       "sources": sorted(sources)},
            )
            result = self._on_finding(finding)
            if result is not None:
                await result
```

- [ ] **Step 4: Correr tests**

Run: `pytest tests/unit/test_correlator.py -v`
Expected: 5 passed.

- [ ] **Step 5: Commit**

```bash
git add cerberus/detection/correlator.py tests/unit/test_correlator.py
git commit -m "feat(detection): add Correlator with sliding-window multi-source clustering"
```

---

## Task 9: `MarkdownReportWriter` — sección de findings

**Files:**
- Modify: `cerberus/reporting/markdown.py`
- Modify: `tests/unit/test_report_markdown.py`

- [ ] **Step 1: Añadir tests fallidos a `tests/unit/test_report_markdown.py`**

Añadir AL FINAL del archivo existente:
```python
def test_render_with_findings_section():
    from cerberus.core.finding import Finding
    from cerberus.core.event import Event

    def _e(source, type_, pid=10):
        return Event(source=source, type=type_, host="H", pid=pid,
                     user="u", raw={}, indicators={})

    events = [_e("proc", "new_process"), _e("net", "outbound_conn")]
    finding = Finding.from_cluster(host="H", pid=10, user="u", evidence=events)
    out = MarkdownReportWriter.render(events, host="H", findings=[finding])
    assert "## Findings" in out
    assert "**Total findings:** 1" in out
    assert finding.id in out
    assert "proc" in out and "net" in out


def test_render_no_findings_shows_zero():
    out = MarkdownReportWriter.render([], host="H", findings=[])
    assert "**Total findings:** 0" in out


def test_write_with_findings(tmp_path):
    from cerberus.core.finding import Finding
    from cerberus.core.event import Event
    writer = MarkdownReportWriter(reports_dir=tmp_path, host="H")
    events = [Event(source="proc", type="new_process", host="H", pid=10,
                    user="u", raw={}, indicators={}),
              Event(source="fs", type="mass_rename", host="H", pid=10,
                    user="u", raw={}, indicators={})]
    finding = Finding.from_cluster(host="H", pid=10, user="u", evidence=events)
    path = writer.write(events, findings=[finding])
    content = path.read_text(encoding="utf-8")
    assert "## Findings" in content
    assert "mass_rename" in content
```

- [ ] **Step 2: Correr y verificar fallo**

Run: `pytest tests/unit/test_report_markdown.py -v`
Expected: FAIL en los tests nuevos (`render`/`write` no aceptan `findings`).

- [ ] **Step 3: Reemplazar `cerberus/reporting/markdown.py` completo**

```python
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path

from cerberus.core.event import Event, Severity
from cerberus.core.finding import Finding


class MarkdownReportWriter:
    def __init__(self, reports_dir: Path, host: str) -> None:
        self.reports_dir = Path(reports_dir)
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.host = host

    @staticmethod
    def render(
        events: list[Event],
        host: str,
        when: datetime | None = None,
        findings: list[Finding] | None = None,
    ) -> str:
        when = when or datetime.now(UTC)
        findings = findings or []
        lines: list[str] = []
        lines.append("# CERBERUS-LOCAL — Reporte")
        lines.append("")
        lines.append(f"**Host:** {host}")
        lines.append(f"**Generado:** {when.isoformat()}")
        lines.append(f"**Total eventos:** {len(events)}")
        lines.append(f"**Total findings:** {len(findings)}")
        lines.append("")

        # --- Findings primero (lo más relevante) ---
        lines.append("## Findings")
        lines.append("")
        if not findings:
            lines.append("Sin findings correlacionados en el intervalo.")
            lines.append("")
        else:
            lines.append("| ID | Severidad | PID | Fuentes | Categorías |")
            lines.append("|----|-----------|-----|---------|------------|")
            for f in findings:
                sev = Severity(f.severity).name
                srcs = ", ".join(sorted(f.sources))
                cats = ", ".join(sorted(f.categories))
                lines.append(f"| `{f.id}` | {sev} | {f.pid} | {srcs} | {cats} |")
            lines.append("")

        # --- Eventos por fuente ---
        if not events:
            lines.append("## Eventos")
            lines.append("")
            lines.append("Sin eventos en el intervalo.")
            return "\n".join(lines)

        by_source: dict[str, list[Event]] = defaultdict(list)
        for ev in events:
            by_source[ev.source].append(ev)
        for source in sorted(by_source):
            evs = by_source[source]
            lines.append(f"## {source}")
            lines.append("")
            type_counts = Counter(ev.type for ev in evs)
            lines.append("| Tipo | Cantidad |")
            lines.append("|------|----------|")
            for t, n in sorted(type_counts.items()):
                lines.append(f"| `{t}` | {n} |")
            lines.append("")
            lines.append("<details><summary>Ejemplos (hasta 10)</summary>")
            lines.append("")
            for ev in evs[:10]:
                ind = ", ".join(f"{k}={v}" for k, v in ev.indicators.items() if v)
                lines.append(f"- `{ev.timestamp.isoformat()}` pid={ev.pid} {ev.type} — {ind}")
            lines.append("")
            lines.append("</details>")
            lines.append("")
        return "\n".join(lines)

    def write(
        self,
        events: list[Event],
        when: datetime | None = None,
        findings: list[Finding] | None = None,
    ) -> Path:
        when = when or datetime.now(UTC)
        filename = when.strftime("%Y-%m-%d_%H-%M") + ".md"
        path = self.reports_dir / filename
        path.write_text(
            self.render(events, host=self.host, when=when, findings=findings),
            encoding="utf-8",
        )
        return path
```

- [ ] **Step 4: Correr tests**

Run: `pytest tests/unit/test_report_markdown.py -v`
Expected: todos pasan (los 3 de M1 + 3 nuevos).

> Nota: el test de M1 `test_render_report_groups_by_source` espera `## proc`. La nueva sección `## Findings` no colisiona con esa aserción. Si algún test de M1 verificaba que `## proc` fuese el primer encabezado de sección, ajústalo: ahora `## Findings` precede a las secciones por fuente.

- [ ] **Step 5: Commit**

```bash
git add cerberus/reporting/markdown.py tests/unit/test_report_markdown.py
git commit -m "feat(reporting): add findings section to Markdown report"
```

---

## Task 10: Wiring CLI — 4 collectors + correlator + findings store

**Files:**
- Modify: `cerberus/cli/commands.py`

- [ ] **Step 1: Reemplazar `cerberus/cli/commands.py` completo**

```python
from __future__ import annotations

import asyncio
import signal
from datetime import UTC, datetime
from pathlib import Path

from cerberus import __version__
from cerberus.collectors.base import Collector
from cerberus.collectors.evt import EvtCollector
from cerberus.collectors.fs import FsCollector
from cerberus.collectors.net import NetCollector
from cerberus.collectors.proc import ProcCollector
from cerberus.core.config import CerberusConfig, load_config
from cerberus.core.db import EventStore
from cerberus.core.event import Event
from cerberus.core.event_bus import EventBus
from cerberus.core.finding import Finding
from cerberus.core.logger import get_logger
from cerberus.detection.correlator import Correlator
from cerberus.detection.finding_store import FindingStore
from cerberus.reporting.markdown import MarkdownReportWriter

_log = get_logger("cerberus.cli")


def cmd_version() -> int:
    print(f"cerberus-local {__version__}")
    return 0


def cmd_status(cfg: CerberusConfig) -> int:
    store = EventStore(cfg.paths.events_db)
    store.init_schema()
    fstore = FindingStore(cfg.paths.findings_db)
    fstore.init_schema()
    print(f"Host        : {cfg.host_name}")
    print(f"Mode        : {cfg.mode}")
    print(f"Events DB   : {cfg.paths.events_db}")
    print(f"Findings DB : {cfg.paths.findings_db}")
    print(f"Eventos     : {store.count()}")
    print(f"Findings    : {fstore.count()}")
    print("Collectors  : "
          f"proc={cfg.collectors.proc.enabled} "
          f"net={cfg.collectors.net.enabled} "
          f"fs={cfg.collectors.fs.enabled} "
          f"evt={cfg.collectors.evt.enabled}")
    store.close()
    fstore.close()
    return 0


def cmd_start(cfg: CerberusConfig) -> int:
    if cfg.mode != "dry_run":
        _log.warning("mode_forced_dry_run", extra={"requested": cfg.mode})
    return asyncio.run(_run_loop(cfg))


def _build_collectors(cfg: CerberusConfig) -> list[Collector]:
    collectors: list[Collector] = []
    if cfg.collectors.proc.enabled:
        collectors.append(ProcCollector(
            host=cfg.host_name,
            poll_interval_seconds=cfg.collectors.proc.poll_interval_seconds,
        ))
    if cfg.collectors.net.enabled:
        collectors.append(NetCollector(
            host=cfg.host_name,
            poll_interval_seconds=cfg.collectors.net.poll_interval_seconds,
            beaconing_window_seconds=cfg.collectors.net.beaconing_window_seconds,
            beaconing_min_connections=cfg.collectors.net.beaconing_min_connections,
        ))
    if cfg.collectors.fs.enabled:
        collectors.append(FsCollector(
            host=cfg.host_name,
            watch_paths=cfg.collectors.fs.watch_paths,
            mass_rename_threshold=cfg.collectors.fs.mass_rename_threshold,
            mass_rename_window_seconds=cfg.collectors.fs.mass_rename_window_seconds,
            high_entropy_threshold=cfg.collectors.fs.high_entropy_threshold,
        ))
    if cfg.collectors.evt.enabled:
        collectors.append(EvtCollector(
            host=cfg.host_name,
            channels=cfg.collectors.evt.channels,
        ))
    return collectors


async def _run_loop(cfg: CerberusConfig) -> int:
    store = EventStore(cfg.paths.events_db)
    store.init_schema()
    fstore = FindingStore(cfg.paths.findings_db)
    fstore.init_schema()
    bus = EventBus()
    writer = MarkdownReportWriter(cfg.paths.reports_dir, host=cfg.host_name)

    collected_events: list[Event] = []
    collected_findings: list[Finding] = []

    async def persist_event(ev: Event) -> None:
        store.insert(ev)
        collected_events.append(ev)

    async def on_finding(f: Finding) -> None:
        fstore.insert(f)
        collected_findings.append(f)

    bus.subscribe(persist_event)
    correlator = Correlator(
        window_seconds=cfg.correlator.window_seconds,
        min_sources_for_finding=cfg.correlator.min_sources_for_finding,
        on_finding=on_finding,
    )
    correlator.attach(bus)
    bus.start()
    correlator_task = asyncio.create_task(correlator.run(), name="correlator")

    collectors = _build_collectors(cfg)
    collector_tasks = [
        asyncio.create_task(c.start(bus), name=f"collector_{c.name}")
        for c in collectors
    ]
    reporter_task = asyncio.create_task(
        _report_loop(writer, collected_events, collected_findings,
                     cfg.reporting.interval_seconds),
        name="reporter",
    )

    stop_event = asyncio.Event()

    def _on_signal(*_a: object) -> None:
        stop_event.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _on_signal)
        except NotImplementedError:
            signal.signal(sig, lambda *_: stop_event.set())

    _log.info("cerberus_started",
              extra={"host": cfg.host_name, "mode": cfg.mode,
                     "collectors": [c.name for c in collectors]})
    try:
        await stop_event.wait()
    finally:
        for c in collectors:
            await c.stop()
        await correlator.stop()
        # drenar eventos pendientes y promover findings finales antes de cerrar
        await bus.drain()
        await correlator.flush()
        for t in (*collector_tasks, correlator_task, reporter_task):
            t.cancel()
        for t in (*collector_tasks, correlator_task, reporter_task):
            try:
                await t
            except asyncio.CancelledError:
                pass
        await bus.stop()
        if collected_events or collected_findings:
            writer.write(collected_events, when=datetime.now(UTC),
                         findings=collected_findings)
        store.close()
        fstore.close()
    return 0


async def _report_loop(
    writer: MarkdownReportWriter,
    events: list[Event],
    findings: list[Finding],
    interval: int,
) -> None:
    while True:
        await asyncio.sleep(interval)
        ev_snapshot = list(events)
        fn_snapshot = list(findings)
        events.clear()
        findings.clear()
        writer.write(ev_snapshot, when=datetime.now(UTC), findings=fn_snapshot)


def cmd_stop(cfg: CerberusConfig) -> int:
    print("M2 corre en foreground. Usa Ctrl+C para detener.")
    return 0


def resolve_config(path: Path | None) -> CerberusConfig:
    if path is None:
        path = Path(__file__).resolve().parent.parent.parent / "config" / "cerberus.default.yml"
    return load_config(path)
```

- [ ] **Step 2: Smoke test manual del CLI**

Run: `python cerberus_local.py version`
Expected: `cerberus-local 0.2.0`

Run: `python cerberus_local.py status`
Expected: imprime tabla con Host, Mode, Events DB, Findings DB, conteos, y línea `Collectors : proc=True net=True fs=True evt=True`.

- [ ] **Step 3: Commit**

```bash
git add cerberus/cli/commands.py
git commit -m "feat(cli): wire 4 collectors + correlator + findings store into run loop"
```

---

## Task 11: Integration test M2 (vertical slice multi-fuente)

**Files:**
- Create: `tests/integration/test_pipeline_m2.py`

- [ ] **Step 1: Escribir test de integración**

`tests/integration/test_pipeline_m2.py`:
```python
import asyncio
from pathlib import Path

import pytest

from cerberus.core.db import EventStore
from cerberus.core.event import Event
from cerberus.core.event_bus import EventBus
from cerberus.core.finding import Finding
from cerberus.detection.correlator import Correlator
from cerberus.detection.finding_store import FindingStore
from cerberus.reporting.markdown import MarkdownReportWriter


@pytest.mark.asyncio
async def test_m2_pipeline_correlates_persists_and_reports(tmp_path: Path):
    """Eventos sintéticos de 3 fuentes con el mismo pid → 1 finding correlacionado,
    persistido en findings.db y reflejado en el reporte Markdown."""
    events_db = tmp_path / "events.db"
    findings_db = tmp_path / "findings.db"
    reports = tmp_path / "reports"

    store = EventStore(events_db)
    store.init_schema()
    fstore = FindingStore(findings_db)
    fstore.init_schema()
    writer = MarkdownReportWriter(reports, host="H")
    bus = EventBus()

    collected_events: list[Event] = []
    collected_findings: list[Finding] = []

    async def persist_event(ev: Event) -> None:
        store.insert(ev)
        collected_events.append(ev)

    async def on_finding(f: Finding) -> None:
        fstore.insert(f)
        collected_findings.append(f)

    bus.subscribe(persist_event)
    corr = Correlator(window_seconds=10, min_sources_for_finding=2, on_finding=on_finding)
    corr.attach(bus)
    bus.start()

    # Simular telemetría de 3 collectors para el mismo proceso (pid=4892)
    await bus.publish(Event(source="fs", type="mass_rename", host="H", pid=4892,
                            user="u", raw={}, indicators={"rename_count": 30}))
    await bus.publish(Event(source="proc", type="new_process", host="H", pid=4892,
                            user="u", raw={}, indicators={"cmdline": "powershell -enc AAAA"}))
    await bus.publish(Event(source="net", type="outbound_conn", host="H", pid=4892,
                            user="u", raw={}, indicators={"remote_ip": "185.10.10.10"}))
    # Un evento aislado de otro pid que NO debe generar finding
    await bus.publish(Event(source="proc", type="new_process", host="H", pid=99,
                            user="u", raw={}, indicators={}))
    await bus.drain()
    await corr.flush()
    await bus.stop()

    # Persistencia de eventos
    assert store.count() == 4
    # Exactamente un finding (pid 4892 multi-fuente; pid 99 single-source descartado)
    assert fstore.count() == 1
    rows = fstore.fetch_all()
    assert rows[0]["pid"] == 4892
    assert set(rows[0]["sources"]) == {"fs", "proc", "net"}
    store.close()
    fstore.close()

    # Reporte refleja eventos + findings
    report_path = writer.write(collected_events, findings=collected_findings)
    text = report_path.read_text(encoding="utf-8")
    assert "## Findings" in text
    assert "**Total findings:** 1" in text
    assert "mass_rename" in text
    assert "## net" in text and "## proc" in text and "## fs" in text
```

- [ ] **Step 2: Correr integration test**

Run: `pytest tests/integration/test_pipeline_m2.py -v`
Expected: 1 passed.

- [ ] **Step 3: Correr suite completa**

Run: `pytest -v`
Expected: todos los tests pasan (M1 + M2), coverage ≥ 85%.

- [ ] **Step 4: Lint + tipos**

Run: `ruff check .`
Expected: sin errores.

Run: `mypy cerberus cerberus_local.py`
Expected: sin errores.

- [ ] **Step 5: Commit**

```bash
git add tests/integration/test_pipeline_m2.py
git commit -m "test(integration): add M2 multi-source correlation end-to-end test"
```

---

## Task 12: Auditoría de seguridad, README M2 y tag v0.2.0-m2

> **Antes de cerrar el hito:** invocar skill `auditing-security` para una pasada OWASP/ASVS sobre los nuevos módulos (lectura de FS arbitrario en `_maybe_high_entropy`, parseo de XML del event log en `_parse_event_id`, manejo de rutas de config). Documentar hallazgos o el "sin hallazgos" en el commit.

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Auditoría rápida con skill `auditing-security`**

Foco mínimo:
- `cerberus/collectors/fs.py::_maybe_high_entropy` — confirmar que `open(path, "rb")` solo lee (`"rb"`), captura `OSError`, y limita lectura a `_ENTROPY_SAMPLE_BYTES`. No ejecutar ni escribir.
- `cerberus/collectors/evt.py::_parse_event_id` — el regex sobre XML no debe ser vulnerable a ReDoS (patrón `\d+` acotado entre tags fijos: OK).
- `cerberus/core/config.py` — `yaml.safe_load` (no `load`): OK. Rutas de config provienen del operador; no hay deserialización de eventos no confiables.
- Confirmar que ningún módulo M2 ejecuta comandos del sistema ni acepta input de red sin sanitizar (NetCollector solo lee estado local con psutil).

Registrar el resultado en el cuerpo del commit final.

- [ ] **Step 2: Reemplazar `README.md` completo**

```markdown
# CERBERUS-LOCAL — M2 (Telemetría multi-fuente + Correlator)

EDR híbrido Windows con IA local Ollama. Fork defensivo de HADES-LOCAL.

**Hito actual:** M2 — los cuatro collectors + correlación heurística. Sin reglas Sigma, sin IA, sin respuesta automática (vienen en M3).

## Componentes en M2

- `ProcCollector` (psutil) → `new_process`, `process_exit`
- `NetCollector` (psutil polling) → `outbound_conn`, `beaconing_suspect` *(pyshark/Npcap se difiere a M3)*
- `FsCollector` (watchdog) → `file_created`, `file_modified`, `mass_rename`, `high_entropy_write`
- `EvtCollector` (win32evtlog) → `logon_failure`, `service_install`, `scheduled_task_create`, `ps_blocklist`, `win_event` *(degrada con gracia fuera de Windows)*
- `EventBus` (asyncio) → fan-out a suscriptores
- `Correlator` (ventana deslizante) → agrupa por `(host, pid, user)` y promueve clusters multi-fuente a `Finding`
- `EventStore` (events.db) + `FindingStore` (findings.db) → persistencia SQLite WAL
- `MarkdownReportWriter` → reporte con sección de findings + eventos por fuente
- CLI `cerberus_local.py` con `start`, `status`, `stop`, `version`

## Quickstart

\`\`\`bash
python -m venv .venv
.venv\Scripts\activate
pip install -e ".[dev]"
# En Windows, para el EvtCollector real:
pip install -e ".[windows]"

python cerberus_local.py version
python cerberus_local.py start      # foreground, Ctrl+C para detener
python cerberus_local.py status     # conteos de eventos y findings + estado collectors
\`\`\`

Reportes en `C:\Users\Public\cerberus_reports\` (configurable en `config/cerberus.default.yml`).

## Tests

\`\`\`bash
pytest                       # suite completa con coverage
pytest tests/unit            # solo unitarios
pytest tests/integration     # solo integración
ruff check .
mypy cerberus cerberus_local.py
\`\`\`

## Próximos hitos

- **M3** — `RuleEngine` (YAML Sigma-like), `AIAnalyst` (Ollama, único componente LLM), `OllamaClient`, `PolicyEngine`, `ResponseEngine`, guardrails LLM, pyshark/Npcap + `dns_query`
- **M4** — Windows Service, named pipe IPC, `.msi` instalador, killswitch, anti-tampering, redteam tests

Ver `docs/superpowers/specs/2026-05-21-cerberus-local-edr-design.md` para diseño completo.
```

- [ ] **Step 3: Verificar build limpio**

Run: `pytest && ruff check . && mypy cerberus cerberus_local.py`
Expected: todo verde, coverage ≥ 85%.

- [ ] **Step 4: Commit y tag**

```bash
git add README.md
git commit -m "docs: finalize M2 README; security audit pass (no findings)"
git tag -a v0.2.0-m2 -m "M2: NetCollector + FsCollector + EvtCollector + Correlator"
```

- [ ] **Step 5: Verificación final manual (Windows)**

Run en una ventana: `python cerberus_local.py start`
En otra: abre Notepad, guarda un archivo en `C:\Users\Public`, ábrelo/ciérralo, espera unos segundos, Ctrl+C el agente.

Verificar en el reporte de `cerberus_reports/`:
- Sección `## proc` con `new_process`/`process_exit` para notepad.
- Sección `## fs` con `file_created`/`file_modified` para el archivo guardado.
- Sección `## Findings` (puede estar vacía si no hubo cluster multi-fuente para el mismo pid — es correcto en uso benigno).

Run: `python cerberus_local.py status`
Expected: `Eventos` > 0; `Findings` ≥ 0; `Collectors : proc=True net=True fs=True evt=<True en Windows>`.

---

## Checklist final M2

- [ ] Pre-flight: árbol limpio sobre `v0.1.0-m1`
- [ ] 12 tareas completadas (todas con tests verdes)
- [ ] Coverage ≥ 85%
- [ ] `ruff check .` limpio
- [ ] `mypy cerberus cerberus_local.py` limpio
- [ ] Auditoría `auditing-security` ejecutada sobre módulos M2
- [ ] Smoke test manual (proc + fs) confirmado
- [ ] Invariante §10.5 respetado: 0 LLM en M2 (100% heurístico)
- [ ] Tag `v0.2.0-m2` creado

## Próximo plan

Una vez M2 validado, crear:
`docs/superpowers/plans/YYYY-MM-DD-cerberus-m3-rules-ai-response.md`
(RuleEngine + AIAnalyst + OllamaClient + PolicyEngine + ResponseEngine + guardrails LLM + pyshark/dns_query)
