# CERBERUS-LOCAL · Plan M1 — Esqueleto y ProcCollector

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Producir un vertical slice funcional en Windows: CLI que arranca un `ProcCollector` en modo `dry_run`, normaliza eventos, los persiste a SQLite, y escribe un reporte Markdown cada N segundos. Sin reglas, sin IA, sin respuesta — sólo telemetría → bus → persistencia → reporte.

**Architecture:** Capa heurística pura (sin LLM en este hito). Event dataclass normalizado fluye por un `asyncio.Queue` desde `ProcCollector` (basado en `psutil`) hacia un sink que persiste a SQLite y un `ReportWriter` que renderiza Markdown periódicamente. CLI con subcomandos `start`, `status`, `stop`, `version`.

**Tech Stack:** Python 3.11+, `asyncio`, `psutil`, `pyyaml`, `pytest`, `pytest-asyncio`, SQLite stdlib, `ruff`, `mypy`. **Ningún Windows API exclusivo en M1** (WMI/win32evtlog/pyshark vienen en M2). Esto permite testear M1 cross-platform si hace falta, pero el target oficial es Windows 11.

**Reference spec:** `docs/superpowers/specs/2026-05-21-cerberus-local-edr-design.md`

---

## File Structure (qué se crea en M1)

```
cerberus-local/
├── pyproject.toml               # build + deps + ruff/mypy config
├── .gitignore
├── README.md                    # quickstart minimal
├── cerberus_local.py            # CLI entrypoint
├── cerberus/
│   ├── __init__.py              # __version__ = "0.1.0"
│   ├── core/
│   │   ├── __init__.py
│   │   ├── event.py             # Event dataclass + Severity enum
│   │   ├── event_bus.py         # EventBus (asyncio.Queue + subscribers)
│   │   ├── db.py                # SQLite WAL persistence (events.db)
│   │   ├── config.py            # YAML config loader + defaults
│   │   └── logger.py            # JSON structured logger
│   ├── collectors/
│   │   ├── __init__.py
│   │   ├── base.py              # abstract Collector
│   │   └── proc.py              # ProcCollector (psutil)
│   ├── reporting/
│   │   ├── __init__.py
│   │   └── markdown.py          # daily ReportWriter
│   └── cli/
│       ├── __init__.py
│       └── commands.py          # start/status/stop/version handlers
├── config/
│   └── cerberus.default.yml     # config por defecto
└── tests/
    ├── __init__.py
    ├── unit/
    │   ├── __init__.py
    │   ├── test_event.py
    │   ├── test_event_bus.py
    │   ├── test_db.py
    │   ├── test_config.py
    │   ├── test_logger.py
    │   ├── test_proc_collector.py
    │   └── test_report_markdown.py
    └── integration/
        ├── __init__.py
        └── test_pipeline_m1.py
```

**Out of scope (vienen en hitos posteriores):**
- M2: `NetCollector`, `FsCollector`, `EvtCollector`, Correlator, named pipe IPC
- M3: `RuleEngine`, `AIAnalyst`, `OllamaClient`, `PolicyEngine`, `ResponseEngine`, acciones, rollback
- M4: `CerberusService` (Windows Service), .msi packaging, killswitch, anti-tampering, redteam tests

---

## Task 1: Bootstrap del proyecto

**Files:**
- Create: `cerberus-local/pyproject.toml`
- Create: `cerberus-local/.gitignore`
- Create: `cerberus-local/README.md`
- Create: `cerberus-local/cerberus/__init__.py`
- Create: `cerberus-local/cerberus/core/__init__.py`
- Create: `cerberus-local/cerberus/collectors/__init__.py`
- Create: `cerberus-local/cerberus/reporting/__init__.py`
- Create: `cerberus-local/cerberus/cli/__init__.py`
- Create: `cerberus-local/tests/__init__.py`
- Create: `cerberus-local/tests/unit/__init__.py`
- Create: `cerberus-local/tests/integration/__init__.py`

- [ ] **Step 1: Crear `pyproject.toml`**

```toml
[project]
name = "cerberus-local"
version = "0.1.0"
description = "EDR híbrido Windows con IA local (fork defensivo de HADES-LOCAL)"
requires-python = ">=3.11"
license = {text = "MIT"}
authors = [{name = "Fabián Hormazábal", email = "combatelamejor@gmail.com"}]
dependencies = [
    "psutil>=5.9.8",
    "pyyaml>=6.0.1",
]

[project.optional-dependencies]
dev = [
    "pytest>=8.0",
    "pytest-asyncio>=0.23",
    "pytest-cov>=4.1",
    "ruff>=0.4",
    "mypy>=1.10",
]

[project.scripts]
cerberus = "cerberus_local:main"

[tool.ruff]
line-length = 100
target-version = "py311"

[tool.ruff.lint]
select = ["E", "F", "I", "B", "UP", "ASYNC"]

[tool.mypy]
python_version = "3.11"
strict = true
warn_unused_ignores = true

[tool.pytest.ini_options]
asyncio_mode = "auto"
testpaths = ["tests"]
addopts = "-v --cov=cerberus --cov-report=term-missing --cov-fail-under=85"

[build-system]
requires = ["setuptools>=68", "wheel"]
build-backend = "setuptools.build_meta"
```

- [ ] **Step 2: Crear `.gitignore`**

```
__pycache__/
*.pyc
*.pyo
*.egg-info/
.venv/
venv/
dist/
build/
.pytest_cache/
.mypy_cache/
.ruff_cache/
.coverage
coverage.xml
htmlcov/
*.db
*.db-wal
*.db-shm
.idea/
.vscode/
*.log
cerberus_reports/
```

- [ ] **Step 3: Crear `README.md` mínimo**

```markdown
# CERBERUS-LOCAL

EDR híbrido Windows con IA local Ollama. Fork defensivo de HADES-LOCAL.

**Estado:** M1 — esqueleto + ProcCollector (sin detección, sin respuesta).

## Quickstart

\`\`\`bash
python -m venv .venv
.venv\Scripts\activate    # Windows
pip install -e ".[dev]"
python cerberus_local.py version
python cerberus_local.py start --dry-run
\`\`\`

Ver `docs/superpowers/specs/2026-05-21-cerberus-local-edr-design.md` para el diseño completo.
```

- [ ] **Step 4: Crear todos los `__init__.py` vacíos excepto el raíz**

`cerberus/__init__.py`:
```python
__version__ = "0.1.0"
```

Los demás `__init__.py` quedan vacíos (un archivo de 0 bytes cada uno).

- [ ] **Step 5: Instalar dependencias y verificar**

Run: `python -m venv .venv && .venv\Scripts\activate && pip install -e ".[dev]"`
Expected: instalación exitosa, sin errores.

Run: `python -c "import cerberus; print(cerberus.__version__)"`
Expected: `0.1.0`

- [ ] **Step 6: Init git y commit**

```bash
git init
git add .
git commit -m "chore: bootstrap cerberus-local M1 project structure"
```

---

## Task 2: Event dataclass + Severity enum

**Files:**
- Create: `cerberus/core/event.py`
- Test: `tests/unit/test_event.py`

- [ ] **Step 1: Escribir tests fallidos**

`tests/unit/test_event.py`:
```python
from datetime import datetime, timezone
from cerberus.core.event import Event, Severity


def test_event_creates_with_required_fields():
    ev = Event(
        source="proc",
        type="new_process",
        host="DESKTOP-X",
        pid=1234,
        user="DESKTOP-X\\fabian",
        raw={"name": "notepad.exe"},
        indicators={"binary": "C:\\Windows\\notepad.exe"},
    )
    assert ev.source == "proc"
    assert ev.type == "new_process"
    assert isinstance(ev.id, str) and len(ev.id) == 36  # uuid4
    assert ev.timestamp.tzinfo == timezone.utc


def test_event_id_unique():
    a = Event(source="proc", type="x", host="h", pid=None, user=None, raw={}, indicators={})
    b = Event(source="proc", type="x", host="h", pid=None, user=None, raw={}, indicators={})
    assert a.id != b.id


def test_event_to_dict_roundtrip():
    ev = Event(source="proc", type="new_process", host="h", pid=1, user=None, raw={"k": "v"}, indicators={})
    d = ev.to_dict()
    assert d["source"] == "proc"
    assert d["raw"] == {"k": "v"}
    assert isinstance(d["timestamp"], str)  # ISO-8601


def test_event_invalid_source_raises():
    import pytest
    with pytest.raises(ValueError):
        Event(source="invalid", type="x", host="h", pid=None, user=None, raw={}, indicators={})


def test_severity_ordering():
    assert Severity.INFO < Severity.LOW < Severity.MEDIUM < Severity.HIGH < Severity.CRITICAL
```

- [ ] **Step 2: Correr tests, verificar que fallan**

Run: `pytest tests/unit/test_event.py -v`
Expected: FAIL con `ModuleNotFoundError: cerberus.core.event`

- [ ] **Step 3: Implementar `cerberus/core/event.py`**

```python
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import IntEnum
from typing import Any, Literal

SourceType = Literal["proc", "net", "fs", "evt"]
_VALID_SOURCES = {"proc", "net", "fs", "evt"}


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass(frozen=True)
class Event:
    """Evento normalizado emitido por cualquier collector."""

    source: SourceType
    type: str
    host: str
    pid: int | None
    user: str | None
    raw: dict[str, Any]
    indicators: dict[str, Any]
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self) -> None:
        if self.source not in _VALID_SOURCES:
            raise ValueError(
                f"Invalid source {self.source!r}; must be one of {sorted(_VALID_SOURCES)}"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "source": self.source,
            "type": self.type,
            "host": self.host,
            "pid": self.pid,
            "user": self.user,
            "raw": self.raw,
            "indicators": self.indicators,
        }
```

- [ ] **Step 4: Correr tests, verificar que pasan**

Run: `pytest tests/unit/test_event.py -v`
Expected: 5 passed.

- [ ] **Step 5: Commit**

```bash
git add cerberus/core/event.py tests/unit/test_event.py
git commit -m "feat(core): add Event dataclass with Severity enum"
```

---

## Task 3: Logger JSON estructurado

**Files:**
- Create: `cerberus/core/logger.py`
- Test: `tests/unit/test_logger.py`

- [ ] **Step 1: Escribir tests fallidos**

`tests/unit/test_logger.py`:
```python
import json
import logging
from io import StringIO

from cerberus.core.logger import JsonFormatter, get_logger


def test_json_formatter_outputs_valid_json():
    formatter = JsonFormatter()
    record = logging.LogRecord(
        name="cerberus.test",
        level=logging.INFO,
        pathname=__file__,
        lineno=10,
        msg="hello %s",
        args=("world",),
        exc_info=None,
    )
    line = formatter.format(record)
    payload = json.loads(line)
    assert payload["level"] == "INFO"
    assert payload["logger"] == "cerberus.test"
    assert payload["message"] == "hello world"
    assert "timestamp" in payload


def test_get_logger_writes_to_stream():
    stream = StringIO()
    logger = get_logger("cerberus.tests.unit", stream=stream)
    logger.info("payload", extra={"event_id": "abc-123"})
    payload = json.loads(stream.getvalue().splitlines()[-1])
    assert payload["message"] == "payload"
    assert payload["event_id"] == "abc-123"


def test_get_logger_is_idempotent():
    a = get_logger("cerberus.tests.unit")
    b = get_logger("cerberus.tests.unit")
    assert a is b
    # No debe duplicar handlers al pedirlo dos veces.
    assert len(a.handlers) == len(b.handlers)
```

- [ ] **Step 2: Correr y verificar fallo**

Run: `pytest tests/unit/test_logger.py -v`
Expected: FAIL con `ModuleNotFoundError`.

- [ ] **Step 3: Implementar `cerberus/core/logger.py`**

```python
from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from typing import IO, Any

_STANDARD_RECORD_ATTRS = {
    "name", "msg", "args", "levelname", "levelno", "pathname", "filename",
    "module", "exc_info", "exc_text", "stack_info", "lineno", "funcName",
    "created", "msecs", "relativeCreated", "thread", "threadName",
    "processName", "process", "message", "asctime",
}


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for key, value in record.__dict__.items():
            if key not in _STANDARD_RECORD_ATTRS and not key.startswith("_"):
                payload[key] = value
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def get_logger(name: str, stream: IO[str] | None = None) -> logging.Logger:
    logger = logging.getLogger(name)
    if getattr(logger, "_cerberus_configured", False):
        return logger
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler(stream if stream is not None else sys.stderr)
    handler.setFormatter(JsonFormatter())
    logger.addHandler(handler)
    logger.propagate = False
    logger._cerberus_configured = True  # type: ignore[attr-defined]
    return logger
```

- [ ] **Step 4: Correr tests, verificar pasan**

Run: `pytest tests/unit/test_logger.py -v`
Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git add cerberus/core/logger.py tests/unit/test_logger.py
git commit -m "feat(core): add JSON structured logger"
```

---

## Task 4: EventBus (asyncio.Queue + subscribers)

**Files:**
- Create: `cerberus/core/event_bus.py`
- Test: `tests/unit/test_event_bus.py`

- [ ] **Step 1: Escribir tests fallidos**

`tests/unit/test_event_bus.py`:
```python
import asyncio
import pytest

from cerberus.core.event import Event
from cerberus.core.event_bus import EventBus


def _evt(source="proc", type_="new_process"):
    return Event(
        source=source, type=type_, host="h", pid=1,
        user=None, raw={}, indicators={},
    )


async def test_subscriber_receives_published_event():
    bus = EventBus()
    received: list[Event] = []

    async def handler(ev: Event) -> None:
        received.append(ev)

    bus.subscribe(handler)
    bus.start()
    await bus.publish(_evt())
    await bus.drain()
    assert len(received) == 1


async def test_filter_by_source():
    bus = EventBus()
    proc_events: list[Event] = []
    net_events: list[Event] = []

    bus.subscribe(lambda e: proc_events.append(e), source_filter="proc")
    bus.subscribe(lambda e: net_events.append(e), source_filter="net")
    bus.start()
    await bus.publish(_evt(source="proc"))
    await bus.publish(_evt(source="net"))
    await bus.drain()
    assert len(proc_events) == 1 and len(net_events) == 1


async def test_handler_exception_does_not_break_bus():
    bus = EventBus()

    async def bad(ev: Event) -> None:
        raise RuntimeError("boom")

    good_calls: list[Event] = []
    bus.subscribe(bad)
    bus.subscribe(lambda e: good_calls.append(e))
    bus.start()
    await bus.publish(_evt())
    await bus.drain()
    assert len(good_calls) == 1  # un handler malo no impide al otro


async def test_unsubscribe():
    bus = EventBus()
    calls: list[Event] = []
    sub = bus.subscribe(lambda e: calls.append(e))
    bus.start()
    await bus.publish(_evt())
    await bus.drain()
    sub.unsubscribe()
    await bus.publish(_evt())
    await bus.drain()
    assert len(calls) == 1


async def test_stop_drains_pending():
    bus = EventBus()
    received: list[Event] = []
    bus.subscribe(lambda e: received.append(e))
    bus.start()
    for _ in range(5):
        await bus.publish(_evt())
    await bus.stop()
    assert len(received) == 5
```

- [ ] **Step 2: Correr y verificar fallo**

Run: `pytest tests/unit/test_event_bus.py -v`
Expected: FAIL — `ModuleNotFoundError`.

- [ ] **Step 3: Implementar `cerberus/core/event_bus.py`**

```python
from __future__ import annotations

import asyncio
import inspect
from dataclasses import dataclass, field
from typing import Awaitable, Callable

from cerberus.core.event import Event
from cerberus.core.logger import get_logger

_log = get_logger("cerberus.core.event_bus")

Handler = Callable[[Event], Awaitable[None] | None]


@dataclass
class Subscription:
    handler: Handler
    source_filter: str | None
    _bus: "EventBus"
    _alive: bool = field(default=True, repr=False)

    def unsubscribe(self) -> None:
        if self._alive:
            self._bus._remove(self)
            self._alive = False


class EventBus:
    def __init__(self, maxsize: int = 10_000) -> None:
        self._queue: asyncio.Queue[Event] = asyncio.Queue(maxsize=maxsize)
        self._subs: list[Subscription] = []
        self._dispatcher: asyncio.Task[None] | None = None
        self._closed = False

    def subscribe(self, handler: Handler, source_filter: str | None = None) -> Subscription:
        sub = Subscription(handler=handler, source_filter=source_filter, _bus=self)
        self._subs.append(sub)
        return sub

    def _remove(self, sub: Subscription) -> None:
        try:
            self._subs.remove(sub)
        except ValueError:
            pass

    def start(self) -> None:
        if self._dispatcher is None:
            self._dispatcher = asyncio.create_task(self._run(), name="event_bus")

    async def publish(self, event: Event) -> None:
        if self._closed:
            raise RuntimeError("EventBus is closed")
        await self._queue.put(event)

    async def drain(self) -> None:
        await self._queue.join()

    async def stop(self) -> None:
        await self.drain()
        self._closed = True
        if self._dispatcher is not None:
            self._dispatcher.cancel()
            try:
                await self._dispatcher
            except asyncio.CancelledError:
                pass
            self._dispatcher = None

    async def _run(self) -> None:
        while True:
            event = await self._queue.get()
            try:
                await self._dispatch(event)
            finally:
                self._queue.task_done()

    async def _dispatch(self, event: Event) -> None:
        for sub in list(self._subs):
            if sub.source_filter and sub.source_filter != event.source:
                continue
            try:
                result = sub.handler(event)
                if inspect.isawaitable(result):
                    await result
            except Exception as exc:  # un handler malo no debe romper al resto
                _log.error("handler_error", extra={"error": str(exc), "event_id": event.id})
```

- [ ] **Step 4: Correr tests**

Run: `pytest tests/unit/test_event_bus.py -v`
Expected: 5 passed.

- [ ] **Step 5: Commit**

```bash
git add cerberus/core/event_bus.py tests/unit/test_event_bus.py
git commit -m "feat(core): add EventBus with subscriber pattern"
```

---

## Task 5: SQLite persistence (events.db)

**Files:**
- Create: `cerberus/core/db.py`
- Test: `tests/unit/test_db.py`

- [ ] **Step 1: Tests fallidos**

`tests/unit/test_db.py`:
```python
from pathlib import Path

import pytest

from cerberus.core.db import EventStore
from cerberus.core.event import Event


@pytest.fixture
def store(tmp_path: Path) -> EventStore:
    s = EventStore(tmp_path / "events.db")
    s.init_schema()
    return s


def _evt(source="proc", type_="new_process") -> Event:
    return Event(
        source=source, type=type_, host="h", pid=1,
        user=None, raw={"name": "x.exe"}, indicators={"hash": "abc"},
    )


def test_init_schema_creates_table(store: EventStore):
    assert store.table_exists("events")


def test_insert_and_fetch(store: EventStore):
    ev = _evt()
    store.insert(ev)
    rows = store.fetch_all()
    assert len(rows) == 1
    assert rows[0]["id"] == ev.id
    assert rows[0]["source"] == "proc"


def test_fetch_by_source(store: EventStore):
    store.insert(_evt(source="proc"))
    store.insert(_evt(source="net"))
    proc_rows = store.fetch_by_source("proc")
    assert len(proc_rows) == 1


def test_count(store: EventStore):
    for _ in range(7):
        store.insert(_evt())
    assert store.count() == 7


def test_purge_older_than_days(store: EventStore, monkeypatch):
    from datetime import datetime, timedelta, timezone
    old = _evt()
    object.__setattr__(old, "timestamp", datetime.now(timezone.utc) - timedelta(days=10))
    store.insert(old)
    store.insert(_evt())
    deleted = store.purge_older_than(days=7)
    assert deleted == 1
    assert store.count() == 1
```

- [ ] **Step 2: Correr y verificar fallo**

Run: `pytest tests/unit/test_db.py -v`
Expected: FAIL.

- [ ] **Step 3: Implementar `cerberus/core/db.py`**

```python
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cerberus.core.event import Event

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id          TEXT PRIMARY KEY,
    timestamp   TEXT NOT NULL,
    source      TEXT NOT NULL,
    type        TEXT NOT NULL,
    host        TEXT NOT NULL,
    pid         INTEGER,
    user        TEXT,
    raw         TEXT NOT NULL,
    indicators  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_source ON events(source);
"""


class EventStore:
    def __init__(self, path: Path | str) -> None:
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

    def insert(self, event: Event) -> None:
        self._conn.execute(
            """
            INSERT INTO events(id, timestamp, source, type, host, pid, user, raw, indicators)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event.id,
                event.timestamp.isoformat(),
                event.source,
                event.type,
                event.host,
                event.pid,
                event.user,
                json.dumps(event.raw),
                json.dumps(event.indicators),
            ),
        )

    def fetch_all(self) -> list[dict[str, Any]]:
        rows = self._conn.execute("SELECT * FROM events ORDER BY timestamp").fetchall()
        return [dict(r) for r in rows]

    def fetch_by_source(self, source: str) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT * FROM events WHERE source=? ORDER BY timestamp", (source,),
        ).fetchall()
        return [dict(r) for r in rows]

    def count(self) -> int:
        row = self._conn.execute("SELECT COUNT(*) AS n FROM events").fetchone()
        return int(row["n"])

    def purge_older_than(self, days: int) -> int:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        cur = self._conn.execute("DELETE FROM events WHERE timestamp < ?", (cutoff,))
        return cur.rowcount

    def close(self) -> None:
        self._conn.close()
```

- [ ] **Step 4: Correr tests**

Run: `pytest tests/unit/test_db.py -v`
Expected: 5 passed.

- [ ] **Step 5: Commit**

```bash
git add cerberus/core/db.py tests/unit/test_db.py
git commit -m "feat(core): add SQLite EventStore with WAL mode"
```

---

## Task 6: Config loader (YAML)

**Files:**
- Create: `cerberus/core/config.py`
- Create: `config/cerberus.default.yml`
- Test: `tests/unit/test_config.py`

- [ ] **Step 1: Crear `config/cerberus.default.yml`**

```yaml
# Cerberus M1 default config
mode: dry_run                       # dry_run | monitor (auto_* vienen en M3)
host_name: null                     # null = autodetect

paths:
  data_dir: "C:\\ProgramData\\Cerberus"
  events_db: "C:\\ProgramData\\Cerberus\\db\\events.db"
  reports_dir: "C:\\Users\\Public\\cerberus_reports"
  log_file: "C:\\ProgramData\\Cerberus\\logs\\cerberus.log"

collectors:
  proc:
    enabled: true
    poll_interval_seconds: 1.0

reporting:
  interval_seconds: 300              # 5 minutos
  retention_days: 7
```

- [ ] **Step 2: Tests fallidos**

`tests/unit/test_config.py`:
```python
from pathlib import Path

import pytest

from cerberus.core.config import CerberusConfig, load_config


def test_load_default_config(tmp_path: Path):
    cfg_file = tmp_path / "c.yml"
    cfg_file.write_text(
        """
mode: dry_run
host_name: null
paths:
  data_dir: /tmp/cerberus
  events_db: /tmp/cerberus/events.db
  reports_dir: /tmp/cerberus_reports
  log_file: /tmp/cerberus.log
collectors:
  proc:
    enabled: true
    poll_interval_seconds: 1.0
reporting:
  interval_seconds: 300
  retention_days: 7
"""
    )
    cfg = load_config(cfg_file)
    assert isinstance(cfg, CerberusConfig)
    assert cfg.mode == "dry_run"
    assert cfg.collectors.proc.poll_interval_seconds == 1.0
    assert cfg.reporting.retention_days == 7


def test_invalid_mode_raises(tmp_path: Path):
    cfg_file = tmp_path / "c.yml"
    cfg_file.write_text("mode: nuke_everything\npaths: {}\ncollectors: {}\nreporting: {}\n")
    with pytest.raises(ValueError):
        load_config(cfg_file)


def test_host_name_autodetected_when_null(tmp_path: Path):
    cfg_file = tmp_path / "c.yml"
    cfg_file.write_text(
        """
mode: dry_run
host_name: null
paths: {data_dir: /tmp/c, events_db: /tmp/c.db, reports_dir: /tmp/r, log_file: /tmp/l}
collectors: {proc: {enabled: true, poll_interval_seconds: 1.0}}
reporting: {interval_seconds: 60, retention_days: 1}
"""
    )
    cfg = load_config(cfg_file)
    assert cfg.host_name  # no es None ni vacío
    assert isinstance(cfg.host_name, str)
```

- [ ] **Step 3: Correr y verificar fallo**

Run: `pytest tests/unit/test_config.py -v`
Expected: FAIL.

- [ ] **Step 4: Implementar `cerberus/core/config.py`**

```python
from __future__ import annotations

import socket
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import yaml

Mode = Literal["dry_run", "monitor"]  # auto_* se añaden en M3
_VALID_MODES = {"dry_run", "monitor"}


@dataclass(frozen=True)
class ProcCollectorConfig:
    enabled: bool
    poll_interval_seconds: float


@dataclass(frozen=True)
class CollectorsConfig:
    proc: ProcCollectorConfig


@dataclass(frozen=True)
class PathsConfig:
    data_dir: Path
    events_db: Path
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
    reporting: ReportingConfig


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
        reports_dir=Path(paths_raw.get("reports_dir", "")),
        log_file=Path(paths_raw.get("log_file", "")),
    )
    coll_raw = raw.get("collectors", {})
    proc_raw = coll_raw.get("proc", {})
    collectors = CollectorsConfig(
        proc=ProcCollectorConfig(
            enabled=bool(proc_raw.get("enabled", True)),
            poll_interval_seconds=float(proc_raw.get("poll_interval_seconds", 1.0)),
        )
    )
    rep_raw = raw.get("reporting", {})
    reporting = ReportingConfig(
        interval_seconds=int(rep_raw.get("interval_seconds", 300)),
        retention_days=int(rep_raw.get("retention_days", 7)),
    )
    return CerberusConfig(
        mode=mode, host_name=host, paths=paths,
        collectors=collectors, reporting=reporting,
    )
```

- [ ] **Step 5: Correr tests**

Run: `pytest tests/unit/test_config.py -v`
Expected: 3 passed.

- [ ] **Step 6: Commit**

```bash
git add cerberus/core/config.py config/cerberus.default.yml tests/unit/test_config.py
git commit -m "feat(core): add YAML config loader with defaults"
```

---

## Task 7: Collector abstract base

**Files:**
- Create: `cerberus/collectors/base.py`
- Test (más tarde en Task 8 con `ProcCollector` real)

- [ ] **Step 1: Implementar `cerberus/collectors/base.py`**

```python
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from cerberus.core.event_bus import EventBus


@dataclass
class CollectorHealth:
    name: str
    running: bool
    events_emitted: int
    last_error: str | None


class Collector(ABC):
    name: str = "collector"

    def __init__(self) -> None:
        self._events_emitted: int = 0
        self._last_error: str | None = None
        self._running: bool = False

    @abstractmethod
    async def start(self, bus: EventBus) -> None: ...

    @abstractmethod
    async def stop(self) -> None: ...

    def health(self) -> CollectorHealth:
        return CollectorHealth(
            name=self.name,
            running=self._running,
            events_emitted=self._events_emitted,
            last_error=self._last_error,
        )
```

- [ ] **Step 2: Verificar import sin errores**

Run: `python -c "from cerberus.collectors.base import Collector, CollectorHealth; print('ok')"`
Expected: `ok`.

- [ ] **Step 3: Commit**

```bash
git add cerberus/collectors/base.py
git commit -m "feat(collectors): add abstract Collector base"
```

---

## Task 8: ProcCollector (psutil)

> **Antes de codear este módulo:** invocar skill `using-context7` para verificar APIs actuales de `psutil` v5.9.8+ (`process_iter`, `Process.cmdline`, `Process.username`, `Process.create_time`).

**Files:**
- Create: `cerberus/collectors/proc.py`
- Test: `tests/unit/test_proc_collector.py`

- [ ] **Step 1: Tests fallidos con mocks de psutil**

`tests/unit/test_proc_collector.py`:
```python
import asyncio
from unittest.mock import MagicMock, patch

import pytest

from cerberus.collectors.proc import ProcCollector
from cerberus.core.event import Event
from cerberus.core.event_bus import EventBus


class _FakeProc:
    def __init__(self, pid, name, cmdline, username, create_time):
        self.pid = pid
        self.info = {
            "pid": pid,
            "name": name,
            "cmdline": cmdline,
            "username": username,
            "create_time": create_time,
            "exe": f"C:\\\\Windows\\\\{name}",
        }


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
    except asyncio.TimeoutError:
        pass
    await bus.stop()
    return received


@pytest.mark.asyncio
async def test_proc_collector_emits_new_process_events():
    fake_procs_before = [_FakeProc(100, "explorer.exe", ["explorer.exe"], "u", 1000.0)]
    fake_procs_after = fake_procs_before + [
        _FakeProc(200, "notepad.exe", ["notepad.exe", "a.txt"], "u", 2000.0),
    ]
    iterations = iter([fake_procs_before, fake_procs_after])

    def fake_iter(attrs):
        return next(iterations)

    bus = EventBus()
    collector = ProcCollector(host="H", poll_interval_seconds=0.05)
    with patch("cerberus.collectors.proc.psutil.process_iter", side_effect=fake_iter):
        task = asyncio.create_task(collector.start(bus))
        received = await _collect_events(bus, target_count=1, timeout=1.0)
        await collector.stop()
        task.cancel()

    types = {ev.type for ev in received}
    assert "new_process" in types
    new = next(e for e in received if e.type == "new_process")
    assert new.pid == 200
    assert new.indicators.get("name") == "notepad.exe"


@pytest.mark.asyncio
async def test_proc_collector_emits_process_exit():
    procs_a = [_FakeProc(100, "a.exe", ["a.exe"], "u", 1.0),
               _FakeProc(200, "b.exe", ["b.exe"], "u", 1.0)]
    procs_b = [_FakeProc(100, "a.exe", ["a.exe"], "u", 1.0)]  # 200 desapareció
    iterations = iter([procs_a, procs_b])

    def fake_iter(attrs):
        return next(iterations)

    bus = EventBus()
    collector = ProcCollector(host="H", poll_interval_seconds=0.05)
    with patch("cerberus.collectors.proc.psutil.process_iter", side_effect=fake_iter):
        task = asyncio.create_task(collector.start(bus))
        received = await _collect_events(bus, target_count=1, timeout=1.0)
        await collector.stop()
        task.cancel()

    exit_events = [e for e in received if e.type == "process_exit"]
    assert len(exit_events) >= 1
    assert exit_events[0].pid == 200


def test_proc_collector_health_initial():
    c = ProcCollector(host="H")
    h = c.health()
    assert h.name == "proc"
    assert h.running is False
    assert h.events_emitted == 0
```

- [ ] **Step 2: Correr y verificar fallo**

Run: `pytest tests/unit/test_proc_collector.py -v`
Expected: FAIL.

- [ ] **Step 3: Implementar `cerberus/collectors/proc.py`**

```python
from __future__ import annotations

import asyncio
from typing import Any

import psutil

from cerberus.collectors.base import Collector
from cerberus.core.event import Event
from cerberus.core.event_bus import EventBus
from cerberus.core.logger import get_logger

_log = get_logger("cerberus.collectors.proc")

_PROC_ATTRS = ["pid", "name", "cmdline", "username", "create_time", "exe"]


class ProcCollector(Collector):
    name = "proc"

    def __init__(self, host: str, poll_interval_seconds: float = 1.0) -> None:
        super().__init__()
        self._host = host
        self._interval = poll_interval_seconds
        self._known_pids: set[int] = set()
        self._known_meta: dict[int, dict[str, Any]] = {}
        self._stop = asyncio.Event()

    async def start(self, bus: EventBus) -> None:
        self._running = True
        self._stop.clear()
        try:
            await self._seed()
            while not self._stop.is_set():
                try:
                    await self._tick(bus)
                except Exception as exc:
                    self._last_error = repr(exc)
                    _log.error("proc_tick_error", extra={"error": str(exc)})
                try:
                    await asyncio.wait_for(self._stop.wait(), timeout=self._interval)
                except asyncio.TimeoutError:
                    pass
        finally:
            self._running = False

    async def stop(self) -> None:
        self._stop.set()

    async def _seed(self) -> None:
        for proc in psutil.process_iter(attrs=_PROC_ATTRS):
            info = proc.info
            self._known_pids.add(info["pid"])
            self._known_meta[info["pid"]] = info

    async def _tick(self, bus: EventBus) -> None:
        current_meta: dict[int, dict[str, Any]] = {}
        current_pids: set[int] = set()
        for proc in psutil.process_iter(attrs=_PROC_ATTRS):
            info = proc.info
            current_meta[info["pid"]] = info
            current_pids.add(info["pid"])

        for pid in current_pids - self._known_pids:
            info = current_meta[pid]
            ev = Event(
                source="proc",
                type="new_process",
                host=self._host,
                pid=pid,
                user=info.get("username"),
                raw=info,
                indicators={
                    "name": info.get("name"),
                    "cmdline": " ".join(info.get("cmdline") or []),
                    "exe": info.get("exe"),
                },
            )
            await bus.publish(ev)
            self._events_emitted += 1

        for pid in self._known_pids - current_pids:
            info = self._known_meta.get(pid, {"pid": pid})
            ev = Event(
                source="proc",
                type="process_exit",
                host=self._host,
                pid=pid,
                user=info.get("username"),
                raw=info,
                indicators={"name": info.get("name")},
            )
            await bus.publish(ev)
            self._events_emitted += 1

        self._known_pids = current_pids
        self._known_meta = current_meta
```

- [ ] **Step 4: Correr tests**

Run: `pytest tests/unit/test_proc_collector.py -v`
Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git add cerberus/collectors/proc.py tests/unit/test_proc_collector.py
git commit -m "feat(collectors): add ProcCollector with psutil polling"
```

---

## Task 9: Markdown ReportWriter

**Files:**
- Create: `cerberus/reporting/markdown.py`
- Test: `tests/unit/test_report_markdown.py`

- [ ] **Step 1: Tests fallidos**

`tests/unit/test_report_markdown.py`:
```python
from datetime import datetime, timezone
from pathlib import Path

from cerberus.core.event import Event
from cerberus.reporting.markdown import MarkdownReportWriter


def _ev(source, type_, **kw):
    base = dict(host="H", pid=1, user=None, raw={}, indicators={})
    base.update(kw)
    return Event(source=source, type=type_, **base)


def test_render_empty_report():
    out = MarkdownReportWriter.render([], host="H")
    assert "# CERBERUS-LOCAL — Reporte" in out
    assert "Sin eventos" in out


def test_render_report_groups_by_source():
    events = [
        _ev("proc", "new_process", pid=10, indicators={"name": "a.exe"}),
        _ev("proc", "new_process", pid=11, indicators={"name": "b.exe"}),
        _ev("proc", "process_exit", pid=12),
    ]
    out = MarkdownReportWriter.render(events, host="H")
    assert "## proc" in out
    assert "new_process" in out
    assert "process_exit" in out
    assert "**Total eventos:** 3" in out


def test_write_creates_file(tmp_path: Path):
    writer = MarkdownReportWriter(reports_dir=tmp_path, host="H")
    events = [_ev("proc", "new_process", pid=10, indicators={"name": "x.exe"})]
    path = writer.write(events, when=datetime(2026, 5, 21, 14, 30, tzinfo=timezone.utc))
    assert path.exists()
    name = path.name
    assert name.startswith("2026-05-21_14-30") and name.endswith(".md")
    content = path.read_text(encoding="utf-8")
    assert "## proc" in content
```

- [ ] **Step 2: Correr y verificar fallo**

Run: `pytest tests/unit/test_report_markdown.py -v`
Expected: FAIL.

- [ ] **Step 3: Implementar `cerberus/reporting/markdown.py`**

```python
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

from cerberus.core.event import Event


class MarkdownReportWriter:
    def __init__(self, reports_dir: Path, host: str) -> None:
        self.reports_dir = Path(reports_dir)
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.host = host

    @staticmethod
    def render(events: list[Event], host: str, when: datetime | None = None) -> str:
        when = when or datetime.now(timezone.utc)
        lines: list[str] = []
        lines.append("# CERBERUS-LOCAL — Reporte")
        lines.append("")
        lines.append(f"**Host:** {host}")
        lines.append(f"**Generado:** {when.isoformat()}")
        lines.append(f"**Total eventos:** {len(events)}")
        lines.append("")
        if not events:
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

    def write(self, events: list[Event], when: datetime | None = None) -> Path:
        when = when or datetime.now(timezone.utc)
        filename = when.strftime("%Y-%m-%d_%H-%M") + ".md"
        path = self.reports_dir / filename
        path.write_text(self.render(events, host=self.host, when=when), encoding="utf-8")
        return path
```

- [ ] **Step 4: Correr tests**

Run: `pytest tests/unit/test_report_markdown.py -v`
Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git add cerberus/reporting/markdown.py tests/unit/test_report_markdown.py
git commit -m "feat(reporting): add Markdown report writer"
```

---

## Task 10: CLI commands (start/status/stop/version)

**Files:**
- Create: `cerberus/cli/commands.py`
- Create: `cerberus_local.py`
- Test: integración cubre esta capa en Task 11.

- [ ] **Step 1: Implementar `cerberus/cli/commands.py`**

```python
from __future__ import annotations

import asyncio
import signal
from datetime import datetime, timezone
from pathlib import Path

from cerberus import __version__
from cerberus.collectors.proc import ProcCollector
from cerberus.core.config import CerberusConfig, load_config
from cerberus.core.db import EventStore
from cerberus.core.event import Event
from cerberus.core.event_bus import EventBus
from cerberus.core.logger import get_logger
from cerberus.reporting.markdown import MarkdownReportWriter

_log = get_logger("cerberus.cli")


def cmd_version() -> int:
    print(f"cerberus-local {__version__}")
    return 0


def cmd_status(cfg: CerberusConfig) -> int:
    store = EventStore(cfg.paths.events_db)
    store.init_schema()
    print(f"Host       : {cfg.host_name}")
    print(f"Mode       : {cfg.mode}")
    print(f"Events DB  : {cfg.paths.events_db}")
    print(f"Eventos    : {store.count()}")
    store.close()
    return 0


def cmd_start(cfg: CerberusConfig) -> int:
    if cfg.mode != "dry_run":
        # M1 sólo soporta dry_run; monitor/auto_* vienen en hitos posteriores
        _log.warning("mode_forced_dry_run", extra={"requested": cfg.mode})
    return asyncio.run(_run_loop(cfg))


async def _run_loop(cfg: CerberusConfig) -> int:
    store = EventStore(cfg.paths.events_db)
    store.init_schema()
    bus = EventBus()
    writer = MarkdownReportWriter(cfg.paths.reports_dir, host=cfg.host_name)

    collected: list[Event] = []

    async def persist_and_buffer(ev: Event) -> None:
        store.insert(ev)
        collected.append(ev)

    bus.subscribe(persist_and_buffer)
    bus.start()

    collector = ProcCollector(
        host=cfg.host_name,
        poll_interval_seconds=cfg.collectors.proc.poll_interval_seconds,
    )
    collector_task = asyncio.create_task(collector.start(bus), name="proc_collector")
    reporter_task = asyncio.create_task(
        _report_loop(writer, collected, cfg.reporting.interval_seconds),
        name="reporter",
    )

    stop_event = asyncio.Event()

    def _on_signal(*_a):
        stop_event.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _on_signal)
        except NotImplementedError:
            # Windows no soporta add_signal_handler para SIGTERM en algunos contextos
            signal.signal(sig, lambda *_: stop_event.set())

    _log.info("cerberus_started", extra={"host": cfg.host_name, "mode": cfg.mode})
    try:
        await stop_event.wait()
    finally:
        await collector.stop()
        collector_task.cancel()
        reporter_task.cancel()
        for t in (collector_task, reporter_task):
            try:
                await t
            except asyncio.CancelledError:
                pass
        await bus.stop()
        if collected:
            writer.write(collected, when=datetime.now(timezone.utc))
        store.close()
    return 0


async def _report_loop(writer: MarkdownReportWriter, buffer: list[Event], interval: int) -> None:
    while True:
        await asyncio.sleep(interval)
        snapshot = list(buffer)
        buffer.clear()
        writer.write(snapshot, when=datetime.now(timezone.utc))


def cmd_stop(cfg: CerberusConfig) -> int:
    # M1 corre en foreground; stop = matar el proceso. Se elaborará IPC en M4.
    print("M1 corre en foreground. Usa Ctrl+C para detener.")
    return 0


def resolve_config(path: Path | None) -> CerberusConfig:
    if path is None:
        path = Path(__file__).resolve().parent.parent.parent / "config" / "cerberus.default.yml"
    return load_config(path)
```

- [ ] **Step 2: Implementar `cerberus_local.py` (entrypoint)**

```python
#!/usr/bin/env python3
"""CERBERUS-LOCAL CLI (M1)."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from cerberus.cli.commands import (
    cmd_start, cmd_status, cmd_stop, cmd_version, resolve_config,
)


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="cerberus_local.py", description="CERBERUS-LOCAL EDR (M1)")
    sub = p.add_subparsers(dest="command", required=True)
    for name in ("start", "status", "stop"):
        s = sub.add_parser(name)
        s.add_argument("--config", type=Path, default=None, help="Ruta a YAML de config")
        if name == "start":
            s.add_argument("--dry-run", action="store_true", help="Forzar modo dry_run")
    sub.add_parser("version")
    return p


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.command == "version":
        return cmd_version()
    cfg = resolve_config(args.config)
    if args.command == "start":
        return cmd_start(cfg)
    if args.command == "status":
        return cmd_status(cfg)
    if args.command == "stop":
        return cmd_stop(cfg)
    return 2


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 3: Smoke test manual**

Run: `python cerberus_local.py version`
Expected: `cerberus-local 0.1.0`.

Run: `python cerberus_local.py status`
Expected: imprime tabla con host, mode, events DB y count = 0 (o > 0 si has corrido start antes).

- [ ] **Step 4: Commit**

```bash
git add cerberus/cli/commands.py cerberus_local.py
git commit -m "feat(cli): add start/status/stop/version commands"
```

---

## Task 11: Integration test M1 (vertical slice)

**Files:**
- Test: `tests/integration/test_pipeline_m1.py`

- [ ] **Step 1: Escribir test de integración**

`tests/integration/test_pipeline_m1.py`:
```python
import asyncio
from pathlib import Path
from unittest.mock import patch

import pytest

from cerberus.collectors.proc import ProcCollector
from cerberus.core.db import EventStore
from cerberus.core.event import Event
from cerberus.core.event_bus import EventBus
from cerberus.reporting.markdown import MarkdownReportWriter


class _FakeProc:
    def __init__(self, pid, name):
        self.pid = pid
        self.info = {
            "pid": pid, "name": name, "cmdline": [name],
            "username": "u", "create_time": 1.0, "exe": f"C:\\\\{name}",
        }


@pytest.mark.asyncio
async def test_m1_pipeline_persists_and_reports(tmp_path: Path):
    db_path = tmp_path / "events.db"
    reports = tmp_path / "reports"

    bus = EventBus()
    store = EventStore(db_path)
    store.init_schema()
    writer = MarkdownReportWriter(reports, host="H")

    collected: list[Event] = []

    async def sink(ev: Event) -> None:
        store.insert(ev)
        collected.append(ev)

    bus.subscribe(sink)
    bus.start()

    procs_seq = iter([
        [_FakeProc(100, "explorer.exe")],
        [_FakeProc(100, "explorer.exe"), _FakeProc(200, "notepad.exe")],
        [_FakeProc(100, "explorer.exe")],  # 200 sale
    ])

    def fake_iter(attrs):
        try:
            return next(procs_seq)
        except StopIteration:
            return [_FakeProc(100, "explorer.exe")]

    collector = ProcCollector(host="H", poll_interval_seconds=0.05)
    with patch("cerberus.collectors.proc.psutil.process_iter", side_effect=fake_iter):
        task = asyncio.create_task(collector.start(bus))
        await asyncio.sleep(0.4)
        await collector.stop()
        try:
            await task
        except asyncio.CancelledError:
            pass

    await bus.stop()

    # Verificamos persistencia
    rows = store.fetch_all()
    types_db = {r["type"] for r in rows}
    assert "new_process" in types_db
    assert "process_exit" in types_db
    assert store.count() == len(collected)
    store.close()

    # Verificamos reporte
    report_path = writer.write(collected)
    text = report_path.read_text(encoding="utf-8")
    assert "## proc" in text
    assert "new_process" in text
```

- [ ] **Step 2: Correr integration test**

Run: `pytest tests/integration/test_pipeline_m1.py -v`
Expected: 1 passed.

- [ ] **Step 3: Correr suite completa**

Run: `pytest -v`
Expected: todos los tests pasan, coverage ≥ 85% (gate de `pyproject.toml`).

- [ ] **Step 4: Lint + tipos**

Run: `ruff check .`
Expected: sin errores.

Run: `mypy cerberus cerberus_local.py`
Expected: sin errores.

- [ ] **Step 5: Commit**

```bash
git add tests/integration/test_pipeline_m1.py
git commit -m "test(integration): add M1 vertical slice end-to-end test"
```

---

## Task 12: README final M1 + tag v0.1.0

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Actualizar README con instrucciones reales**

Reemplazar contenido por:

```markdown
# CERBERUS-LOCAL — M1 (Skeleton + ProcCollector)

EDR híbrido Windows con IA local Ollama. Fork defensivo de HADES-LOCAL.

**Hito actual:** M1 — vertical slice de telemetría sin detección ni respuesta.

## Componentes en M1

- `ProcCollector` (psutil) → emite eventos `new_process` y `process_exit`
- `EventBus` (asyncio) → fan-out a suscriptores
- `EventStore` (SQLite WAL) → persistencia
- `MarkdownReportWriter` → reportes Markdown cada N segundos
- CLI `cerberus_local.py` con `start`, `status`, `stop`, `version`

## Quickstart

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -e ".[dev]"

# Ver versión
python cerberus_local.py version

# Arrancar (foreground, Ctrl+C para detener)
python cerberus_local.py start

# Estado y conteo de eventos
python cerberus_local.py status
```

Los reportes se escriben en `C:\Users\Public\cerberus_reports\` (configurable en `config/cerberus.default.yml`).

## Tests

```bash
pytest                       # suite completa con coverage
pytest tests/unit            # solo unitarios
pytest tests/integration     # solo integración
ruff check .
mypy cerberus cerberus_local.py
```

## Próximos hitos

- **M2** — `NetCollector` (pyshark+Npcap), `FsCollector` (watchdog), `EvtCollector` (win32evtlog), Correlator
- **M3** — `RuleEngine`, `AIAnalyst` (Ollama), `PolicyEngine`, `ResponseEngine`, guardrails LLM
- **M4** — Windows Service, named pipe IPC, .msi instalador, anti-tampering, redteam tests

Ver `docs/superpowers/specs/2026-05-21-cerberus-local-edr-design.md` para diseño completo.
```

- [ ] **Step 2: Verificar build limpio**

Run: `pytest && ruff check . && mypy cerberus cerberus_local.py`
Expected: todo verde.

- [ ] **Step 3: Commit y tag**

```bash
git add README.md
git commit -m "docs: finalize M1 README"
git tag -a v0.1.0-m1 -m "M1: skeleton + ProcCollector vertical slice"
```

- [ ] **Step 4: Verificación final**

Run: `python cerberus_local.py version`
Expected: `cerberus-local 0.1.0`.

Run en una ventana: `python cerberus_local.py start`
Abre Notepad en otra ventana, espera 3 segundos, cierra Notepad, Ctrl+C el agente.

Verificar: archivo Markdown creado en `cerberus_reports/`, contiene una entrada `new_process` para `notepad.exe` y un `process_exit` para el mismo PID.

---

## Checklist final M1

- [ ] 12 tareas completadas (todas con tests verdes)
- [ ] Coverage ≥ 85%
- [ ] `ruff check .` limpio
- [ ] `mypy cerberus cerberus_local.py` limpio
- [ ] Smoke test manual con Notepad confirmado
- [ ] Tag `v0.1.0-m1` creado
- [ ] Antes de continuar a M2: validar diseño en uso real ≥ 1 hora idle + 30 min con carga (abrir/cerrar apps)

## Próximo plan

Una vez M1 validado, crear:
`docs/superpowers/plans/YYYY-MM-DD-cerberus-m2-collectors-correlator.md`
