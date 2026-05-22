# CERBERUS-LOCAL · Plan M4 — Respuesta: PolicyEngine + ResponseEngine + acciones + rollback

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Arrancar la **Cabeza 3 (Respuesta)**. Tras el enriquecimiento del `DetectionPipeline`, cada `Finding` pasa por una `PolicyEngine` **heurística** que decide qué acciones autorizar a partir de `(severity, categories)`, y un `ResponseEngine` que aplica una cadena de gates fail-closed (**killswitch → modo → require_confirmation → rate-limit**) y, solo si todos pasan, ejecuta la acción a través de un `_SystemExecutor` aislado. Cada acción (ejecutada o simulada) se persiste en `actions_log.db` con su comando y su reversión, habilitando `cerberus rollback <action_id>`.

**Architecture:** 100% heurístico — **0 LLM nuevo**. La **PolicyEngine es la única autoridad que decide acciones** (§10.5 G1): NO lee `ai_triage` ni `suggested_actions`; solo `severity` + `categories`. El `_SystemExecutor` es la única capa que toca el SO (psutil/subprocess) y **todos los tests la mockean** — ningún test mata procesos ni corre `netsh`. **`dry_run` es el default obligatorio en primer arranque**: computa el plan, registra comando+reversión en `actions_log.db`, pero NO ejecuta. La ejecución real solo ocurre en `auto_critical`/`auto_all`. Anti-inyección (A05): toda llamada al SO usa `subprocess.run(args_list, shell=False)` con inputs validados (IP vía `ipaddress`, pid `int`, service/username contra allowlist regex, paths normalizados).

**Tech Stack:** Python 3.11+, `asyncio`, `psutil`, `subprocess`/`shutil`/`ipaddress` stdlib, `pyyaml`, `pytest`, `pytest-asyncio`, SQLite stdlib, `ruff`, `mypy`. **Ninguna dependencia runtime nueva.** Acciones reales solo en Windows; en otros SO el executor degrada (build OK, run reporta `unsupported_platform`).

**Reference spec:** `2026-05-21-cerberus-local-edr-design.md` (§4.7 ResponseEngine, §4.8 PolicyEngine, §7.1 modos, §7.3 rollback, §7.4 killswitch, §7.5 rate limits, §10.5.3 G1/G3).

---

## Scope (decisiones aprobadas 2026-05-22)

1. **Ejecución real, aislada tras `_SystemExecutor`, gated por `dry_run`.** Las llamadas reales al SO existen pero (a) están encapsuladas en `_SystemExecutor` (mockeado en TODOS los tests), (b) solo se invocan cuando los gates autorizan (nunca en `dry_run`/`monitor`/killswitch). El comando que SE HABRÍA corrido + su reversión se registran igual en `actions_log.db` para auditoría.
2. **Las 6 acciones:** `kill_pid`, `quarantine`, `block_ip`, `stop_service`, `isolate_host`, `disable_user`. `isolate_host` y `disable_user` quedan en policies con `require_confirmation: true` (no auto por blast-radius).
3. **`PolicyEngine` decide SOLO con `severity` + `categories`** (G1). El LLM (`ai_triage.suggested_actions`) es complementario y **nunca** causa ejecución.

---

## Cadena de decisión (núcleo de seguridad)

```
Finding enriquecido (severity, severity_base, categories, rule_ids, ai_triage[complementario])
  → PolicyEngine.decide(finding) -> list[PolicyDecision]   # SOLO (severity, categories); NO ai_triage  (G1)
  → ResponseEngine.handle(finding):
       for decision in decisions:
         should, reason = _decide_execute(decision, finding):     # fail-closed, en orden:
            1. killswitch activo?      -> (False, "killswitch")
            2. mode dry_run/monitor?   -> (False, mode)
            3. auto_critical: sev==CRITICAL y categories ∩ auto_critical_categories? si no -> (False,"mode_gate")
               auto_all:      sev >= HIGH? si no -> (False,"mode_gate")
            4. decision.require_confirmation? -> (False, "require_confirmation")
            5. rate_limiter.allow(type)?  si no -> (False, "rate_limited")
            -> (True, "authorized")
         if should:  result = executor.run(action)            # EJECUTA (capa mockeada en tests)
         else:       built = executor.build(action); result = ActionResult(executed=False, command=built...)
         action_store.insert(result, finding_id, policy_id, mode)
       -> ActionReport
```

`_decide_execute` es testeable sin tocar el SO ⇒ G3 verificable por tests. `executor.build()` (puro: valida + arma el string del comando y su reversión, sin ejecutar) se usa para el registro en `dry_run`. `executor.run()` llama a `build()` y solo si es válido ejecuta.

---

## Guardrails relevantes en M4

| # | Guardrail | Realización |
|---|-----------|-------------|
| G1 | El LLM no decide acciones | `PolicyEngine.decide` solo usa `severity`+`categories`; no recibe `ai_triage`. Test: finding con `suggested_actions=['format_disk']` y policy `[kill_pid]` → jamás se ejecuta `format_disk` (Task 4, 8) |
| G3 | El LLM no bypassa dry_run/killswitch/rate_limits/confirmation | gates en `ResponseEngine._decide_execute`, fail-closed, independientes del `ai_triage` (Task 8) |
| G7 | Trazabilidad heurística | `actions_log.db` persiste `finding_id` + `policy_id` (causal) por acción (Task 3, 8) |
| A05 | Inyección de comandos | `subprocess.run(list, shell=False)` + validación de IP/pid/service/username/path en `_SystemExecutor` (Task 7) |

---

## File Structure (M4)

```
cerberus-local/
├── pyproject.toml                       # MODIFICAR: version 0.4.0
├── config/cerberus.default.yml          # MODIFICAR: mode dry_run; secciones response + paths nuevos
├── policies/                            # CREAR
│   ├── ransomware.yml
│   ├── c2.yml
│   ├── execution.yml
│   ├── credential_access.yml
│   └── isolation.yml
├── cerberus/
│   ├── __init__.py                      # MODIFICAR: 0.4.0
│   ├── core/config.py                   # MODIFICAR: Mode +auto_*; PathsConfig +actions_db/killswitch/quarantine; ResponseConfig
│   └── response/
│       ├── __init__.py                  # CREAR
│       ├── actions.py                   # CREAR: Action, ActionResult, ActionReport, PolicyDecision
│       ├── action_store.py              # CREAR: ActionStore (actions_log.db)
│       ├── policy_engine.py             # CREAR: PolicyEngine + Policy
│       ├── rate_limiter.py              # CREAR: RateLimiter
│       ├── executor.py                  # CREAR: _SystemExecutor (6 acciones, anti-inyección)
│       └── engine.py                    # CREAR: ResponseEngine (gates + orquestación)
│   ├── reporting/markdown.py            # MODIFICAR: sección "Acciones"
│   └── cli/commands.py                  # MODIFICAR: wire response; cmd_mode; cmd_rollback
└── tests/
    ├── unit/
    │   ├── test_config.py               # MODIFICAR: response + modos auto_*
    │   ├── test_cli_commands.py         # MODIFICAR: _make_cfg con response/paths nuevos
    │   ├── test_report_markdown.py      # MODIFICAR: sección acciones
    │   ├── test_actions.py              # CREAR
    │   ├── test_action_store.py         # CREAR
    │   ├── test_policy_engine.py        # CREAR
    │   ├── test_default_policies.py     # CREAR
    │   ├── test_rate_limiter.py         # CREAR
    │   ├── test_executor.py             # CREAR
    │   └── test_response_engine.py      # CREAR (gates G1/G3)
    └── integration/
        └── test_pipeline_m4.py          # CREAR: finding→policy→dry_run(no exec)/auto(exec mock)/killswitch
```

**Out of scope (M5):** Windows Service, named pipe IPC, `.msi`, anti-tampering, redteam, pyshark/`dns_query`, hardening del LOW de NetCollector, `--json` y UI.

---

## Pre-flight

- [ ] **Step 1:** `git checkout master && git status` → limpio, HEAD en merge commit de M3 (`501d698`), tag `v0.3.0-m3`.
- [ ] **Step 2:** `.venv/Scripts/python -m pytest -p no:cacheprovider -q --ignore=tests/integration/test_ollama_live.py 2>&1 | tail -3` → 103 passed.
- [ ] **Step 3:** `git checkout -b m4/policy-and-response && git branch --show-current` → `m4/policy-and-response`.

---

## Task 1: Bump 0.4.0 + config (modos auto_*, ResponseConfig, paths)

**Files:** `cerberus/__init__.py`, `pyproject.toml`, `config/cerberus.default.yml`, `cerberus/core/config.py`, `tests/unit/test_config.py`, `tests/unit/test_cli_commands.py`

- [ ] **Step 1:** `cerberus/__init__.py` → `__version__ = "0.4.0"`. `pyproject.toml` → `version = "0.4.0"`.

- [ ] **Step 2: Añadir tests fallidos a `tests/unit/test_config.py`** (al final):
```python
def test_load_response_config_and_auto_modes(tmp_path):
    cfg_file = tmp_path / "c.yml"
    cfg_file.write_text(
        """
mode: auto_critical
host_name: null
paths:
  data_dir: /tmp/c
  events_db: /tmp/c/e.db
  findings_db: /tmp/c/f.db
  actions_db: /tmp/c/a.db
  reports_dir: /tmp/c/r
  log_file: /tmp/c/l.log
  killswitch_path: /tmp/c/KILLSWITCH
  quarantine_dir: /tmp/c/quarantine
collectors: {proc: {enabled: true, poll_interval_seconds: 1.0}}
response:
  enabled: true
  policies_dir: policies
  auto_critical_categories: [ransomware, c2, data_exfil]
  rate: {max_actions_per_minute: 10, max_isolate_per_hour: 1}
reporting: {interval_seconds: 60, retention_days: 1}
""",
        encoding="utf-8",
    )
    from cerberus.core.config import load_config
    cfg = load_config(cfg_file)
    assert cfg.mode == "auto_critical"
    assert str(cfg.paths.actions_db) == "/tmp/c/a.db"
    assert "KILLSWITCH" in str(cfg.paths.killswitch_path)
    assert cfg.response.enabled is True
    assert "ransomware" in cfg.response.auto_critical_categories
    assert cfg.response.rate.max_actions_per_minute == 10
    assert cfg.response.rate.max_isolate_per_hour == 1


def test_response_defaults_when_absent(tmp_path):
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
    assert cfg.response.enabled is True
    assert cfg.response.rate.max_actions_per_minute == 10
    # paths nuevos tienen defaults derivados de data_dir cuando faltan
    assert str(cfg.paths.actions_db).endswith("actions_log.db")
    assert str(cfg.paths.killswitch_path).endswith("KILLSWITCH")


def test_invalid_mode_still_rejected(tmp_path):
    import pytest
    cfg_file = tmp_path / "c.yml"
    cfg_file.write_text("mode: nuke\npaths: {}\ncollectors: {}\nreporting: {}\n")
    from cerberus.core.config import load_config
    with pytest.raises(ValueError):
        load_config(cfg_file)
```

- [ ] **Step 3:** Editar `cerberus/core/config.py`:

(a) Mode + modos válidos:
```python
Mode = Literal["dry_run", "monitor", "auto_critical", "auto_all"]
_VALID_MODES = {"dry_run", "monitor", "auto_critical", "auto_all"}
```

(b) `PathsConfig` — añadir 3 campos:
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
```

(c) Nuevas dataclasses (tras `DetectionConfig`):
```python
@dataclass(frozen=True)
class RateConfig:
    max_actions_per_minute: int
    max_isolate_per_hour: int


@dataclass(frozen=True)
class ResponseConfig:
    enabled: bool
    policies_dir: Path
    auto_critical_categories: frozenset[str]
    rate: RateConfig
```

(d) `CerberusConfig` — añadir `response: ResponseConfig` (tras `detection`).

(e) helper `_response` (tras `_detection`):
```python
_DEFAULT_AUTO_CRITICAL_CATEGORIES = ["ransomware", "c2", "data_exfil"]


def _response(raw: dict[str, Any]) -> ResponseConfig:
    rate_raw = raw.get("rate", {})
    cats = raw.get("auto_critical_categories") or list(_DEFAULT_AUTO_CRITICAL_CATEGORIES)
    return ResponseConfig(
        enabled=bool(raw.get("enabled", True)),
        policies_dir=Path(raw.get("policies_dir", "policies")),
        auto_critical_categories=frozenset(str(c) for c in cats),
        rate=RateConfig(
            max_actions_per_minute=int(rate_raw.get("max_actions_per_minute", 10)),
            max_isolate_per_hour=int(rate_raw.get("max_isolate_per_hour", 1)),
        ),
    )
```

(f) En `load_config`, reescribir el bloque `paths` para incluir los nuevos campos con defaults derivados de `data_dir`:
```python
    paths_raw = raw.get("paths", {})
    data_dir = Path(paths_raw.get("data_dir", ""))
    paths = PathsConfig(
        data_dir=data_dir,
        events_db=Path(paths_raw.get("events_db", "")),
        findings_db=Path(paths_raw.get("findings_db", "")),
        actions_db=Path(paths_raw.get("actions_db") or (data_dir / "db" / "actions_log.db")),
        reports_dir=Path(paths_raw.get("reports_dir", "")),
        log_file=Path(paths_raw.get("log_file", "")),
        killswitch_path=Path(paths_raw.get("killswitch_path") or (data_dir / "KILLSWITCH")),
        quarantine_dir=Path(paths_raw.get("quarantine_dir") or (data_dir / "Quarantine")),
    )
```
y construir `response = _response(raw.get("response", {}))` y pasar `response=response` al `CerberusConfig(...)`.

- [ ] **Step 4:** `config/cerberus.default.yml` — añadir `actions_db`, `killswitch_path`, `quarantine_dir` bajo `paths:` y la sección `response:` antes de `reporting:`:
```yaml
paths:
  data_dir: "C:\\ProgramData\\Cerberus"
  events_db: "C:\\ProgramData\\Cerberus\\db\\events.db"
  findings_db: "C:\\ProgramData\\Cerberus\\db\\findings.db"
  actions_db: "C:\\ProgramData\\Cerberus\\db\\actions_log.db"
  reports_dir: "C:\\Users\\Public\\cerberus_reports"
  log_file: "C:\\ProgramData\\Cerberus\\logs\\cerberus.log"
  killswitch_path: "C:\\ProgramData\\Cerberus\\KILLSWITCH"
  quarantine_dir: "C:\\ProgramData\\Cerberus\\Quarantine"
```
```yaml
response:
  enabled: true
  policies_dir: "policies"
  auto_critical_categories: [ransomware, c2, data_exfil]
  rate:
    max_actions_per_minute: 10
    max_isolate_per_hour: 1
```
(Mantener `mode: dry_run` como default obligatorio.)

- [ ] **Step 5:** Editar `tests/unit/test_cli_commands.py::_make_cfg` — importar `ResponseConfig`, `RateConfig` y añadir `actions_db`/`killswitch_path`/`quarantine_dir` a `PathsConfig` y `response=` al `CerberusConfig` (response **enabled=False** para que los unit tests del CLI no disparen acciones):
```python
from cerberus.core.config import (
    AIAnalystConfig, CerberusConfig, CollectorsConfig, CorrelatorConfig,
    DetectionConfig, EvtCollectorConfig, FsCollectorConfig, NetCollectorConfig,
    PathsConfig, ProcCollectorConfig, RateConfig, ReportingConfig,
    ResponseConfig, RuleEngineConfig,
)
```
En `PathsConfig(...)` de `_make_cfg` añadir:
```python
            actions_db=tmp_path / "actions.db",
            killswitch_path=tmp_path / "KILLSWITCH",
            quarantine_dir=tmp_path / "quarantine",
```
y tras `detection=...`:
```python
        response=ResponseConfig(
            enabled=False, policies_dir=Path("policies"),
            auto_critical_categories=frozenset({"ransomware", "c2", "data_exfil"}),
            rate=RateConfig(max_actions_per_minute=10, max_isolate_per_hour=1),
        ),
```

- [ ] **Step 6:** `.venv/Scripts/python -m pytest tests/unit/test_config.py tests/unit/test_cli_commands.py -p no:cacheprovider --no-cov -q` → verde. `.venv/Scripts/python -c "import cerberus; print(cerberus.__version__)"` → `0.4.0`. Full suite `--no-cov` verde.

- [ ] **Step 7:** Commit:
```bash
git add pyproject.toml cerberus/__init__.py config/cerberus.default.yml cerberus/core/config.py tests/unit/test_config.py tests/unit/test_cli_commands.py
git commit -m "chore(m4): bump to 0.4.0; add response config, auto_* modes, response paths"
```
Trailer: `Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>`

---

## Task 2: Dataclasses `Action` / `ActionResult` / `ActionReport` / `PolicyDecision`

**Files:** `cerberus/response/__init__.py` (vacío), `cerberus/response/actions.py`, `tests/unit/test_actions.py`

- [ ] **Step 1:** Crear `cerberus/response/__init__.py` vacío (0 bytes).

- [ ] **Step 2: Tests** — `tests/unit/test_actions.py`:
```python
import json

from cerberus.response.actions import Action, ActionReport, ActionResult, PolicyDecision

_VALID = {"kill_pid", "quarantine", "block_ip", "stop_service", "isolate_host", "disable_user"}


def test_action_types_constant():
    assert Action.VALID_TYPES == _VALID


def test_action_rejects_unknown_type():
    import pytest
    with pytest.raises(ValueError):
        Action(type="format_disk", params={})


def test_action_result_to_dict_serializable():
    a = Action(type="kill_pid", params={"pid": 1234})
    r = ActionResult(action=a, executed=False, success=False, output="",
                     command="taskkill /F /T /PID 1234", reverted_command=None,
                     reason="dry_run")
    d = r.to_dict()
    assert d["action_type"] == "kill_pid"
    assert d["params"] == {"pid": 1234}
    assert d["executed"] is False
    assert d["reason"] == "dry_run"
    json.dumps(d)


def test_policy_decision_carries_metadata():
    a = Action(type="block_ip", params={"ip": "9.9.9.9"})
    d = PolicyDecision(action=a, policy_id="c2_response", require_confirmation=False)
    assert d.policy_id == "c2_response"
    assert d.require_confirmation is False


def test_action_report_aggregates():
    a = Action(type="kill_pid", params={"pid": 1})
    r = ActionResult(action=a, executed=True, success=True, output="ok",
                     command="x", reverted_command=None, reason="authorized")
    rep = ActionReport(finding_id="F1", mode="auto_all", results=[r])
    assert rep.finding_id == "F1"
    assert rep.executed_count == 1
```

- [ ] **Step 3:** Implementar `cerberus/response/actions.py`:
```python
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, ClassVar


@dataclass(frozen=True)
class Action:
    VALID_TYPES: ClassVar[set[str]] = {
        "kill_pid", "quarantine", "block_ip",
        "stop_service", "isolate_host", "disable_user",
    }
    type: str
    params: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.type not in self.VALID_TYPES:
            raise ValueError(
                f"Invalid action type {self.type!r}; must be one of {sorted(self.VALID_TYPES)}"
            )


@dataclass(frozen=True)
class PolicyDecision:
    action: Action
    policy_id: str
    require_confirmation: bool


@dataclass(frozen=True)
class ActionResult:
    action: Action
    executed: bool
    success: bool
    output: str
    command: str
    reverted_command: str | None
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_type": self.action.type,
            "params": self.action.params,
            "executed": self.executed,
            "success": self.success,
            "output": self.output,
            "command": self.command,
            "reverted_command": self.reverted_command,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class ActionReport:
    finding_id: str
    mode: str
    results: list[ActionResult]

    @property
    def executed_count(self) -> int:
        return sum(1 for r in self.results if r.executed)
```

- [ ] **Step 4:** `pytest tests/unit/test_actions.py -v` → 5 passed.

- [ ] **Step 5:** Commit:
```bash
git add cerberus/response/__init__.py cerberus/response/actions.py tests/unit/test_actions.py
git commit -m "feat(response): add Action/ActionResult/ActionReport/PolicyDecision dataclasses"
```
Trailer: `Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>`

---

## Task 3: `ActionStore` (actions_log.db)

**Files:** `cerberus/response/action_store.py`, `tests/unit/test_action_store.py`

- [ ] **Step 1: Tests** — `tests/unit/test_action_store.py`:
```python
from pathlib import Path

import pytest

from cerberus.response.action_store import ActionStore
from cerberus.response.actions import Action, ActionResult


@pytest.fixture
def store(tmp_path: Path) -> ActionStore:
    s = ActionStore(tmp_path / "actions_log.db")
    s.init_schema()
    return s


def _result(executed=True, reverted="netsh ... delete"):
    a = Action(type="block_ip", params={"ip": "9.9.9.9"})
    return ActionResult(action=a, executed=executed, success=executed, output="ok",
                        command="netsh ... add", reverted_command=reverted,
                        reason="authorized")


def test_init_creates_table(store):
    assert store.table_exists("actions_log")


def test_insert_and_fetch_by_id(store):
    r = _result()
    aid = store.insert(r, finding_id="F1", policy_id="c2_response", mode="auto_all")
    row = store.fetch_by_id(aid)
    assert row is not None
    assert row["finding_id"] == "F1"
    assert row["policy_id"] == "c2_response"
    assert row["action_type"] == "block_ip"
    assert row["params"] == {"ip": "9.9.9.9"}
    assert row["executed"] == 1
    assert row["reverted_command"] == "netsh ... delete"


def test_fetch_recent_orders_desc(store):
    store.insert(_result(), finding_id="F1", policy_id="p", mode="auto_all")
    store.insert(_result(), finding_id="F2", policy_id="p", mode="auto_all")
    recent = store.fetch_recent(limit=10)
    assert len(recent) == 2


def test_fetch_by_id_missing_returns_none(store):
    assert store.fetch_by_id("nope") is None
```

- [ ] **Step 2:** `pytest tests/unit/test_action_store.py -v` → FAIL.

- [ ] **Step 3:** Implementar `cerberus/response/action_store.py`:
```python
from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cerberus.response.actions import ActionResult

_SCHEMA = """
CREATE TABLE IF NOT EXISTS actions_log (
    id                TEXT PRIMARY KEY,
    timestamp         TEXT NOT NULL,
    finding_id        TEXT NOT NULL,
    policy_id         TEXT NOT NULL,
    action_type       TEXT NOT NULL,
    params            TEXT NOT NULL,
    executed          INTEGER NOT NULL,
    success           INTEGER NOT NULL,
    command           TEXT NOT NULL,
    reverted_command  TEXT,
    reason            TEXT NOT NULL,
    mode              TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_actions_timestamp ON actions_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_actions_finding ON actions_log(finding_id);
"""


class ActionStore:
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
            "SELECT name FROM sqlite_master WHERE type='table' AND name=?", (name,),
        ).fetchone()
        return row is not None

    def insert(self, result: ActionResult, finding_id: str, policy_id: str, mode: str) -> str:
        d = result.to_dict()
        action_id = str(uuid.uuid4())
        self._conn.execute(
            """
            INSERT INTO actions_log(
                id, timestamp, finding_id, policy_id, action_type, params,
                executed, success, command, reverted_command, reason, mode
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                action_id,
                datetime.now(UTC).isoformat(),
                finding_id,
                policy_id,
                d["action_type"],
                json.dumps(d["params"]),
                1 if d["executed"] else 0,
                1 if d["success"] else 0,
                d["command"],
                d["reverted_command"],
                d["reason"],
                mode,
            ),
        )
        return action_id

    def _row_to_dict(self, row: Any) -> dict[str, Any]:
        d = dict(row)
        d["params"] = json.loads(d["params"])
        return d

    def fetch_by_id(self, action_id: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT * FROM actions_log WHERE id=?", (action_id,),
        ).fetchone()
        return self._row_to_dict(row) if row is not None else None

    def fetch_recent(self, limit: int = 50) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT * FROM actions_log ORDER BY timestamp DESC LIMIT ?", (limit,),
        ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def close(self) -> None:
        self._conn.close()
```

- [ ] **Step 4:** `pytest tests/unit/test_action_store.py -v` → 4 passed.

- [ ] **Step 5:** Commit:
```bash
git add cerberus/response/action_store.py tests/unit/test_action_store.py
git commit -m "feat(response): add ActionStore (actions_log.db) audit trail"
```
Trailer: `Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>`

---

## Task 4: `PolicyEngine` + `Policy` (decide solo por severity+categories — G1)

**Files:** `cerberus/response/policy_engine.py`, `tests/unit/test_policy_engine.py`

**Formato policy** (`policies/*.yml`):
```yaml
id: <str>
match:
  severity_min: INFO|LOW|MEDIUM|HIGH|CRITICAL
  categories: [<cat>, ...]          # vacío/ausente = cualquier categoría
require_confirmation: <bool>
actions:
  - kill_pid
  - block_ip
```
Una policy casa si `finding.severity >= severity_min` Y (`categories` vacío O intersección con `finding.categories`). `decide()` devuelve la unión de `PolicyDecision` de las policies que casan, resolviendo params desde la evidencia; **una acción cuyos params no se resuelven se descarta** (log). **`decide()` NO accede a `finding.ai_triage`.**

- [ ] **Step 1: Tests** — `tests/unit/test_policy_engine.py`:
```python
from pathlib import Path

from cerberus.core.event import Event, Severity
from cerberus.core.finding import Finding
from cerberus.response.policy_engine import PolicyEngine


def _ev(source, type_, **ind):
    return Event(source=source, type=type_, host="H", pid=4892, user="DESK\\u",
                 raw={}, indicators=ind)


def _finding(severity, categories_events, ai_suggested=None):
    f = Finding.from_cluster(host="H", pid=4892, user="DESK\\u", evidence=categories_events)
    import dataclasses
    return dataclasses.replace(
        f, severity=severity, severity_base=severity,
        ai_triage={"suggested_actions": ai_suggested or [], "severity": int(severity)},
    )


def _write(d: Path, name: str, text: str) -> None:
    (d / name).write_text(text, encoding="utf-8")


def test_load_counts(tmp_path):
    _write(tmp_path, "p.yml", """
id: p1
match: {severity_min: HIGH, categories: [execution]}
require_confirmation: true
actions: [kill_pid]
""")
    eng = PolicyEngine(tmp_path)
    assert eng.load() == 1


def test_decide_matches_severity_and_category(tmp_path):
    _write(tmp_path, "ransom.yml", """
id: ransomware_response
match: {severity_min: CRITICAL, categories: [ransomware]}
require_confirmation: false
actions: [kill_pid, block_ip]
""")
    eng = PolicyEngine(tmp_path)
    eng.load()
    evs = [_ev("proc", "new_process"), _ev("net", "outbound_conn", remote_ip="9.9.9.9")]
    f = _finding(Severity.CRITICAL, evs)
    # marcamos la categoría 'ransomware' via un evento mass_rename
    import dataclasses
    f = dataclasses.replace(f, evidence=(*evs, _ev("fs", "mass_rename")))
    # categories incluye new_process/outbound_conn/mass_rename; añadimos match por categoria propia
    decisions = eng.decide(f)
    # la policy casa por severity CRITICAL; categories de la policy = [ransomware]
    # -> requiere que finding.categories contenga 'ransomware'. Ver nota: categories del finding
    #    son los TYPES de evento. Para casar 'ransomware' la policy debe usar categorias de regla.
    # Este test fija el contrato: si categories de policy no están en finding.categories -> no casa.
    assert decisions == []


def test_decide_category_from_rule_categories(tmp_path):
    # finding.categories incluye los rule categories vía rule matching en pipeline;
    # aqui simulamos inyectando un evento cuyo type coincide con la categoria de policy
    _write(tmp_path, "c2.yml", """
id: c2_response
match: {severity_min: MEDIUM, categories: [beaconing_suspect]}
require_confirmation: false
actions: [block_ip]
""")
    eng = PolicyEngine(tmp_path)
    eng.load()
    evs = [_ev("net", "beaconing_suspect", remote_ip="9.9.9.9"),
           _ev("proc", "new_process")]
    f = _finding(Severity.HIGH, evs)
    decisions = eng.decide(f)
    assert len(decisions) == 1
    assert decisions[0].policy_id == "c2_response"
    assert decisions[0].action.type == "block_ip"
    assert decisions[0].action.params == {"ip": "9.9.9.9"}


def test_decide_skips_action_with_unresolvable_params(tmp_path):
    # block_ip sin ningún remote_ip en la evidencia -> se descarta
    _write(tmp_path, "c2.yml", """
id: c2_response
match: {severity_min: MEDIUM, categories: []}
require_confirmation: false
actions: [block_ip]
""")
    eng = PolicyEngine(tmp_path)
    eng.load()
    f = _finding(Severity.HIGH, [_ev("proc", "new_process")])
    assert eng.decide(f) == []


def test_decide_ignores_ai_suggested_actions(tmp_path):
    # G1: aunque la IA sugiera 'isolate_host'/'format_disk', solo la policy decide
    _write(tmp_path, "exec.yml", """
id: execution_response
match: {severity_min: HIGH, categories: []}
require_confirmation: true
actions: [kill_pid]
""")
    eng = PolicyEngine(tmp_path)
    eng.load()
    f = _finding(Severity.HIGH, [_ev("proc", "new_process")],
                 ai_suggested=["isolate_host", "format_disk", "disable_user"])
    decisions = eng.decide(f)
    types = {d.action.type for d in decisions}
    assert types == {"kill_pid"}   # nada de lo que sugirió la IA
    assert decisions[0].require_confirmation is True


def test_malformed_policy_skipped(tmp_path):
    _write(tmp_path, "bad.yml", "id: bad\nmatch: {severity_min: NOPE}\nactions: []\n")
    _write(tmp_path, "good.yml", """
id: good
match: {severity_min: LOW, categories: []}
require_confirmation: false
actions: [kill_pid]
""")
    eng = PolicyEngine(tmp_path)
    assert eng.load() == 1
```

> **Nota de contrato (importante para el implementador):** `finding.categories` es el conjunto de **tipos de evento** de la evidencia (definido en M2: `{ev.type for ev in evidence}`). Las `categories` de una policy se casan contra ese conjunto. Las reglas de M3 tienen su propia `category` (ransomware/c2/...) pero esa categoría vive en `RuleMatch`, no en `finding.categories`. Por tanto **las policies de M4 deben matchear contra tipos de evento** (p.ej. `beaconing_suspect`, `mass_rename`, `logon_failure`) **o dejar `categories: []`** y apoyarse en `severity_min`. Las policies por defecto (Task 5) usan esta convención. (Unificar rule-category ↔ finding-category es mejora futura, fuera de M4.)

- [ ] **Step 2:** `pytest tests/unit/test_policy_engine.py -v` → FAIL.

- [ ] **Step 3:** Implementar `cerberus/response/policy_engine.py`:
```python
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from cerberus.core.event import Severity
from cerberus.core.finding import Finding
from cerberus.core.logger import get_logger
from cerberus.response.actions import Action, PolicyDecision

_log = get_logger("cerberus.response.policy_engine")


@dataclass(frozen=True)
class _Policy:
    id: str
    severity_min: Severity
    categories: frozenset[str]
    require_confirmation: bool
    action_types: tuple[str, ...]


def _parse_policy(raw: dict[str, Any]) -> _Policy:
    pid = str(raw["id"])
    match = raw.get("match", {})
    severity_min = Severity[str(match["severity_min"]).upper()]
    categories = frozenset(str(c) for c in (match.get("categories") or []))
    actions = tuple(str(a) for a in raw["actions"])
    for a in actions:
        if a not in Action.VALID_TYPES:
            raise ValueError(f"invalid action type in policy: {a!r}")
    return _Policy(
        id=pid, severity_min=severity_min, categories=categories,
        require_confirmation=bool(raw.get("require_confirmation", False)),
        action_types=actions,
    )


def _first_indicator(finding: Finding, key: str) -> Any | None:
    for ev in finding.evidence:
        val = ev.indicators.get(key)
        if val:
            return val
    return None


class PolicyEngine:
    """Decide acciones SOLO desde (severity, categories del finding). No lee ai_triage (G1)."""

    def __init__(self, policies_dir: Path | str) -> None:
        self._dir = Path(policies_dir)
        self._policies: list[_Policy] = []

    def load(self) -> int:
        policies: list[_Policy] = []
        if self._dir.exists():
            for path in sorted(self._dir.glob("*.yml")):
                try:
                    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
                    policies.append(_parse_policy(raw))
                except (KeyError, ValueError, TypeError, yaml.YAMLError) as exc:
                    _log.error("policy_invalid", extra={"path": str(path), "error": str(exc)})
        self._policies = policies
        return len(policies)

    def reload(self) -> int:
        return self.load()

    def _resolve_params(self, action_type: str, finding: Finding) -> dict[str, Any] | None:
        if action_type == "kill_pid":
            return {"pid": finding.pid} if finding.pid is not None else None
        if action_type == "block_ip":
            ip = _first_indicator(finding, "remote_ip")
            return {"ip": ip} if ip else None
        if action_type == "quarantine":
            path = _first_indicator(finding, "exe") or _first_indicator(finding, "path")
            return {"path": path} if path else None
        if action_type == "stop_service":
            name = _first_indicator(finding, "service_name")
            return {"name": name} if name else None
        if action_type == "disable_user":
            return {"username": finding.user} if finding.user else None
        if action_type == "isolate_host":
            return {}
        return None

    def decide(self, finding: Finding) -> list[PolicyDecision]:
        decisions: list[PolicyDecision] = []
        for policy in self._policies:
            if finding.severity < policy.severity_min:
                continue
            if policy.categories and not (policy.categories & finding.categories):
                continue
            for action_type in policy.action_types:
                params = self._resolve_params(action_type, finding)
                if params is None:
                    _log.info("action_skipped_unresolvable",
                              extra={"policy": policy.id, "action": action_type})
                    continue
                decisions.append(PolicyDecision(
                    action=Action(type=action_type, params=params),
                    policy_id=policy.id,
                    require_confirmation=policy.require_confirmation,
                ))
        return decisions
```

- [ ] **Step 4:** `pytest tests/unit/test_policy_engine.py -v` → 6 passed.

- [ ] **Step 5:** Commit:
```bash
git add cerberus/response/policy_engine.py tests/unit/test_policy_engine.py
git commit -m "feat(response): add PolicyEngine deciding actions from severity+categories only (G1)"
```
Trailer: `Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>`

---

## Task 5: Policies por defecto (`policies/*.yml`)

**Files:** `policies/ransomware.yml`, `policies/c2.yml`, `policies/execution.yml`, `policies/credential_access.yml`, `policies/isolation.yml`, `tests/unit/test_default_policies.py`

> Casan contra **tipos de evento** (categorías del finding) per la nota de Task 4.

- [ ] **Step 1:** `policies/ransomware.yml`:
```yaml
id: ransomware_response
match:
  severity_min: CRITICAL
  categories: [mass_rename]
require_confirmation: false
actions: [kill_pid, quarantine, block_ip]
```
`policies/c2.yml`:
```yaml
id: c2_response
match:
  severity_min: HIGH
  categories: [beaconing_suspect]
require_confirmation: false
actions: [block_ip]
```
`policies/execution.yml`:
```yaml
id: execution_response
match:
  severity_min: HIGH
  categories: [new_process]
require_confirmation: true
actions: [kill_pid]
```
`policies/credential_access.yml`:
```yaml
id: credential_access_response
match:
  severity_min: HIGH
  categories: [logon_failure]
require_confirmation: true
actions: [disable_user]
```
`policies/isolation.yml`:
```yaml
id: isolation_response
match:
  severity_min: CRITICAL
  categories: []
require_confirmation: true
actions: [isolate_host]
```

- [ ] **Step 2:** `tests/unit/test_default_policies.py`:
```python
from pathlib import Path

import yaml

from cerberus.response.policy_engine import PolicyEngine

_DIR = Path(__file__).resolve().parents[2] / "policies"


def test_default_policies_all_load():
    eng = PolicyEngine(_DIR)
    assert eng.load() == 5


def test_default_policy_ids_unique():
    ids = [yaml.safe_load(p.read_text(encoding="utf-8"))["id"]
           for p in sorted(_DIR.glob("*.yml"))]
    assert len(ids) == len(set(ids))


def test_high_blast_actions_require_confirmation():
    # isolate_host y disable_user nunca deben ser auto (require_confirmation=true)
    for p in sorted(_DIR.glob("*.yml")):
        raw = yaml.safe_load(p.read_text(encoding="utf-8"))
        acts = set(raw.get("actions", []))
        if acts & {"isolate_host", "disable_user"}:
            assert raw.get("require_confirmation") is True, p.name
```

- [ ] **Step 3:** `pytest tests/unit/test_default_policies.py -v` → 3 passed.

- [ ] **Step 4:** Commit:
```bash
git add policies tests/unit/test_default_policies.py
git commit -m "feat(response): add default response policies (high-blast actions gated by confirmation)"
```
Trailer: `Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>`

---

## Task 6: `RateLimiter`

**Files:** `cerberus/response/rate_limiter.py`, `tests/unit/test_rate_limiter.py`

- [ ] **Step 1: Tests** — `tests/unit/test_rate_limiter.py`:
```python
from cerberus.response.rate_limiter import RateLimiter


def test_allows_under_global_limit():
    rl = RateLimiter(max_actions_per_minute=3, max_isolate_per_hour=1)
    assert rl.allow("kill_pid") is True
    assert rl.allow("kill_pid") is True
    assert rl.allow("kill_pid") is True
    assert rl.allow("kill_pid") is False   # 4ta excede 3/min


def test_isolate_host_hourly_limit():
    rl = RateLimiter(max_actions_per_minute=10, max_isolate_per_hour=1)
    assert rl.allow("isolate_host") is True
    assert rl.allow("isolate_host") is False   # 2da isolate en la hora


def test_global_window_eviction(monkeypatch):
    import cerberus.response.rate_limiter as mod
    t = {"now": 1000.0}
    monkeypatch.setattr(mod.time, "monotonic", lambda: t["now"])
    rl = RateLimiter(max_actions_per_minute=2, max_isolate_per_hour=5)
    assert rl.allow("kill_pid") is True
    assert rl.allow("kill_pid") is True
    assert rl.allow("kill_pid") is False
    t["now"] += 61      # avanza > 60s -> ventana se vacía
    assert rl.allow("kill_pid") is True
```

- [ ] **Step 2:** `pytest tests/unit/test_rate_limiter.py -v` → FAIL.

- [ ] **Step 3:** Implementar `cerberus/response/rate_limiter.py`:
```python
from __future__ import annotations

import time
from collections import deque


class RateLimiter:
    """Límite heurístico: N acciones/min global + M isolate_host/hora. Eviction por ventana."""

    def __init__(self, max_actions_per_minute: int, max_isolate_per_hour: int) -> None:
        self._max_min = max_actions_per_minute
        self._max_isolate = max_isolate_per_hour
        self._global: deque[float] = deque()
        self._isolate: deque[float] = deque()

    @staticmethod
    def _evict(dq: deque[float], now: float, window: float) -> None:
        cutoff = now - window
        while dq and dq[0] < cutoff:
            dq.popleft()

    def allow(self, action_type: str) -> bool:
        now = time.monotonic()
        self._evict(self._global, now, 60.0)
        if len(self._global) >= self._max_min:
            return False
        if action_type == "isolate_host":
            self._evict(self._isolate, now, 3600.0)
            if len(self._isolate) >= self._max_isolate:
                return False
            self._isolate.append(now)
        self._global.append(now)
        return True
```

- [ ] **Step 4:** `pytest tests/unit/test_rate_limiter.py -v` → 3 passed.

- [ ] **Step 5:** Commit:
```bash
git add cerberus/response/rate_limiter.py tests/unit/test_rate_limiter.py
git commit -m "feat(response): add RateLimiter (per-minute global + hourly isolate cap)"
```
Trailer: `Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>`

---

## Task 7: `_SystemExecutor` (6 acciones, anti-inyección, build/run/revert)

> **Antes de codear:** invocar `using-context7` para confirmar firmas actuales de `psutil.Process.terminate`/`pid_exists` y patrones seguros de `subprocess.run` (args list, `shell=False`, `capture_output`).

**Files:** `cerberus/response/executor.py`, `tests/unit/test_executor.py`

**Contrato:**
- `build(action) -> _Built(command: str, reverted_command: str | None, valid: bool, reason: str)` — **puro**, valida params y arma strings; NO ejecuta.
- `run(action) -> ActionResult` — `build()`; si inválido → result `executed=False, success=False, reason`; si válido → ejecuta (psutil/subprocess) y devuelve result `executed=True`.
- `revert(action) -> ActionResult` — ejecuta la reversión (para rollback). `kill_pid` no es revertible → `success=False, reason="not_revertible"`.

Validación (A05): `ip` vía `ipaddress.ip_address` (rechaza inválida); `pid` int ≥ 0; `service`/`username` contra `^[A-Za-z0-9_.\\\- ]+$`; `path` normalizado + existe + es archivo. Toda ejecución: `subprocess.run([...], shell=False, capture_output=True, text=True, timeout=...)`.

- [ ] **Step 1: Tests** — `tests/unit/test_executor.py`:
```python
from unittest.mock import MagicMock, patch

from cerberus.response.actions import Action
from cerberus.response.executor import SystemExecutor


def _ex(tmp_path):
    return SystemExecutor(quarantine_dir=tmp_path / "q")


def test_build_block_ip_valid(tmp_path):
    b = _ex(tmp_path).build(Action(type="block_ip", params={"ip": "9.9.9.9"}))
    assert b.valid is True
    assert "9.9.9.9" in b.command
    assert b.reverted_command and "delete" in b.reverted_command


def test_build_block_ip_rejects_bad_ip(tmp_path):
    b = _ex(tmp_path).build(Action(type="block_ip", params={"ip": "9.9.9.9; rm -rf /"}))
    assert b.valid is False
    assert b.reason == "invalid_ip"


def test_build_stop_service_rejects_bad_name(tmp_path):
    b = _ex(tmp_path).build(Action(type="stop_service", params={"name": "svc & evil"}))
    assert b.valid is False


def test_build_disable_user_rejects_bad_name(tmp_path):
    b = _ex(tmp_path).build(Action(type="disable_user", params={"username": "a|b"}))
    assert b.valid is False


def test_run_block_ip_uses_subprocess_args_list(tmp_path):
    ex = _ex(tmp_path)
    with patch("cerberus.response.executor.subprocess.run") as mrun:
        mrun.return_value = MagicMock(returncode=0, stdout="ok", stderr="")
        res = ex.run(Action(type="block_ip", params={"ip": "9.9.9.9"}))
    assert res.executed is True
    assert res.success is True
    args, kwargs = mrun.call_args
    assert isinstance(args[0], list)        # args list, NO shell string
    assert kwargs.get("shell", False) is False


def test_run_invalid_does_not_call_subprocess(tmp_path):
    ex = _ex(tmp_path)
    with patch("cerberus.response.executor.subprocess.run") as mrun:
        res = ex.run(Action(type="block_ip", params={"ip": "bad ip"}))
    assert res.executed is False
    assert res.success is False
    mrun.assert_not_called()


def test_run_kill_pid_uses_psutil(tmp_path):
    ex = _ex(tmp_path)
    with patch("cerberus.response.executor.psutil.Process") as mproc:
        inst = mproc.return_value
        inst.terminate.return_value = None
        res = ex.run(Action(type="kill_pid", params={"pid": 4892}))
    assert res.executed is True
    inst.terminate.assert_called_once()


def test_revert_kill_pid_not_revertible(tmp_path):
    res = _ex(tmp_path).revert(Action(type="kill_pid", params={"pid": 1}))
    assert res.success is False
    assert res.reason == "not_revertible"


def test_revert_block_ip_runs_delete(tmp_path):
    ex = _ex(tmp_path)
    with patch("cerberus.response.executor.subprocess.run") as mrun:
        mrun.return_value = MagicMock(returncode=0, stdout="ok", stderr="")
        res = ex.revert(Action(type="block_ip", params={"ip": "9.9.9.9"}))
    assert res.executed is True
    assert "delete" in res.command
```

- [ ] **Step 2:** `pytest tests/unit/test_executor.py -v` → FAIL.

- [ ] **Step 3:** Implementar `cerberus/response/executor.py`:
```python
from __future__ import annotations

import ipaddress
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

import psutil

from cerberus.core.logger import get_logger
from cerberus.response.actions import Action, ActionResult

_log = get_logger("cerberus.response.executor")

_NAME_RE = re.compile(r"^[A-Za-z0-9_.\\\- ]+$")
_CMD_TIMEOUT = 15


@dataclass(frozen=True)
class _Built:
    command: str
    reverted_command: str | None
    valid: bool
    reason: str
    argv: list[str] | None = None
    revert_argv: list[str] | None = None


def _valid_ip(ip: object) -> str | None:
    try:
        return str(ipaddress.ip_address(str(ip)))
    except ValueError:
        return None


def _valid_name(name: object) -> str | None:
    s = str(name)
    return s if _NAME_RE.match(s) else None


class SystemExecutor:
    """Única capa que toca el SO. Mockeada en todos los tests.

    build() es puro (valida + arma comando). run()/revert() ejecutan.
    Anti-inyección: subprocess.run(list, shell=False) con inputs validados.
    """

    def __init__(self, quarantine_dir: Path | str) -> None:
        self._quarantine_dir = Path(quarantine_dir)

    # ---- build (puro) ----
    def build(self, action: Action) -> _Built:
        t = action.type
        p = action.params
        if t == "kill_pid":
            pid = p.get("pid")
            if not isinstance(pid, int) or pid < 0:
                return _Built("", None, False, "invalid_pid")
            return _Built(f"taskkill /F /T /PID {pid}", None, True, "ok",
                          argv=["taskkill", "/F", "/T", "/PID", str(pid)])
        if t == "block_ip":
            ip = _valid_ip(p.get("ip"))
            if ip is None:
                return _Built("", None, False, "invalid_ip")
            name = f"Cerberus_block_{ip}"
            add = ["netsh", "advfirewall", "firewall", "add", "rule",
                   f"name={name}", "dir=out", "action=block", f"remoteip={ip}"]
            dele = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"]
            return _Built(" ".join(add), " ".join(dele), True, "ok",
                          argv=add, revert_argv=dele)
        if t == "stop_service":
            name = _valid_name(p.get("name"))
            if name is None:
                return _Built("", None, False, "invalid_service")
            return _Built(f"sc stop {name}", f"sc start {name}", True, "ok",
                          argv=["sc", "stop", name], revert_argv=["sc", "start", name])
        if t == "disable_user":
            user = _valid_name(p.get("username"))
            if user is None:
                return _Built("", None, False, "invalid_username")
            return _Built(f"net user {user} /active:no", f"net user {user} /active:yes",
                          True, "ok",
                          argv=["net", "user", user, "/active:no"],
                          revert_argv=["net", "user", user, "/active:yes"])
        if t == "isolate_host":
            name = "Cerberus_isolate"
            add = ["netsh", "advfirewall", "firewall", "add", "rule",
                   f"name={name}", "dir=out", "action=block", "remoteip=0.0.0.0/0"]
            dele = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"]
            return _Built(" ".join(add), " ".join(dele), True, "ok",
                          argv=add, revert_argv=dele)
        if t == "quarantine":
            raw = p.get("path")
            if not raw:
                return _Built("", None, False, "invalid_path")
            src = Path(str(raw))
            if not src.is_file():
                return _Built("", None, False, "path_not_a_file")
            dest = self._quarantine_dir / f"{src.name}.quarantined"
            return _Built(f"move {src} -> {dest}", f"move {dest} -> {src}", True, "ok")
        return _Built("", None, False, "unknown_action")

    # ---- run (ejecuta) ----
    def run(self, action: Action) -> ActionResult:
        built = self.build(action)
        if not built.valid:
            return ActionResult(action=action, executed=False, success=False, output="",
                                command=built.command, reverted_command=built.reverted_command,
                                reason=built.reason)
        try:
            if action.type == "kill_pid":
                success, output = self._kill_pid(int(action.params["pid"]))
            elif action.type == "quarantine":
                success, output = self._quarantine(Path(str(action.params["path"])), built)
            elif built.argv is not None:
                success, output = self._run_cmd(built.argv)
            else:
                return ActionResult(action=action, executed=False, success=False, output="",
                                    command=built.command, reverted_command=built.reverted_command,
                                    reason="not_executable")
        except Exception as exc:  # cualquier fallo del SO -> registrado, no rompe el pipeline
            _log.error("action_exec_error", extra={"action": action.type, "error": str(exc)})
            return ActionResult(action=action, executed=True, success=False, output=repr(exc),
                                command=built.command, reverted_command=built.reverted_command,
                                reason="exec_error")
        return ActionResult(action=action, executed=True, success=success, output=output,
                            command=built.command, reverted_command=built.reverted_command,
                            reason="authorized")

    # ---- revert (rollback) ----
    def revert(self, action: Action) -> ActionResult:
        built = self.build(action)
        if built.revert_argv is None and action.type != "quarantine":
            return ActionResult(action=action, executed=False, success=False, output="",
                                command=built.reverted_command or "",
                                reverted_command=None, reason="not_revertible")
        try:
            if action.type == "quarantine":
                success, output = (False, "manual_restore_required")
            else:
                assert built.revert_argv is not None
                success, output = self._run_cmd(built.revert_argv)
        except Exception as exc:
            return ActionResult(action=action, executed=True, success=False, output=repr(exc),
                                command=built.reverted_command or "", reverted_command=None,
                                reason="revert_error")
        return ActionResult(action=action, executed=True, success=success, output=output,
                            command=built.reverted_command or "", reverted_command=None,
                            reason="reverted")

    # ---- low-level (mockeado en tests) ----
    @staticmethod
    def _run_cmd(argv: list[str]) -> tuple[bool, str]:
        proc = subprocess.run(argv, shell=False, capture_output=True, text=True,
                              timeout=_CMD_TIMEOUT)
        return proc.returncode == 0, (proc.stdout or proc.stderr or "")

    @staticmethod
    def _kill_pid(pid: int) -> tuple[bool, str]:
        try:
            psutil.Process(pid).terminate()
            return True, f"terminated {pid}"
        except Exception:
            ok, out = SystemExecutor._run_cmd(["taskkill", "/F", "/T", "/PID", str(pid)])
            return ok, out

    def _quarantine(self, src: Path, built: _Built) -> tuple[bool, str]:
        import shutil
        self._quarantine_dir.mkdir(parents=True, exist_ok=True)
        dest = self._quarantine_dir / f"{src.name}.quarantined"
        shutil.move(str(src), str(dest))
        return True, f"quarantined to {dest}"
```

- [ ] **Step 4:** `pytest tests/unit/test_executor.py -v` → 9 passed.

- [ ] **Step 5:** Commit:
```bash
git add cerberus/response/executor.py tests/unit/test_executor.py
git commit -m "feat(response): add SystemExecutor (6 actions, injection-safe argv, build/run/revert)"
```
Trailer: `Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>`

---

## Task 8: `ResponseEngine` (gates fail-closed + orquestación) — G1/G3

**Files:** `cerberus/response/engine.py`, `tests/unit/test_response_engine.py`

- [ ] **Step 1: Tests** — `tests/unit/test_response_engine.py`:
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


def _finding(severity=Severity.CRITICAL, categories=("mass_rename",), pid=4892):
    evs = [Event(source="fs", type=c, host="H", pid=pid, user="u", raw={}, indicators={})
           for c in categories]
    f = Finding.from_cluster(host="H", pid=pid, user="u", evidence=evs)
    return dataclasses.replace(f, severity=severity, severity_base=severity)


class _FakePolicy:
    def __init__(self, decisions):
        self._d = decisions

    def decide(self, finding):
        return self._d


class _FakeExecutor:
    def __init__(self):
        self.run_calls = []

    def build(self, action):
        from cerberus.response.executor import _Built
        return _Built(command="CMD", reverted_command="REV", valid=True, reason="ok")

    def run(self, action):
        self.run_calls.append(action)
        return ActionResult(action=action, executed=True, success=True, output="ok",
                            command="CMD", reverted_command="REV", reason="authorized")


def _engine(tmp_path, mode, decisions, executor=None, killswitch=False):
    store = ActionStore(tmp_path / "a.db")
    store.init_schema()
    ks = tmp_path / "KILLSWITCH"
    if killswitch:
        ks.write_text("x", encoding="utf-8")
    return ResponseEngine(
        policy_engine=_FakePolicy(decisions),
        executor=executor or _FakeExecutor(),
        action_store=store,
        rate_limiter=RateLimiter(10, 1),
        mode=mode,
        killswitch_path=ks,
        auto_critical_categories=frozenset({"ransomware", "mass_rename", "c2", "data_exfil"}),
    ), store


def _dec(type_="kill_pid", confirm=False, pid=4892):
    return PolicyDecision(action=Action(type=type_, params={"pid": pid}),
                          policy_id="p1", require_confirmation=confirm)


@pytest.mark.asyncio
async def test_dry_run_never_executes_but_logs(tmp_path):
    ex = _FakeExecutor()
    eng, store = _engine(tmp_path, "dry_run", [_dec()], executor=ex)
    report = await eng.handle(_finding())
    assert ex.run_calls == []                       # no ejecución
    assert report.executed_count == 0
    row = store.fetch_recent()[0]
    assert row["executed"] == 0 and row["reason"] == "dry_run"
    assert row["command"] == "CMD"                  # comando registrado igualmente


@pytest.mark.asyncio
async def test_monitor_never_executes(tmp_path):
    ex = _FakeExecutor()
    eng, _ = _engine(tmp_path, "monitor", [_dec()], executor=ex)
    await eng.handle(_finding())
    assert ex.run_calls == []


@pytest.mark.asyncio
async def test_killswitch_forces_no_exec(tmp_path):
    ex = _FakeExecutor()
    eng, store = _engine(tmp_path, "auto_all", [_dec()], executor=ex, killswitch=True)
    await eng.handle(_finding(severity=Severity.CRITICAL))
    assert ex.run_calls == []
    assert store.fetch_recent()[0]["reason"] == "killswitch"


@pytest.mark.asyncio
async def test_auto_critical_executes_on_critical_matching_category(tmp_path):
    ex = _FakeExecutor()
    eng, _ = _engine(tmp_path, "auto_critical", [_dec()], executor=ex)
    await eng.handle(_finding(severity=Severity.CRITICAL, categories=("mass_rename",)))
    assert len(ex.run_calls) == 1


@pytest.mark.asyncio
async def test_auto_critical_skips_non_matching_category(tmp_path):
    ex = _FakeExecutor()
    eng, store = _engine(tmp_path, "auto_critical", [_dec()], executor=ex)
    await eng.handle(_finding(severity=Severity.CRITICAL, categories=("new_process",)))
    assert ex.run_calls == []
    assert store.fetch_recent()[0]["reason"] == "mode_gate"


@pytest.mark.asyncio
async def test_require_confirmation_blocks_auto(tmp_path):
    ex = _FakeExecutor()
    eng, store = _engine(tmp_path, "auto_all", [_dec(confirm=True)], executor=ex)
    await eng.handle(_finding(severity=Severity.CRITICAL))
    assert ex.run_calls == []
    assert store.fetch_recent()[0]["reason"] == "require_confirmation"


@pytest.mark.asyncio
async def test_rate_limit_blocks_excess(tmp_path):
    ex = _FakeExecutor()
    store = ActionStore(tmp_path / "a.db"); store.init_schema()
    ks = tmp_path / "KILLSWITCH"
    eng = ResponseEngine(
        policy_engine=_FakePolicy([_dec(pid=i) for i in range(5)]),
        executor=ex, action_store=store,
        rate_limiter=RateLimiter(max_actions_per_minute=2, max_isolate_per_hour=1),
        mode="auto_all", killswitch_path=ks,
        auto_critical_categories=frozenset(),
    )
    await eng.handle(_finding(severity=Severity.CRITICAL))
    assert len(ex.run_calls) == 2                   # solo 2 pasan el rate limit
    reasons = [r["reason"] for r in store.fetch_recent(limit=10)]
    assert reasons.count("rate_limited") == 3


@pytest.mark.asyncio
async def test_only_policy_decides_not_ai(tmp_path):
    # G1: aunque ai_triage sugiera más acciones, solo se procesan las PolicyDecision recibidas
    ex = _FakeExecutor()
    eng, store = _engine(tmp_path, "auto_all", [_dec(type_="kill_pid")], executor=ex)
    f = _finding(severity=Severity.CRITICAL)
    f = dataclasses.replace(f, ai_triage={"suggested_actions": ["isolate_host", "disable_user"]})
    await eng.handle(f)
    assert [a.type for a in ex.run_calls] == ["kill_pid"]   # nada de la IA
```

- [ ] **Step 2:** `pytest tests/unit/test_response_engine.py -v` → FAIL.

- [ ] **Step 3:** Implementar `cerberus/response/engine.py`:
```python
from __future__ import annotations

from pathlib import Path
from typing import Protocol

from cerberus.core.event import Severity
from cerberus.core.finding import Finding
from cerberus.core.logger import get_logger
from cerberus.response.action_store import ActionStore
from cerberus.response.actions import Action, ActionReport, ActionResult, PolicyDecision
from cerberus.response.rate_limiter import RateLimiter

_log = get_logger("cerberus.response.engine")


class _PolicyEngine(Protocol):
    def decide(self, finding: Finding) -> list[PolicyDecision]: ...


class _Executor(Protocol):
    def build(self, action: Action) -> object: ...
    def run(self, action: Action) -> ActionResult: ...


class ResponseEngine:
    """Orquesta la respuesta. Gates fail-closed: killswitch -> modo -> confirmation -> rate.
    Solo la PolicyEngine decide acciones (G1); los gates no consultan ai_triage (G3).
    """

    def __init__(
        self,
        policy_engine: _PolicyEngine,
        executor: _Executor,
        action_store: ActionStore,
        rate_limiter: RateLimiter,
        mode: str,
        killswitch_path: Path,
        auto_critical_categories: frozenset[str],
    ) -> None:
        self._policy = policy_engine
        self._executor = executor
        self._store = action_store
        self._rate = rate_limiter
        self._mode = mode
        self._killswitch_path = Path(killswitch_path)
        self._auto_critical_categories = auto_critical_categories

    def _killswitch_active(self) -> bool:
        return self._killswitch_path.exists()

    def _decide_execute(self, decision: PolicyDecision, finding: Finding) -> tuple[bool, str]:
        if self._killswitch_active():
            return False, "killswitch"
        if self._mode in ("dry_run", "monitor"):
            return False, self._mode
        if self._mode == "auto_critical":
            if not (finding.severity == Severity.CRITICAL
                    and (finding.categories & self._auto_critical_categories)):
                return False, "mode_gate"
        elif self._mode == "auto_all":
            if finding.severity < Severity.HIGH:
                return False, "mode_gate"
        if decision.require_confirmation:
            return False, "require_confirmation"
        if not self._rate.allow(decision.action.type):
            return False, "rate_limited"
        return True, "authorized"

    async def handle(self, finding: Finding) -> ActionReport:
        decisions = self._policy.decide(finding)
        results: list[ActionResult] = []
        for decision in decisions:
            should, reason = self._decide_execute(decision, finding)
            if should:
                result = self._executor.run(decision.action)
            else:
                built = self._executor.build(decision.action)
                result = ActionResult(
                    action=decision.action, executed=False, success=False, output="",
                    command=getattr(built, "command", ""),
                    reverted_command=getattr(built, "reverted_command", None),
                    reason=reason,
                )
            self._store.insert(result, finding_id=finding.id,
                               policy_id=decision.policy_id, mode=self._mode)
            _log.info("response_action",
                      extra={"finding_id": finding.id, "policy": decision.policy_id,
                             "action": decision.action.type, "executed": result.executed,
                             "reason": result.reason})
            results.append(result)
        return ActionReport(finding_id=finding.id, mode=self._mode, results=results)
```

- [ ] **Step 4:** `pytest tests/unit/test_response_engine.py -v` → 8 passed.

- [ ] **Step 5:** Commit:
```bash
git add cerberus/response/engine.py tests/unit/test_response_engine.py
git commit -m "feat(response): add ResponseEngine with fail-closed gates (killswitch/mode/confirm/rate)"
```
Trailer: `Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>`

---

## Task 9: Wire ResponseEngine en CLI + sección "Acciones" en reporte

**Files:** `cerberus/cli/commands.py`, `cerberus/reporting/markdown.py`, `tests/unit/test_report_markdown.py`

- [ ] **Step 1:** En `cerberus/cli/commands.py` añadir imports:
```python
from cerberus.response.action_store import ActionStore
from cerberus.response.engine import ResponseEngine
from cerberus.response.executor import SystemExecutor
from cerberus.response.policy_engine import PolicyEngine
from cerberus.response.rate_limiter import RateLimiter
```
Helper (tras `_build_pipeline`):
```python
def _build_response_engine(cfg: CerberusConfig, action_store: ActionStore) -> ResponseEngine | None:
    if not cfg.response.enabled:
        return None
    repo_root = Path(__file__).resolve().parent.parent.parent
    policies_dir = cfg.response.policies_dir
    if not policies_dir.is_absolute():
        policies_dir = repo_root / policies_dir
    policy_engine = PolicyEngine(policies_dir)
    n = policy_engine.load()
    _log.info("policies_loaded", extra={"count": n})
    return ResponseEngine(
        policy_engine=policy_engine,
        executor=SystemExecutor(quarantine_dir=cfg.paths.quarantine_dir),
        action_store=action_store,
        rate_limiter=RateLimiter(
            max_actions_per_minute=cfg.response.rate.max_actions_per_minute,
            max_isolate_per_hour=cfg.response.rate.max_isolate_per_hour,
        ),
        mode=cfg.mode,
        killswitch_path=cfg.paths.killswitch_path,
        auto_critical_categories=cfg.response.auto_critical_categories,
    )
```
En `_run_loop`, tras crear `fstore`, crear el action store y el response engine, una lista `collected_action_reports`, y enriquecer `on_finding`:
```python
    astore = ActionStore(cfg.paths.actions_db)
    astore.init_schema()
    response_engine = _build_response_engine(cfg, astore)
    collected_action_reports: list[ActionReport] = []

    async def on_finding(f: Finding) -> None:
        enriched = await pipeline.process(f)
        fstore.insert(enriched)
        collected_findings.append(enriched)
        if response_engine is not None:
            report = await response_engine.handle(enriched)
            collected_action_reports.append(report)
```
Importar `from cerberus.response.actions import ActionReport`. Pasar `collected_action_reports` al `_report_loop` y a la escritura final del `finally`. El `_report_loop` cambia a:
```python
async def _report_loop(
    writer: MarkdownReportWriter,
    events: list[Event],
    findings: list[Finding],
    action_reports: list[ActionReport],
    interval: int,
) -> None:
    while True:
        await asyncio.sleep(interval)
        ev_snapshot = list(events)
        fn_snapshot = list(findings)
        ar_snapshot = list(action_reports)
        events.clear()
        findings.clear()
        action_reports.clear()
        writer.write(ev_snapshot, when=datetime.now(UTC), findings=fn_snapshot,
                     action_reports=ar_snapshot)
```
La creación de `reporter_task` pasa `collected_action_reports`; la escritura final del `finally` pasa `action_reports=collected_action_reports`; y se cierra `astore.close()` junto a `store.close()`/`fstore.close()`. El `if collected_events or collected_findings:` final se amplía a `if collected_events or collected_findings or collected_action_reports:`.

- [ ] **Step 2:** En `cmd_status`, añadir conteo de acciones:
```python
    astore = ActionStore(cfg.paths.actions_db)
    astore.init_schema()
    print(f"Actions DB  : {cfg.paths.actions_db}")
    print(f"Acciones    : {len(astore.fetch_recent(limit=100000))}")
    astore.close()
```
(insertar antes de `store.close()`).

- [ ] **Step 3:** Añadir test a `tests/unit/test_report_markdown.py`:
```python
def test_render_actions_section():
    from cerberus.response.actions import Action, ActionResult, ActionReport
    a = Action(type="kill_pid", params={"pid": 10})
    r = ActionResult(action=a, executed=False, success=False, output="",
                     command="taskkill /F /T /PID 10", reverted_command=None, reason="dry_run")
    rep = ActionReport(finding_id="F1", mode="dry_run", results=[r])
    out = MarkdownReportWriter.render([], host="H", findings=[], action_reports=[rep])
    assert "## Acciones" in out
    assert "kill_pid" in out
    assert "dry_run" in out
```

- [ ] **Step 4:** En `cerberus/reporting/markdown.py`, añadir parámetro `action_reports` y la sección. Firma de `render` y `write` gana `action_reports: list[ActionReport] | None = None`; importar `ActionReport`. Tras la sección de findings (antes de la sección de eventos), añadir:
```python
        action_reports = action_reports or []
        if action_reports:
            lines.append("## Acciones")
            lines.append("")
            lines.append("| Finding | Modo | Acción | Ejecutada | Éxito | Razón |")
            lines.append("|---------|------|--------|-----------|-------|-------|")
            for rep in action_reports:
                for r in rep.results:
                    lines.append(
                        f"| `{rep.finding_id}` | {rep.mode} | {r.action.type} | "
                        f"{r.executed} | {r.success} | {r.reason} |"
                    )
            lines.append("")
```
(El parámetro debe propagarse de `write` a `render`. Mantener compatibilidad: default `None`.)

- [ ] **Step 5:** Gates:
Run: `.venv/Scripts/python -m pytest tests/unit/test_cli_commands.py tests/unit/test_report_markdown.py -p no:cacheprovider --no-cov -q` → verde.
Run: `.venv/Scripts/python -m ruff check cerberus/cli/commands.py cerberus/reporting/markdown.py tests/unit/test_report_markdown.py` → limpio (aplicar `--fix` si hay orden de imports).
Run: `.venv/Scripts/python -m mypy cerberus cerberus_local.py` → limpio.
Run: `.venv/Scripts/python cerberus_local.py version` → `cerberus-local 0.4.0`.

- [ ] **Step 6:** Commit:
```bash
git add cerberus/cli/commands.py cerberus/reporting/markdown.py tests/unit/test_report_markdown.py
git commit -m "feat(cli): wire ResponseEngine into run loop; add actions section to report"
```
Trailer: `Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>`

---

## Task 10: CLI `mode` y `rollback`

**Files:** `cerberus/cli/commands.py`, `cerberus_local.py`, `tests/unit/test_cli_commands.py`

- [ ] **Step 1:** En `cerberus/cli/commands.py` añadir:
```python
def cmd_mode(cfg: CerberusConfig, new_mode: str) -> int:
    from cerberus.core.config import _VALID_MODES
    if new_mode not in _VALID_MODES:
        print(f"Modo inválido: {new_mode}. Válidos: {sorted(_VALID_MODES)}")
        return 2
    print(f"Para activar el modo {new_mode}, edita 'mode:' en config/cerberus.default.yml "
          f"y reinicia el agente. (La persistencia en caliente llega con el Service en M5.)")
    return 0


def cmd_rollback(cfg: CerberusConfig, action_id: str) -> int:
    astore = ActionStore(cfg.paths.actions_db)
    astore.init_schema()
    row = astore.fetch_by_id(action_id)
    if row is None:
        print(f"No existe action_id {action_id}")
        astore.close()
        return 2
    if not row["executed"]:
        print(f"Acción {action_id} no se ejecutó (reason={row['reason']}); nada que revertir.")
        astore.close()
        return 0
    executor = SystemExecutor(quarantine_dir=cfg.paths.quarantine_dir)
    action = Action(type=row["action_type"], params=row["params"])
    result = executor.revert(action)
    astore.insert(result, finding_id=row["finding_id"],
                  policy_id=f"rollback_of:{action_id}", mode=cfg.mode)
    print(f"Rollback de {action_id} ({row['action_type']}): "
          f"success={result.success} reason={result.reason}")
    astore.close()
    return 0 if result.success else 1
```
(Añadir `from cerberus.response.actions import Action` a los imports.)

- [ ] **Step 2:** En `cerberus_local.py`, añadir subcomandos `mode <value>` y `rollback <action_id>` al parser y al dispatch:
```python
    m = sub.add_parser("mode")
    m.add_argument("value")
    m.add_argument("--config", type=Path, default=None)
    rb = sub.add_parser("rollback")
    rb.add_argument("action_id")
    rb.add_argument("--config", type=Path, default=None)
```
y en `main`:
```python
    if args.command == "mode":
        return cmd_mode(cfg, args.value)
    if args.command == "rollback":
        return cmd_rollback(cfg, args.action_id)
```
(importar `cmd_mode`, `cmd_rollback`).

- [ ] **Step 3:** Tests en `tests/unit/test_cli_commands.py`:
```python
def test_cmd_mode_invalid_returns_2(tmp_path, capsys):
    from cerberus.cli.commands import cmd_mode
    rc = cmd_mode(_make_cfg(tmp_path), "nuke")
    assert rc == 2


def test_cmd_mode_valid_returns_0(tmp_path, capsys):
    from cerberus.cli.commands import cmd_mode
    rc = cmd_mode(_make_cfg(tmp_path), "auto_critical")
    assert rc == 0


def test_cmd_rollback_missing_action(tmp_path, capsys):
    from cerberus.cli.commands import cmd_rollback
    rc = cmd_rollback(_make_cfg(tmp_path), "does-not-exist")
    assert rc == 2


def test_cmd_rollback_reverts_executed_action(tmp_path):
    import dataclasses
    from unittest.mock import MagicMock, patch
    from cerberus.cli.commands import cmd_rollback
    from cerberus.response.action_store import ActionStore
    from cerberus.response.actions import Action, ActionResult
    cfg = _make_cfg(tmp_path)
    astore = ActionStore(cfg.paths.actions_db)
    astore.init_schema()
    a = Action(type="block_ip", params={"ip": "9.9.9.9"})
    r = ActionResult(action=a, executed=True, success=True, output="ok",
                     command="netsh add", reverted_command="netsh delete", reason="authorized")
    aid = astore.insert(r, finding_id="F1", policy_id="c2", mode="auto_all")
    astore.close()
    with patch("cerberus.response.executor.subprocess.run") as mrun:
        mrun.return_value = MagicMock(returncode=0, stdout="ok", stderr="")
        rc = cmd_rollback(cfg, aid)
    assert rc == 0
```

- [ ] **Step 4:** Gates: `pytest tests/unit/test_cli_commands.py -p no:cacheprovider --no-cov -q` → verde. `ruff` + `mypy` limpios. Smoke: `python cerberus_local.py mode auto_critical` y `python cerberus_local.py rollback xxx` (imprime "no existe").

- [ ] **Step 5:** Commit:
```bash
git add cerberus/cli/commands.py cerberus_local.py tests/unit/test_cli_commands.py
git commit -m "feat(cli): add mode and rollback subcommands"
```
Trailer: `Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>`

---

## Task 11: Integration test M4

**Files:** `tests/integration/test_pipeline_m4.py`

- [ ] **Step 1:** `tests/integration/test_pipeline_m4.py`:
```python
import dataclasses
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from cerberus.core.event import Event, Severity
from cerberus.core.finding import Finding
from cerberus.response.action_store import ActionStore
from cerberus.response.engine import ResponseEngine
from cerberus.response.executor import SystemExecutor
from cerberus.response.policy_engine import PolicyEngine
from cerberus.response.rate_limiter import RateLimiter

_POLICIES = Path(__file__).resolve().parents[2] / "policies"


def _ransomware_finding(tmp_path):
    evs = [Event(source="fs", type="mass_rename", host="H", pid=4892, user="u",
                 raw={}, indicators={"rename_count": 30}),
           Event(source="net", type="outbound_conn", host="H", pid=4892, user="u",
                 raw={}, indicators={"remote_ip": "9.9.9.9"}),
           Event(source="proc", type="new_process", host="H", pid=4892, user="u",
                 raw={}, indicators={"exe": str(tmp_path / "evil.exe")})]
    f = Finding.from_cluster(host="H", pid=4892, user="u", evidence=evs)
    return dataclasses.replace(f, severity=Severity.CRITICAL, severity_base=Severity.CRITICAL)


def _engine(tmp_path, mode):
    store = ActionStore(tmp_path / "actions.db"); store.init_schema()
    pe = PolicyEngine(_POLICIES); pe.load()
    return ResponseEngine(
        policy_engine=pe,
        executor=SystemExecutor(quarantine_dir=tmp_path / "q"),
        action_store=store, rate_limiter=RateLimiter(10, 1), mode=mode,
        killswitch_path=tmp_path / "KILLSWITCH",
        auto_critical_categories=frozenset({"ransomware", "mass_rename", "c2", "data_exfil"}),
    ), store


@pytest.mark.asyncio
async def test_m4_dry_run_logs_without_executing(tmp_path):
    eng, store = _engine(tmp_path, "dry_run")
    with patch("cerberus.response.executor.subprocess.run") as mrun, \
         patch("cerberus.response.executor.psutil.Process") as mproc:
        report = await eng.handle(_ransomware_finding(tmp_path))
        mrun.assert_not_called()
        mproc.assert_not_called()
    assert report.executed_count == 0
    rows = store.fetch_recent(limit=50)
    assert len(rows) >= 1
    assert all(r["executed"] == 0 for r in rows)
    assert all(r["reason"] == "dry_run" for r in rows)
    # ransomware(kill_pid,quarantine,block_ip)+execution(kill_pid)+isolation(isolate_host)
    # casan para un finding CRITICAL con mass_rename/new_process -> todos registrados, ninguno ejecutado
    types = {r["action_type"] for r in rows}
    assert {"kill_pid", "quarantine", "block_ip", "isolate_host"} <= types


@pytest.mark.asyncio
async def test_m4_auto_critical_executes_via_mocked_executor(tmp_path):
    eng, store = _engine(tmp_path, "auto_critical")
    with patch("cerberus.response.executor.subprocess.run") as mrun, \
         patch("cerberus.response.executor.psutil.Process") as mproc, \
         patch("cerberus.response.executor.shutil.move") as mmove:
        mrun.return_value = MagicMock(returncode=0, stdout="ok", stderr="")
        report = await eng.handle(_ransomware_finding(tmp_path))
    assert report.executed_count >= 1               # ejecutó vía capa mockeada
    assert any(r["executed"] == 1 for r in store.fetch_recent(limit=50))


@pytest.mark.asyncio
async def test_m4_killswitch_blocks_even_in_auto(tmp_path):
    eng, store = _engine(tmp_path, "auto_critical")
    (tmp_path / "KILLSWITCH").write_text("x", encoding="utf-8")
    with patch("cerberus.response.executor.subprocess.run") as mrun, \
         patch("cerberus.response.executor.psutil.Process") as mproc:
        await eng.handle(_ransomware_finding(tmp_path))
        mrun.assert_not_called()
        mproc.assert_not_called()
    assert all(r["reason"] == "killswitch" for r in store.fetch_recent(limit=50))
```

- [ ] **Step 2:** `pytest tests/integration/test_pipeline_m4.py -v` → 3 passed.

- [ ] **Step 3:** Full gate: `pytest -p no:cacheprovider -q 2>&1 | grep -E "TOTAL|Required|passed|failed"` (verde, ≥85%), `ruff check .` limpio, `mypy cerberus cerberus_local.py` limpio.

- [ ] **Step 4:** Commit:
```bash
git add tests/integration/test_pipeline_m4.py
git commit -m "test(integration): add M4 response pipeline end-to-end (dry_run/auto/killswitch)"
```
Trailer: `Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>`

---

## Task 12: Auditoría de seguridad + README + tag v0.4.0-m4

> **Antes de cerrar:** invocar `auditing-security` con foco en A05 (inyección de comandos) y los guardrails de respuesta.

- [ ] **Step 1: Auditoría `auditing-security`** — checklist:
- **A05 inyección:** `_SystemExecutor` usa SOLO `subprocess.run(argv_list, shell=False)`; IP validada con `ipaddress`, pid `int`, service/username contra `^[A-Za-z0-9_.\\\- ]+$`, path `is_file()`. Confirmar que NINGÚN comando se construye con `shell=True` ni con f-strings interpolando input sin validar en la ejecución (los strings `command` son solo para auditoría/display, no se ejecutan; la ejecución usa `argv`). ✓
- **G1:** `PolicyEngine.decide` no referencia `ai_triage`/`suggested_actions` (grep). ResponseEngine ejecuta solo `PolicyDecision`. ✓
- **G3:** gates fail-closed en `_decide_execute`; killswitch primero; `dry_run`/`monitor` nunca ejecutan; `require_confirmation` bloquea auto; rate-limit. Tests cubren cada rama. ✓
- **Fail-closed:** cualquier excepción del executor → `ActionResult(success=False)`, no rompe el loop; validación fallida → no se ejecuta. ✓
- **Auditoría/rollback:** `actions_log.db` registra finding_id+policy_id+comando+reversión+reason+mode incluso en dry_run. Retención 365d (no auto-purga). ✓
- **Killswitch:** archivo en disco; si existe → fuerza no-ejecución. Documentar que crear el archivo es la parada de emergencia. ✓
Registrar resultado en el commit. Aplicar fixes con su test si surge algo.

- [ ] **Step 2:** Reemplazar `README.md` (encabezado M4, componentes de respuesta, modos, killswitch, rollback, aviso legal reforzado). Incluir:
  - Tabla de modos: dry_run (default), monitor, auto_critical, auto_all.
  - Killswitch: crear `C:\ProgramData\Cerberus\KILLSWITCH` detiene toda acción.
  - Rollback: `cerberus rollback <action_id>`.
  - Estado: tests verdes + cobertura.
  - Aviso legal: la respuesta automática puede causar interrupciones; dry_run obligatorio en primer arranque; solo en hosts propios o con autorización escrita.

- [ ] **Step 3:** Build final verde: `pytest`, `ruff check .`, `mypy cerberus cerberus_local.py`.

- [ ] **Step 4:** Commit + tag:
```bash
git add README.md
git commit -m "docs: M4 README; security audit pass (A05 argv-only exec, fail-closed gates, G1/G3)"
git tag -a v0.4.0-m4 -m "M4: PolicyEngine + ResponseEngine + 6 actions + rollback (dry_run default)"
```

- [ ] **Step 5 (manual, opcional, Windows):** En una VM/host de pruebas, con `mode: dry_run`, generar actividad ransomware-like; verificar que el reporte muestra la sección `## Acciones` con `Ejecutada=False` y `Razón=dry_run`, y que `actions_log.db` tiene las filas con comando+reversión. NO probar `auto_*` fuera de una VM aislada.

---

## Checklist final M4
- [ ] Pre-flight: rama `m4/policy-and-response` desde `master`@`v0.3.0-m3`
- [ ] 12 tareas completadas (tests verdes por tarea)
- [ ] Coverage ≥ 85%, `ruff` limpio, `mypy --strict` limpio
- [ ] G1 (solo policy decide), G3 (gates fail-closed) verificados por tests; G7 (trazabilidad finding_id+policy_id) en actions_log
- [ ] A05: ejecución solo vía `argv` validado + `shell=False`
- [ ] dry_run default obligatorio; killswitch funcional; rate-limits aplicados
- [ ] `_SystemExecutor` mockeado en el 100% de los tests (ningún test toca el SO)
- [ ] Tag `v0.4.0-m4` creado

## Próximo plan
`docs/superpowers/plans/YYYY-MM-DD-cerberus-m5-service-and-packaging.md`
(Windows Service + named pipe IPC + .msi + anti-tampering + redteam + pyshark/dns_query + hardening LOW NetCollector + persistencia en caliente de `mode`).
