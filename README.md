# CERBERUS-LOCAL — M1 (Skeleton + ProcCollector)

EDR híbrido Windows con IA local Ollama. Fork defensivo de HADES-LOCAL.

**Hito actual:** M1 — vertical slice de telemetría sin detección ni respuesta.

## Componentes en M1

- `ProcCollector` (psutil) → emite eventos `new_process` y `process_exit`
- `EventBus` (asyncio) → fan-out a suscriptores con filtrado por source
- `EventStore` (SQLite WAL) → persistencia de eventos
- `MarkdownReportWriter` → reportes Markdown agrupados por source
- CLI `cerberus_local.py` con subcomandos `start`, `status`, `stop`, `version`

## Quickstart

```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -e ".[dev]"

# Ver versión
python cerberus_local.py version

# Ver estado y conteo de eventos
python cerberus_local.py status

# Arrancar (foreground, Ctrl+C para detener)
python cerberus_local.py start
```

Los reportes se escriben en `C:\Users\Public\cerberus_reports\` (configurable en `config/cerberus.default.yml`). El primer reporte aparece tras `reporting.interval_seconds` (default 300 s) o al detener el agente con Ctrl+C.

## Configuración

`config/cerberus.default.yml`:

```yaml
mode: dry_run                       # único modo en M1 (M3 añade auto_critical/auto_all)
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
  interval_seconds: 300
  retention_days: 7
```

## Tests

```powershell
.venv\Scripts\python -m pytest               # suite completa con coverage (gate ≥85%)
.venv\Scripts\python -m pytest tests/unit    # sólo unitarios
.venv\Scripts\python -m pytest tests/integration  # sólo integración
.venv\Scripts\python -m ruff check .
.venv\Scripts\python -m mypy cerberus cerberus_local.py
```

Estado actual: **35 tests verdes, cobertura 95.74%, ruff y mypy limpios.**

## Próximos hitos

- **M2** — `NetCollector` (pyshark+Npcap), `FsCollector` (watchdog), `EvtCollector` (win32evtlog), Correlator
- **M3** — `RuleEngine`, `AIAnalyst` (Ollama), `PolicyEngine`, `ResponseEngine`, guardrails LLM (≥80% heurístico / ≤20% agéntico)
- **M4** — Windows Service, named pipe IPC, `.msi` instalador, anti-tampering, redteam tests

Ver `docs/superpowers/specs/2026-05-21-cerberus-local-edr-design.md` para diseño completo y `docs/superpowers/plans/` para planes por hito.

## Aviso legal

CERBERUS-LOCAL es software defensivo y se despliega únicamente en hosts propios o con autorización escrita del propietario. En M3 (cuando se habilite respuesta automática), el modo `dry_run` será obligatorio en primer arranque.
