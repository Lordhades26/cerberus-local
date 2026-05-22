# CERBERUS-LOCAL — M2 (Telemetría multi-fuente + Correlator)

EDR híbrido Windows con IA local Ollama. Fork defensivo de HADES-LOCAL.

**Hito actual:** M2 — los cuatro collectors + correlación heurística. Sin reglas Sigma, sin IA, sin respuesta automática (vienen en M3).

## Componentes en M2

- `ProcCollector` (psutil) → `new_process`, `process_exit`
- `NetCollector` (psutil polling) → `outbound_conn`, `beaconing_suspect` *(pyshark/Npcap + `dns_query` se difieren a M3)*
- `FsCollector` (watchdog) → `file_created`, `file_modified`, `mass_rename`, `high_entropy_write`
- `EvtCollector` (win32evtlog) → `logon_failure`, `service_install`, `scheduled_task_create`, `ps_blocklist`, `win_event` *(degrada con gracia fuera de Windows / sin pywin32)*
- `EventBus` (asyncio) → fan-out a suscriptores con filtrado por source
- `Correlator` (ventana deslizante) → agrupa por `(host, pid, user)` y promueve clusters multi-fuente a `Finding`
- `EventStore` (events.db) + `FindingStore` (findings.db) → persistencia SQLite WAL
- `MarkdownReportWriter` → reporte con sección de findings + eventos por source
- CLI `cerberus_local.py` con subcomandos `start`, `status`, `stop`, `version`

Toda la cadena de M2 es **100% heurística** (ningún LLM); respeta el invariante ≥80% heurístico / ≤20% agéntico del diseño (§10.5). El LLM entra en M3.

## Quickstart

```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -e ".[dev]"
# En Windows, para el EvtCollector real (Event Log):
pip install -e ".[windows]"

# Ver versión
python cerberus_local.py version

# Ver estado: conteos de eventos/findings + estado de los 4 collectors
python cerberus_local.py status

# Arrancar (foreground, Ctrl+C para detener)
python cerberus_local.py start
```

Los reportes se escriben en `C:\Users\Public\cerberus_reports\` (configurable). El primer reporte aparece tras `reporting.interval_seconds` (default 300 s) o al detener el agente con Ctrl+C.

## Configuración

`config/cerberus.default.yml`:

```yaml
mode: dry_run                       # dry_run | monitor (auto_* vienen en M3)
host_name: null                     # null = autodetect
paths:
  data_dir: "C:\\ProgramData\\Cerberus"
  events_db: "C:\\ProgramData\\Cerberus\\db\\events.db"
  findings_db: "C:\\ProgramData\\Cerberus\\db\\findings.db"
  reports_dir: "C:\\Users\\Public\\cerberus_reports"
  log_file: "C:\\ProgramData\\Cerberus\\logs\\cerberus.log"
collectors:
  proc: {enabled: true, poll_interval_seconds: 1.0}
  net:
    enabled: true
    poll_interval_seconds: 2.0
    beaconing_window_seconds: 60
    beaconing_min_connections: 10
  fs:
    enabled: true
    watch_paths: ["C:\\Users\\Public"]
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

Estado actual: **70 tests verdes, cobertura 90.65%, ruff y mypy (strict) limpios.**

## Próximos hitos

- **M3** — `RuleEngine` (YAML Sigma-like), `AIAnalyst` (Ollama, único componente LLM), `OllamaClient`, `PolicyEngine`, `ResponseEngine`, guardrails LLM, pyshark/Npcap + `dns_query`
- **M4** — Windows Service, named pipe IPC, `.msi` instalador, killswitch, anti-tampering, redteam tests

Ver `docs/superpowers/specs/2026-05-21-cerberus-local-edr-design.md` para diseño completo y `docs/superpowers/plans/` para planes por hito.

## Aviso legal

CERBERUS-LOCAL es software defensivo y se despliega únicamente en hosts propios o con autorización escrita del propietario. En M3 (cuando se habilite respuesta automática), el modo `dry_run` será obligatorio en primer arranque.
