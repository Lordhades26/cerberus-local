# CERBERUS-LOCAL — M5 (Núcleo de servicio: IPC + hot-mode + anti-tampering)

EDR híbrido Windows con IA local Ollama. Fork defensivo de HADES-LOCAL.

**Hito actual:** M5 — endurecimiento para operación como servicio. IPC CLI↔Service
(protocolo JSON sobre transporte abstracto), cambio de **modo en caliente** sin
reiniciar, **anti-tampering por checksum SHA256**, y purga de estado del NetCollector.
La integración real de Windows (Service, `.msi`, Npcap, redteam) es **M6 de campo** —
ver `docs/M6_FIELD_GUIDE.md`.

## Componentes en M5 (sobre M1–M4)

- **IPC** — `IpcDispatcher` (deny-by-default) + `InMemoryTransport` (tests) + `IpcServer`/`IpcClient`; `NamedPipeTransport` (pywin32 lazy, degrada sin pywin32)
- **Hot-mode** — `RuntimeState` (state.json atómico) + `ResponseEngine.set_mode()`; `cerberus mode <m>` persiste y un agente corriendo lo aplica en caliente (watcher en el loop de reporte)
- **Anti-tampering** — `IntegrityVerifier` (manifest SHA256); al arrancar, si el manifest no verifica → **fuerza `dry_run`** (fail-safe). Comandos `integrity snapshot` / `integrity verify`
- **NetCollector hardening** — purga claves beacon obsoletas (cierra el LOW de M2)
- **`ServiceController`** scaffolding (`ForegroundServiceController`; el Windows Service real es M6)

100% heurístico — 0 LLM nuevo. Cambiar a `auto_*` sigue pasando por los gates del ResponseEngine (killswitch/confirmation/rate-limit; G3 intacto).

## Comandos nuevos

```powershell
python cerberus_local.py mode auto_critical   # persiste el modo (hot-switch sin reiniciar)
python cerberus_local.py integrity snapshot   # firma el árbol (manifest.json)
python cerberus_local.py integrity verify     # verifica integridad (rc=1 si hay violación)
python cerberus_local.py rollback <action_id> # revierte una acción ejecutada (M4)
```

## Estado del proyecto (cabezas completas)

- **M1+M2** — Telemetría: 4 collectors (proc/net/fs/evt) + EventBus + Correlator + SQLite + reporte
- **M3** — Detección: RuleEngine + AIAnalyst (Ollama, consultivo, guardrails) + DetectionPipeline
- **M4** — Respuesta: PolicyEngine + ResponseEngine + 6 acciones + rollback (dry_run default)
- **M5** — Servicio: IPC + hot-mode + anti-tampering + hardening

Tests: **181 verdes, cobertura 89.6%, ruff y mypy (strict) limpios.**

## Quickstart

```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -e ".[dev]"
pip install -e ".[windows]"      # opcional, EvtCollector + named pipe reales en Windows

python cerberus_local.py version  # cerberus-local 0.5.0
python cerberus_local.py status
python cerberus_local.py start    # foreground, Ctrl+C (dry_run por defecto)
```

## Tests

```powershell
.venv\Scripts\python -m pytest               # suite completa con coverage (gate >=85%)
.venv\Scripts\python -m ruff check .
.venv\Scripts\python -m mypy cerberus cerberus_local.py
```

## Próximo (M6 — campo, manual en Windows real)

`.msi` WiX · Windows Service real (`win32serviceutil`) · named pipe con ACL SYSTEM ·
Npcap + pyshark/`dns_query` · redteam en VM · ACLs/TakeOwnership de cuarentena.
Ver **`docs/M6_FIELD_GUIDE.md`** y `docs/superpowers/specs/2026-05-21-cerberus-local-edr-design.md`.

## Aviso legal

CERBERUS-LOCAL es software defensivo; solo en hosts propios o con autorización escrita.
La respuesta automática puede causar interrupciones graves; el modo `dry_run` es obligatorio
en primer arranque. El IPC y el cambio de modo no permiten saltarse el killswitch ni los
límites de tasa. No habilites `auto_*` fuera de una VM aislada hasta validar en tu entorno.
