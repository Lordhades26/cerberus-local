# CERBERUS-LOCAL — M6 (Andamiaje de campo: dns_query + Service + packaging)

EDR híbrido Windows con IA local Ollama. Fork defensivo de HADES-LOCAL.

**Hito actual:** M6 — andamiaje para despliegue en Windows real. El **código y artefactos
escribibles** están listos y testeados (captura DNS inyectable, controlador del Service,
SDDL del named pipe, scaffold del Service, plantilla WiX). La **integración real** (Npcap,
registro del Service, build/firma del `.msi`, redteam en VM) se ejecuta en campo —
runbook en **`docs/M6_FIELD_GUIDE.md`**.

## Componentes en M6 (sobre M1–M5)

- `NetCollector` — fuente DNS **inyectable** (`DnsSource`/`_PySharkDnsSource`) → eventos `dns_query`; degrada sin Npcap/pyshark (sigue polling psutil). Config `collectors.net.dns_capture`. Regla `suspicious_dns`.
- `Win32ServiceController` — builders de `sc.exe` puros + parser de `sc query` (testeables); ejecución real `# pragma: no cover`
- `NamedPipeTransport.serve_once()` + `pipe_sddl()` — server del pipe con SDDL que restringe a **SYSTEM + Administrators**
- `cerberus_service.py` — entry-point `win32serviceutil.ServiceFramework` (scaffold, guarded)
- `packaging/` — `cerberus.wxs` (WiX), `build_msi.ps1`, `install_service.ps1`

**Honestidad de validación:** toda E/S real de SO (captura Npcap, `sc.exe`, I/O del pipe, `.msi`, redteam) está marcada `# pragma: no cover` y se valida **en campo**. Lo testeable son los seams puros (source DNS mock, argv/parser de `sc`, SDDL, degradaciones). 100% heurístico — 0 LLM nuevo.

## Estado del proyecto (6 hitos)

| Hito | Contenido | Tag |
|------|-----------|-----|
| M1+M2 | Telemetría: 4 collectors + EventBus + Correlator + SQLite + reporte | v0.2.0-m2 |
| M3 | Detección: RuleEngine + AIAnalyst (Ollama, guardrails) | v0.3.0-m3 |
| M4 | Respuesta: PolicyEngine + ResponseEngine + 6 acciones + rollback | v0.4.0-m4 |
| M5 | Servicio: IPC + hot-mode + anti-tampering + hardening | v0.5.0-m5 |
| M6 | Andamiaje de campo: dns_query + Service + packaging | v0.6.0-m6 |

Tests: **189 verdes, cobertura ~89%, ruff y mypy (strict) limpios.**

## Quickstart

```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -e ".[dev]"
pip install -e ".[windows]"      # pywin32 (Service + named pipe reales)

python cerberus_local.py version  # cerberus-local 0.6.0
python cerberus_local.py start    # foreground, Ctrl+C (dry_run por defecto)
python cerberus_local.py integrity snapshot   # firma el arbol (anti-tampering)
python cerberus_local.py mode auto_critical   # hot-switch del modo
```

## Despliegue como servicio (Windows real — ver `docs/M6_FIELD_GUIDE.md`)

```powershell
# Instalar Npcap (para dns_query). Luego, como Administrador:
.\packaging\install_service.ps1 -PythonExe "C:\Python311\python.exe"
# O construir el .msi:
.\packaging\build_msi.ps1 -PythonExe "C:\Python311\python.exe" -CertThumbprint "<hash>"
```

## Tests

```powershell
.venv\Scripts\python -m pytest               # suite completa con coverage (gate >=85%)
.venv\Scripts\python -m ruff check .
.venv\Scripts\python -m mypy cerberus cerberus_local.py
```

## Campo pendiente (M6 runbook)

Instalar Npcap · registrar el Service real · build/firma del `.msi` · validar el named pipe + ACL ·
redteam en VM aislada · baseline 24h (CPU<5%/RAM<200MB) · checklist pre-release §9.5.
Todo en **`docs/M6_FIELD_GUIDE.md`**.

## Aviso legal

CERBERUS-LOCAL es software defensivo; solo en hosts propios o con autorización escrita.
La respuesta automática puede causar interrupciones graves; `dry_run` es obligatorio en primer
arranque. El named pipe se restringe a SYSTEM/Administrators; el cambio de modo y el IPC no
permiten saltarse killswitch ni rate-limits. No habilites `auto_*` fuera de una VM aislada
hasta validar las policies en tu entorno.
