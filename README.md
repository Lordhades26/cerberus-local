# CERBERUS-LOCAL — M4 (Respuesta: PolicyEngine + ResponseEngine)

EDR híbrido Windows con IA local Ollama. Fork defensivo de HADES-LOCAL.

**Hito actual:** M4 — respuesta automática heurística con guardrails. Tras la
detección (M3), cada finding pasa por una `PolicyEngine` que decide acciones por
`(severity, categorías)` y un `ResponseEngine` que aplica gates fail-closed antes
de ejecutar. **`dry_run` es el default obligatorio**: detecta, decide y registra,
pero no ejecuta hasta que el operador active un modo `auto_*` explícitamente.

## Componentes en M4 (sobre M1–M3)

- `PolicyEngine` (YAML) → decide acciones SOLO por `(severity, categorías del finding)` — **nunca** por la IA (G1)
- `SystemExecutor` → 6 acciones: `kill_pid`, `quarantine`, `block_ip`, `stop_service`, `isolate_host`, `disable_user`; **anti-inyección** (`subprocess` con argv-list, `shell=False`, inputs validados); `build`(puro)/`run`/`revert`
- `ResponseEngine` → gates fail-closed **killswitch → modo → require_confirmation → rate-limit**; ejecución real solo en `auto_critical`/`auto_all`
- `RateLimiter` (10 acciones/min, 1 isolate_host/hora), `ActionStore` (`actions_log.db`, audit trail con comando+reversión)
- CLI `mode <m>` y `rollback <action_id>`; sección "Acciones" en el reporte

100% heurístico — **0 LLM nuevo**. El `ai_triage` de M3 es complementario y no causa ejecución.

## Modos de operación

| Modo | Comportamiento |
|------|----------------|
| `dry_run` | **Default obligatorio.** Detecta + decide + registra; NO ejecuta. |
| `monitor` | Igual que dry_run (sugiere, no ejecuta). |
| `auto_critical` | Ejecuta solo si `severity=CRITICAL` y categoría ∈ `{ransomware, c2, data_exfil}`. |
| `auto_all` | Ejecuta para `HIGH`+`CRITICAL`. |

Cambiar el modo: editar `mode:` en `config/cerberus.default.yml` y reiniciar
(persistencia en caliente llega con el Service en M5). `python cerberus_local.py mode <m>` valida el valor.

## Parada de emergencia (killswitch)

Crear el archivo `C:\ProgramData\Cerberus\KILLSWITCH` **detiene toda ejecución de
acciones** (fuerza dry_run), sin importar el modo. Es el override supremo.

## Rollback

Cada acción (ejecutada o simulada) queda en `actions_log.db` con su comando y su
reversión. Para revertir una acción ejecutada:
```powershell
python cerberus_local.py rollback <action_id>
```
(`kill_pid` no es revertible; `quarantine` requiere restauración manual.)

## Guardrails verificados por tests

- **G1** la IA no decide acciones (solo `PolicyEngine`, por `severity`+`categorías`)
- **G3** la IA no bypassa dry_run/killswitch/rate-limits/confirmation (gates fail-closed)
- **G7** trazabilidad: cada acción en `actions_log.db` referencia `finding_id` + `policy_id`
- **A05** ejecución solo vía `argv` validado con `shell=False` (sin inyección de comandos)
- `isolate_host` y `disable_user` requieren `require_confirmation` (no auto por blast-radius)

## Quickstart

```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -e ".[dev]"
pip install -e ".[windows]"      # opcional, EvtCollector real en Windows

python cerberus_local.py version  # cerberus-local 0.4.0
python cerberus_local.py status   # conteos eventos/findings/acciones + collectors
python cerberus_local.py start    # foreground, Ctrl+C para detener (dry_run por defecto)
```

## Tests

```powershell
.venv\Scripts\python -m pytest               # suite completa con coverage (gate >=85%)
.venv\Scripts\python -m ruff check .
.venv\Scripts\python -m mypy cerberus cerberus_local.py
```

Estado actual: **152 tests verdes, cobertura 91.17%, ruff y mypy (strict) limpios.**

## Próximo hito

- **M5** — Windows Service, named pipe IPC, `.msi`, anti-tampering, redteam tests, pyshark/`dns_query`, hardening del LOW de NetCollector, persistencia en caliente de `mode`.

Ver `docs/superpowers/specs/2026-05-21-cerberus-local-edr-design.md` y `docs/superpowers/plans/`.

## Aviso legal

CERBERUS-LOCAL es software defensivo; solo en hosts propios o con autorización
escrita del propietario. **La respuesta automática (kill/firewall/quarantine/
isolate/disable_user) puede causar interrupciones operativas graves**, incluido el
aislamiento de red o el bloqueo de cuentas. El modo `dry_run` es obligatorio en
primer arranque; **no actives `auto_*` fuera de una VM aislada hasta validar las
policies en tu entorno**. El autor no se responsabiliza por uso indebido.
