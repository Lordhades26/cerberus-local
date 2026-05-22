# CERBERUS-LOCAL — EDR híbrido Windows con IA local

**Fecha:** 2026-05-21
**Autor:** Fabián Hormazábal (combatelamejor@gmail.com)
**Base heredada:** HADES-LOCAL v1.2.0 (`HADES ECOSYSTEM/ediciones hades free/hades_local.py`)
**Estado:** Diseño aprobado — pendiente de plan de implementación
**Filosofía:** sin cloud, IA 100% local (Ollama), autónomo, reportes Markdown

---

## 1. Resumen ejecutivo

CERBERUS-LOCAL es un agente EDR (Endpoint Detection & Response) **híbrido host + red**, **Windows nativo**, con **respuesta automática** y **análisis IA mediante Ollama local**. Hereda directamente la filosofía y código base de HADES-LOCAL (auditoría ofensiva) pero pivota al lado defensivo: monitorea continuamente cuatro fuentes de telemetría, correla eventos, triagea con IA, y ejecuta acciones de contención automáticas según policies configurables.

El nombre (Cerbero, perro guardián del Hades) mantiene el linaje mitológico y mapea su arquitectura: tres cabezas = tres capas (Telemetría · Detección · Respuesta).

## 2. Objetivos y no-objetivos

### 2.1 Objetivos (MVP v1.0)
- Detectar técnicas MITRE ATT&CK comunes en endpoints Windows desde cuatro fuentes simultáneas (procesos, red, FS, event log).
- Triagear con IA local los findings correlacionados (severidad, familia probable, acción sugerida).
- Ejecutar acciones de respuesta automática (kill, quarantine, block IP, isolate, disable user, stop service) con rollback auditable.
- Operar como Windows Service con autoarranque y auto-recovery.
- Funcionar 100% offline tras la descarga inicial del modelo Ollama.
- Generar reportes Markdown de cada finding en `%USERPROFILE%\cerberus_reports\`.

### 2.2 No-objetivos (MVP)
- Soporte Linux/macOS (se considera para v2; el primer puerto será Linux dada la base HADES).
- Dashboard web/UI gráfico (CLI + reportes Markdown son suficientes para MVP).
- Detección basada en machine learning entrenado (solo reglas + LLM heurístico para v1).
- Multi-tenant / consola centralizada (un solo host por instancia en MVP).
- EPP (Endpoint Protection Platform) tipo AV en tiempo real con minifiltro de kernel — fuera de scope.

## 3. Arquitectura

### 3.1 Las tres cabezas

```
┌──────────────────────────────────────────────────────────────┐
│ CABEZA 3 — RESPUESTA & UX                                    │
│  ├─ response_engine (kill, firewall, quarantine, isolate)    │
│  ├─ policy_engine   (YAML: qué hacer ante qué severidad)     │
│  ├─ cli + shell interactivo (estilo HADES)                   │
│  └─ report_writer   (Markdown a ~/cerberus_reports/)         │
└──────────────────────────────────────────────────────────────┘
                            ▲
┌──────────────────────────────────────────────────────────────┐
│ CABEZA 2 — DETECCIÓN & TRIAGE                                │
│  ├─ rule_engine     (reglas YAML estilo Sigma)               │
│  ├─ ai_analyst      (Ollama: triage + contexto + severidad)  │
│  ├─ correlator      (multi-eventos, ventanas temporales)     │
│  └─ event_bus       (cola interna asyncio)                   │
└──────────────────────────────────────────────────────────────┘
                            ▲
┌──────────────────────────────────────────────────────────────┐
│ CABEZA 1 — TELEMETRÍA (4 collectors paralelos)               │
│  ├─ proc_collector  (psutil + WMI: nuevos procesos, CLI)     │
│  ├─ net_collector   (pyshark + Npcap: conexiones, DNS)       │
│  ├─ fs_collector    (watchdog: creación/mod/cifrado masivo)  │
│  └─ evt_collector   (win32evtlog: Security/Sysmon/PS Op)     │
└──────────────────────────────────────────────────────────────┘
                            ▲
                  ┌─────────────────┐
                  │  cerberus_core  │  (Windows Service)
                  │  + SQLite local │  (events.db, findings.db)
                  └─────────────────┘
```

### 3.2 Estructura del proyecto

```
cerberus-local/
├── cerberus_local.py          # entrypoint CLI (estilo hades_local.py)
├── cerberus/
│   ├── core/                  # bus, service, config, logger
│   ├── collectors/            # proc, net, fs, evt
│   ├── detection/             # rules, ai_analyst, correlator
│   ├── response/              # actions, policies
│   ├── reporting/             # markdown writer
│   └── ai/                    # cliente Ollama (port del de HADES)
├── rules/                     # YAML detection rules
├── policies/                  # YAML response policies
├── prompts/                   # prompt templates versionados
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── functional/
│   └── redteam_reports/
└── README.md
```

### 3.3 Decisiones técnicas clave
- **Lenguaje:** Python 3.11+ (heredando filosofía HADES)
- **Concurrencia:** `asyncio` para el bus + correlator; `ThreadPoolExecutor` para collectors bloqueantes (pyshark, watchdog)
- **Persistencia:** SQLite WAL local
- **Service:** `pywin32` (`win32serviceutil.ServiceFramework`)
- **IPC CLI ↔ Service:** named pipe `\\.\pipe\cerberus`
- **IA:** Ollama local (modelo recomendado `qwen2.5:7b`, fallback `qwen2.5:3b` para hardware limitado)
- **Empaquetado:** instalador `.msi` firmado vía WiX Toolset; SBOM y hashes SHA256 publicados

## 4. Componentes y APIs internas

### 4.1 `cerberus.collectors.base.Collector` (abstract)
```python
class Collector(ABC):
    name: str
    @abstractmethod
    async def start(self, bus: EventBus) -> None: ...
    @abstractmethod
    async def stop(self) -> None: ...
    async def health(self) -> dict: ...
    # health → {"running": bool, "events_emitted": int, "last_error": str|None}
```

### 4.2 Collectors concretos

| Collector | Mecanismo | Eventos emitidos |
|-----------|-----------|------------------|
| `ProcCollector` | `psutil.process_iter()` polling 1s + WMI `Win32_ProcessStartTrace` (push) | `new_process`, `process_exit` (cmdline normalizado en `Event.indicators`, suspicious flag asignado por `RuleEngine`) |
| `NetCollector` | `pyshark.LiveCapture` sobre interfaz default vía Npcap | `outbound_conn`, `dns_query`, `beaconing_suspect` |
| `FsCollector` | `watchdog.observers.Observer` + `ReadDirectoryChangesW` en rutas vigiladas | `file_created`, `file_modified`, `mass_rename`, `high_entropy_write` |
| `EvtCollector` | `win32evtlog.EvtSubscribe` a canales `Security`, `Microsoft-Windows-Sysmon/Operational`, `Microsoft-Windows-PowerShell/Operational` | `logon_failure`, `service_install`, `scheduled_task_create`, `ps_blocklist` |

Cada collector emite `Event` al bus. Si su mecanismo falla, `health.running=False` pero el resto sigue.

### 4.3 Contrato `Event` (normalizado)
```python
@dataclass
class Event:
    id: str                    # uuid4
    timestamp: datetime        # UTC
    source: Literal["proc", "net", "fs", "evt"]
    type: str                  # taxonomía: "new_process", "outbound_conn", etc.
    host: str                  # FQDN local
    pid: int | None
    user: str | None
    raw: dict                  # payload original del collector
    indicators: dict           # IOCs extraídos (hashes, IPs, paths)
```

### 4.4 `cerberus.detection.RuleEngine`
```python
class RuleEngine:
    def __init__(self, rules_dir: Path): ...
    def load(self) -> int: ...                      # carga *.yml, devuelve count
    def match(self, finding: Finding) -> list[RuleMatch]: ...
    def reload(self) -> None: ...                   # hot-reload
```
Formato de regla (estilo Sigma simplificado):
```yaml
id: ransomware_pattern_v1
severity: CRITICAL
category: ransomware
condition:
  all:
    - source: fs
      type: mass_rename
      threshold: {count: 20, window_seconds: 5}
    - source: proc
      cmdline_regex: "(powershell|cmd).+(-enc|FromBase64)"
```

### 4.5 `cerberus.detection.AIAnalyst`
```python
class AIAnalyst:
    def __init__(self, ollama_client: OllamaClient, model: str = "qwen2.5:7b"): ...
    async def triage(self, finding: Finding) -> Triage: ...
    # Triage: { severity, family_guess, reasoning, suggested_actions, confidence }
```
- Prompt template versionado en `prompts/triage.md`.
- Respuesta Ollama validada contra JSON schema; si falla → `severity = rule_engine.severity_base`.

### 4.6 `cerberus.detection.Correlator`
Ventana temporal configurable (default 10s) que agrupa eventos por `pid`/`host`/`user`. Promueve clusters a `Finding`. Emite al rule_engine.

### 4.7 `cerberus.response.ResponseEngine`
```python
class ResponseEngine:
    def __init__(self, policy_engine: PolicyEngine, dry_run: bool = False): ...
    async def execute(self, finding: Finding, actions: list[Action]) -> ActionReport: ...
```
Acciones implementadas:
- `kill_pid(pid)` — `psutil.Process.terminate()` → fallback `taskkill /F /T`
- `quarantine(path)` — mover a `C:\ProgramData\Cerberus\Quarantine\<sha256>.bin` con ACL solo SYSTEM
- `block_ip(ip)` — `netsh advfirewall firewall add rule` (alternativa `Set-NetFirewallRule`)
- `isolate_host()` — regla "block all outbound except SYSTEM + VPN admin"
- `disable_user(sid)` — `net user <name> /active:no`
- `stop_service(name)` — `sc.exe stop`

Cada acción retorna `ActionResult { success, output, reverted_command }` para auditoría y rollback.

### 4.8 `cerberus.response.PolicyEngine`
Mapea `(severity, category) → [actions]` desde `policies/*.yml`. Soporta `require_confirmation` por policy.

### 4.9 `cerberus.ai.OllamaClient`
Port directo de `ask_hades()` con autodetect Windows-first:
1. `HADES_OLLAMA_URL` / `OLLAMA_HOST` (env)
2. `http://127.0.0.1:11434`
3. `http://host.docker.internal:11434`
4. Lista configurable adicional

Retry exponencial, timeout configurable, streaming opcional.

### 4.10 `cerberus.core.EventBus`
```python
class EventBus:
    async def publish(self, event: Event) -> None: ...
    def subscribe(self, source_filter: str|None, handler: Callable) -> Subscription: ...
```
Implementación: `asyncio.Queue` + tabla de subscribers. Sin broker externo.

### 4.11 `cerberus.core.CerberusService` (Windows Service)
Hereda `win32serviceutil.ServiceFramework`. Bootstrap:
1. Cargar config + reglas + policies
2. Arrancar los 4 collectors
3. Arrancar correlator + rule_engine + ai_analyst + response_engine
4. Abrir named pipe `\\.\pipe\cerberus` para que `cerberus_local.py status/findings/rollback` hable con el servicio

## 5. Flujo de datos end-to-end (ejemplo: ransomware)

```
T+0.00s  fs_collector → Event { source: "fs", type: "mass_rename", paths: [...], hash_entropy: high }
T+0.01s  proc_collector → Event { source: "proc", type: "new_process",
                                  pid: 4892, parent: explorer.exe,
                                  cmdline: "powershell -enc <base64>" }
T+0.02s  net_collector → Event { source: "net", type: "outbound_conn",
                                  pid: 4892, dst: "185.x.x.x:443", country: "RU" }

T+0.05s  correlator (ventana 10s, agrupa por pid):
         → CorrelatedFinding { id: "F-1234", primary: "mass_rename", evidence: [...] }

T+0.10s  rule_engine.match → coincide ransomware_pattern_v1 → severity_base: CRITICAL

T+0.15s  ai_analyst.triage llama Ollama y devuelve:
         { severity: CRITICAL, family: "likely_lockbit-variant",
           reasoning: "...", suggested_actions: ["kill_pid","isolate_host","quarantine_binary"] }

T+0.20s  policy_engine evalúa policies/ransomware.yml → autorizado para auto-respuesta

T+0.25s  response_engine ejecuta:
         ├─ kill_pid(4892)              ✓
         ├─ quarantine(binary_hash)     ✓
         ├─ block_ip("185.x.x.x")       ✓
         └─ isolate_host()              ✓

T+0.30s  report_writer escribe ~/cerberus_reports/2026-05-21_F-1234_CRITICAL.md
         + persiste finding + actions en SQLite

T+0.31s  log estructurado a Windows Event Log "Cerberus/Operational"
```

## 6. Persistencia y rotación

| Almacén | Ubicación | Retención | Notas |
|---------|-----------|-----------|-------|
| `events.db` | `C:\ProgramData\Cerberus\db\events.db` (SQLite WAL) | 7 días, cap 500MB | Autovacuum |
| `findings.db` | `C:\ProgramData\Cerberus\db\findings.db` | 90 días | Index por severity/source/date |
| `actions_log.db` | `C:\ProgramData\Cerberus\db\actions_log.db` | 365 días | Audit trail, no se purga automáticamente |
| Reportes Markdown | `%USERPROFILE%\cerberus_reports\` | sin purga | Inmutables |
| Quarantine | `C:\ProgramData\Cerberus\Quarantine\` | sin purga | ACL `SYSTEM:F` exclusivo |
| Logs runtime | `C:\ProgramData\Cerberus\logs\cerberus.log` | rotación diaria, 14 días | JSON estructurado |

## 7. Modos, errores y failsafes

### 7.1 Modos de operación
| Modo | Comportamiento | Caso de uso |
|------|---------------|-------------|
| `dry_run` | Detecta + reporta, no ejecuta acciones | **Default obligatorio en primer arranque** (no se puede cambiar hasta que el operador lo haga explícito), tuning, piloto |
| `monitor` | Detecta + reporta + sugiere acciones | Producción inicial pre-respuesta |
| `auto_critical` | Auto-respuesta solo si `severity=CRITICAL` y `category in [ransomware, c2_active, data_exfil]` | Recomendado producción |
| `auto_all` | Auto-respuesta para HIGH+CRITICAL | Honeypots / entornos hostiles |

Cambio: `cerberus_local.py mode auto_critical` (requiere admin).

### 7.2 Failure boundaries
| Componente | Falla | Resultado |
|------------|-------|-----------|
| Ollama no responde | `ai_analyst` timeout > 10s | `severity = rule_engine.severity_base`; log `WARN ai_offline` |
| Npcap no instalado | `NetCollector.start()` falla | `health.running=False`; resto siguen |
| Permisos insuficientes | `kill_pid` retorna AccessDenied | Fallback `taskkill`; si falla, escala alerta |
| Regla YAML malformada | `RuleEngine.load()` falla | Skip esa regla, log `ERROR rule_invalid` |
| SQLite corrupto | excepción en `events.db` | Backup + recreate, log `CRITICAL` |
| Service crash | excepción no capturada | Windows Service recovery: 10s → 1min → 5min |

### 7.3 Rollback
`actions_log.db` registra comando ejecutado + comando de reversión + timestamp + finding_id.
Comando admin: `cerberus_local.py rollback <action_id>` revierte (ej. `block_ip` → `netsh advfirewall firewall delete rule`).

### 7.4 Kill switch
Archivo señal: `C:\ProgramData\Cerberus\KILLSWITCH`. Si existe, el servicio NO ejecuta acciones (modo `dry_run` forzado). Logueado en cada decisión.

### 7.5 Rate limits
- Máx 10 acciones de respuesta por minuto.
- Máx 1 `isolate_host` por hora.
- Buffer de eventos sin procesar: 10.000 (drop oldest + log si se llena).

### 7.6 Anti-tampering
- Service descriptor con `failure_actions=restart`.
- Watchdog interno: verifica que los 4 collectors emitan ≥1 evento cada 60s; restart 3× si uno muere.
- Checksum del binario al arrancar; si difiere → modo `dry_run` forzado + alerta.
- Cuarentena con ACL `SYSTEM:F` (admin sin acceso sin TakeOwnership).

### 7.7 Observabilidad
- Log JSON: `%PROGRAMDATA%\Cerberus\logs\cerberus.log` (rotado diario, 14 días).
- Métricas: `cerberus_local.py metrics` expone eventos/s, findings/h, latencia p50/p95 de `ai_analyst.triage`, acciones ok/fail.
- Health: Windows Event Log canal `Cerberus/Operational` (integrable con SIEM externo).

## 8. CLI y UX

CLI principal `cerberus_local.py` (estilo HADES):
```
cerberus_local.py start                   # arrancar service (admin)
cerberus_local.py stop                    # detener service
cerberus_local.py status                  # estado actual + health collectors
cerberus_local.py mode <dry_run|monitor|auto_critical|auto_all>
cerberus_local.py findings [--last 24h] [--severity CRITICAL]
cerberus_local.py rollback <action_id>
cerberus_local.py metrics
cerberus_local.py rules reload
cerberus_local.py shell                   # shell interactivo estilo HADES
```

Shell interactivo (`CERBERUS@host ▶`) con tab-completion y comandos cortos (`f` → findings, `m` → metrics).

## 9. Estrategia de testing

### 9.1 Nivel 1 — Unitarios (pytest, sin APIs reales de Windows)
- `RuleEngine.match()` con findings sintéticos
- `PolicyEngine.decide()` con permutaciones de `(severity, category)`
- `OllamaClient.parse_response()` con respuestas válidas/malformadas/timeout
- `Correlator.correlate()` con secuencias sintéticas
- Parsers de cmdline sospechosa, entropía de archivo, regex de IOC
- Coverage objetivo: ≥85% de `cerberus/detection/`, `cerberus/response/policies/`, `cerberus/ai/`

### 9.2 Nivel 2 — Integración (mocks de Windows)
- Collectors con mocks de `psutil`, `win32evtlog`, `pyshark` emiten eventos sintéticos
- Bus + correlator + rule_engine + ai_analyst end-to-end con Ollama real local (`qwen2.5:3b` en CI)
- SQLite: open/close/rotate/recover de corrupción
- Service lifecycle simulado (start/stop sin instalación real)

### 9.3 Nivel 3 — Funcionales (VM Windows aislada, sin red externa)
- Casos: EICAR, PowerShell base64+outbound C2 sintético, ransomware sandbox (rename 100 archivos), brute force login (5+ fallos/30s)
- Verificar: detección + correlación + triage IA + acción ejecutada + reporte + rollback
- Snapshot VM antes de cada caso; restore tras cada test

### 9.4 Nivel 4 — Red team simulado (manual pre-release)
- TTPs MITRE: T1059.001 (PowerShell), T1071.001 (DNS C2), T1486 (Ransomware), T1078 (Valid Accounts), T1543.003 (Service)
- Métricas: % TTPs detectados, MTTD, false positive rate en 24h baseline
- Documentado por release en `tests/redteam_reports/`

### 9.5 Verificación pre-release (gate manual)
1. ✅ Tests N1+N2 green en CI
2. ✅ Tests N3 ejecutados en VM limpia
3. ✅ Instalación limpia + arranque exitoso como Service
4. ✅ Killswitch funcional verificado manualmente
5. ✅ Desinstalación limpia (no deja servicios; quarantine se preserva)
6. ✅ Métricas baseline: CPU < 5%, RAM < 200MB en idle (24h sostenido)
7. ✅ Auditoría de seguridad propia con skill `auditing-security` (OWASP/ASVS aplicable a desktop agents)

### 9.6 CI/CD
- GitHub Actions runner `windows-latest`:
  - N1 + N2 en cada push
  - Lint (`ruff`), tipos (`mypy`), security scan (`bandit`)
- N3 en runner self-hosted Windows (VM disponible), solo en releases / `main`
- Release artifacts: `.msi` firmado (WiX), SBOM, hash SHA256

## 10. Reusos directos desde HADES-LOCAL

Para evitar reinventar:
- `_ollama_candidates()` / `resolve_ollama_base()` → `cerberus/ai/ollama_client.py` (adaptar prioridades Windows-first)
- `ask_hades()` → `OllamaClient.ask()`
- `class C` (color constants) → `cerberus/core/colors.py`
- `log()` family → `cerberus/core/logger.py` (extender a JSON estructurado)
- `run_cmd()` + `run_tool()` → `cerberus/core/proc.py`
- Patrón shell interactivo de `HadesEngine.interactive_shell()` → `cerberus/cli/shell.py`
- PID daemon (`write_pid`, `read_pid`, `stop_agent`) → reemplazado por Windows Service, pero el patrón inspira la verificación de single-instance vía named pipe

## 10.5. Balance heurístico / agéntico (invariante de diseño)

**Compromiso arquitectónico (no negociable sin enmienda explícita al spec):**

> CERBERUS-LOCAL es **≥80% programación heurística** y **≤20% programación agéntica**. La spec v1.0 está en ~95/5 — el LLM ocupa exclusivamente `AIAnalyst.triage()`. Cualquier feature futura que aumente el peso agéntico debe pasar revisión y actualizar este apartado.

### 10.5.1 Componentes heurísticos (deterministas, sin LLM)
- Los 4 collectors (proc, net, fs, evt)
- EventBus, Correlator (ventanas temporales + group-by)
- RuleEngine (YAML Sigma-like: regex, thresholds, condition trees)
- **PolicyEngine — única autoridad que decide acciones**
- ResponseEngine, rollback, rate limits, killswitch, anti-tampering
- Persistencia, Service, CLI, ReportWriter (narrativa heurística por plantilla)

### 10.5.2 Componente agéntico (LLM)
- `AIAnalyst.triage()` — recibe un `Finding` correlacionado, devuelve un `Triage` con `severity` ajustada (±1 nivel respecto a `rule_engine.severity_base`), `family_guess`, `reasoning`, `suggested_actions`.

### 10.5.3 Guardrails irrompibles del LLM
Todas estas restricciones son **invariantes de diseño** verificadas por tests:

1. **El LLM NO ejecuta acciones.** Solo `policy_engine` (heurístico) decide qué se ejecuta. Si el LLM sugiere una acción no contemplada por la policy, se descarta sin opción de override.
2. **El LLM NO modifica `severity` más allá de ±1 nivel** respecto al `severity_base` de la regla heurística. Si el LLM devuelve un salto mayor, se trunca y se loguea `WARN ai_severity_clamped`.
3. **El LLM NO bypassa `dry_run`, `killswitch`, `rate_limits`, ni `policy require_confirmation`.** Estos son chequeos posteriores al LLM en el pipeline.
4. **El LLM NO modifica reglas, policies, ni configuración en disco.** Si una feature futura necesita "propuesta de reglas por IA", el LLM emite candidatas a un buffer `proposed_rules.yml` que un humano debe aprobar manualmente.
5. **Cada output del LLM se valida contra JSON schema.** Respuesta malformada / fuera de schema → ignorada; fallback a `severity = rule_engine.severity_base`, `suggested_actions = []`.
6. **El LLM falla → el sistema sigue.** Timeout o error de Ollama no detiene detección ni respuesta heurística (severidad cae a `severity_base`).
7. **Cualquier finding ejecutado tiene trazabilidad heurística completa.** En `findings.db` se persiste `rule_id` que disparó el finding y `policy_id` que autorizó la acción. El campo `ai_triage` es complementario, no causal.

### 10.5.4 Métrica de verificación
En cada release el equipo verifica:
- % de findings que fueron disparados por reglas heurísticas (objetivo: 100%)
- % de acciones ejecutadas autorizadas por policy heurística (objetivo: 100%)
- % de severidades finales donde |`ai_severity` − `severity_base`| ≤ 1 (objetivo: 100%, enforcement por clamp)

Si cualquiera de estas métricas baja de 100% → bug crítico, no se libera.

## 11. Aviso legal

CERBERUS-LOCAL es software defensivo y se despliega únicamente en hosts propios o con autorización escrita del propietario. Su capacidad de respuesta automática (kill, firewall, isolate) puede causar interrupciones operativas; **el modo `dry_run` es el default obligatorio en primer arranque**. El autor no se responsabiliza por uso indebido o despliegues sin pruebas en VM aislada previas.

## 12. Próximos pasos

1. Self-review de este spec (placeholders, contradicciones, ambigüedad, scope).
2. Revisión y aprobación por el usuario.
3. Invocar skill `writing-plans` para generar el plan de implementación detallado por hitos.
4. Antes de codear: invocar `using-context7` para versiones actuales y APIs de `psutil`, `pyshark`, `watchdog`, `pywin32`, `win32evtlog`.
5. Antes de mergear: invocar `auditing-security` para auditoría OWASP/ASVS del agente.
