# CERBERUS-LOCAL — M3 (Detección: RuleEngine + AIAnalyst)

EDR híbrido Windows con IA local Ollama. Fork defensivo de HADES-LOCAL.

**Hito actual:** M3 — detección heurística + triage IA consultivo. Cada finding
recibe `severity_base` y `rule_ids` del RuleEngine y un `ai_triage` del AIAnalyst
(Ollama). **Sin respuesta automática** (PolicyEngine/ResponseEngine van a M4);
sigue en `monitor`/`dry_run`.

## Componentes en M3 (sobre M1+M2)

- `RuleEngine` (YAML Sigma-like) → `severity_base` + `rule_ids` por finding (autoridad causal)
- `OllamaClient` (urllib, autodetect, retry) → `POST /api/generate`, JSON mode
- `AIAnalyst` (único componente LLM, consultivo) → `Triage` con clamp ±1, fallback a base, función pura
- `DetectionPipeline` → RuleEngine → AIAnalyst → `Finding` enriquecido
- Reglas por defecto en `rules/*.yml`; prompt versionado en `prompts/triage.md`
- `findings.db` ahora persiste `severity_base`, `rule_ids` (causal) y `ai_triage` (complementario)

Heredado de M1+M2: `ProcCollector`/`NetCollector`/`FsCollector`/`EvtCollector`,
`EventBus`, `Correlator`, `EventStore`, reporte Markdown, CLI.

### Guardrails del LLM (§10.5.3) — verificados por tests
G1 no ejecuta acciones · G2 clamp ±1 sobre `severity_base` · G4 no escribe disco/reglas/config ·
G5 schema inválido → fallback a `severity_base` · G6 Ollama caído → el sistema sigue ·
G7 trazabilidad: `rule_ids`+`severity_base` (causal) y `ai_triage` (complementario) persistidos.
G3 (no bypassar dry_run/killswitch/rate_limits) es N/A en M3 (no hay respuesta); se hereda en M4.

## Configuración IA (`config/cerberus.default.yml`)

```yaml
detection:
  rule_engine: {enabled: true, rules_dir: "rules"}
  ai_analyst:
    enabled: true
    model: "qwen2.5-coder:14b"   # configurable; requiere Ollama local
    base_url: null               # null = autodetect (env / 127.0.0.1:11434 / host.docker.internal)
    timeout_seconds: 20.0
    max_severity_delta: 1        # límite duro del ajuste de severidad por la IA
```

Si Ollama no está disponible, el sistema sigue: la severidad cae a `severity_base`
(heurística) y `ai_triage` queda con `reasoning="ai_unavailable"`.

## Quickstart

```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -e ".[dev]"
pip install -e ".[windows]"      # opcional, EvtCollector real en Windows

python cerberus_local.py version  # cerberus-local 0.3.0
python cerberus_local.py status   # conteos + estado de collectors
python cerberus_local.py start    # foreground, Ctrl+C para detener
```

## Tests

```powershell
.venv\Scripts\python -m pytest               # suite completa con coverage (gate >=85%)
.venv\Scripts\python -m pytest tests/integration/test_ollama_live.py   # opcional; usa Ollama real, se salta si :11434 no responde
.venv\Scripts\python -m ruff check .
.venv\Scripts\python -m mypy cerberus cerberus_local.py
```

Estado actual: **103 tests verdes, cobertura 91.50%, ruff y mypy (strict) limpios.**

## Próximos hitos

- **M4** — `PolicyEngine` + `ResponseEngine` (kill/quarantine/block_ip/isolate/disable_user/stop_service) + rollback + `auto_critical`/`auto_all` + killswitch + rate limits
- **M5** — Windows Service, named pipe IPC, `.msi`, anti-tampering, redteam tests, pyshark/`dns_query`

Ver `docs/superpowers/specs/2026-05-21-cerberus-local-edr-design.md` y `docs/superpowers/plans/`.

## Aviso legal

CERBERUS-LOCAL es software defensivo; sólo en hosts propios o con autorización escrita.
El triage IA es **consultivo**: nunca decide ni ejecuta acciones (eso es exclusivamente
heurístico, desde M4). En M4 el modo `dry_run` será obligatorio en primer arranque.
