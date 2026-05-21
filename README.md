# CERBERUS-LOCAL

EDR híbrido Windows con IA local Ollama. Fork defensivo de HADES-LOCAL.

**Estado:** M1 — esqueleto + ProcCollector (sin detección, sin respuesta).

## Quickstart

```bash
python -m venv .venv
.venv\Scripts\activate    # Windows
pip install -e ".[dev]"
python cerberus_local.py version
python cerberus_local.py start --dry-run
```

Ver `docs/superpowers/specs/2026-05-21-cerberus-local-edr-design.md` para el diseño completo.
