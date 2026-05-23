import pytest

from cerberus.dashboard.loadgen import run_load


@pytest.mark.asyncio
async def test_load_pipeline_real_components(tmp_path):
    # 100 procesos sintéticos x 3 eventos = 300 eventos por el pipeline REAL (dry_run).
    res = await run_load(tmp_path, n_pids=100, mode="dry_run")
    # correctitud
    assert res.events == 300
    assert res.findings == 100            # un finding correlacionado por pid
    assert res.actions_logged > 0         # policies dispararon acciones (dry_run, registradas)
    # rendimiento: debe procesarse rápido (cota generosa para CI)
    assert res.elapsed_s < 15.0
    assert res.events_per_s > 50.0


@pytest.mark.asyncio
async def test_load_pipeline_dry_run_executes_nothing(tmp_path):
    # En dry_run ninguna acción se ejecuta de verdad (todas registradas como dry_run).
    from cerberus.response.action_store import ActionStore
    await run_load(tmp_path, n_pids=20, mode="dry_run")
    ac = ActionStore(tmp_path / "actions.db")
    ac.init_schema()
    rows = ac.fetch_recent(limit=100000)
    ac.close()
    assert rows
    assert all(r["executed"] == 0 for r in rows)
    assert all(r["reason"] == "dry_run" for r in rows)
