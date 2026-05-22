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
    store = ActionStore(tmp_path / "actions.db")
    store.init_schema()
    pe = PolicyEngine(_POLICIES)
    pe.load()
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
    # casan para un finding CRITICAL con mass_rename/new_process; ninguno ejecutado
    types = {r["action_type"] for r in rows}
    assert {"kill_pid", "quarantine", "block_ip", "isolate_host"} <= types


@pytest.mark.asyncio
async def test_m4_auto_critical_executes_via_mocked_executor(tmp_path):
    eng, store = _engine(tmp_path, "auto_critical")
    with patch("cerberus.response.executor.subprocess.run") as mrun, \
         patch("cerberus.response.executor.psutil.Process"), \
         patch("cerberus.response.executor.shutil.move"):
        mrun.return_value = MagicMock(returncode=0, stdout="ok", stderr="")
        report = await eng.handle(_ransomware_finding(tmp_path))
    assert report.executed_count >= 1
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
