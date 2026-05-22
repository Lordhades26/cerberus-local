import dataclasses

import pytest

from cerberus.core.event import Event, Severity
from cerberus.core.finding import Finding
from cerberus.response.action_store import ActionStore
from cerberus.response.actions import Action, ActionResult, PolicyDecision
from cerberus.response.engine import ResponseEngine
from cerberus.response.rate_limiter import RateLimiter


class _FakePolicy:
    def decide(self, finding):
        return [PolicyDecision(Action("kill_pid", {"pid": 1}), "p1", False)]


class _FakeExecutor:
    def __init__(self):
        self.runs = 0

    def build(self, action):
        from cerberus.response.executor import _Built
        return _Built("CMD", "REV", True, "ok")

    def run(self, action):
        self.runs += 1
        return ActionResult(action=action, executed=True, success=True, output="",
                            command="CMD", reverted_command="REV", reason="authorized")


def _finding():
    evs = [Event(source="fs", type="mass_rename", host="H", pid=1, user="u",
                 raw={}, indicators={})]
    f = Finding.from_cluster(host="H", pid=1, user="u", evidence=evs)
    return dataclasses.replace(f, severity=Severity.CRITICAL, severity_base=Severity.CRITICAL)


def _engine(tmp_path, mode, executor):
    store = ActionStore(tmp_path / "a.db")
    store.init_schema()
    return ResponseEngine(
        policy_engine=_FakePolicy(), executor=executor, action_store=store,
        rate_limiter=RateLimiter(10, 1), mode=mode,
        killswitch_path=tmp_path / "KS",
        auto_critical_categories=frozenset({"mass_rename"}),
    )


@pytest.mark.asyncio
async def test_set_mode_changes_gate_behavior(tmp_path):
    ex = _FakeExecutor()
    eng = _engine(tmp_path, "dry_run", ex)
    await eng.handle(_finding())
    assert ex.runs == 0          # dry_run no ejecuta
    eng.set_mode("auto_all")
    await eng.handle(_finding())
    assert ex.runs == 1          # tras hot-switch, ejecuta


def test_set_mode_rejects_invalid(tmp_path):
    eng = _engine(tmp_path, "dry_run", _FakeExecutor())
    with pytest.raises(ValueError):
        eng.set_mode("nuke")


def test_mode_property_reflects_current(tmp_path):
    eng = _engine(tmp_path, "monitor", _FakeExecutor())
    assert eng.mode == "monitor"
    eng.set_mode("auto_critical")
    assert eng.mode == "auto_critical"
