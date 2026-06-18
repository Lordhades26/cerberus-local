import dataclasses

import pytest

from cerberus.core.event import Event, Severity
from cerberus.core.finding import Finding
from cerberus.response.action_store import ActionStore
from cerberus.response.actions import Action, ActionResult, PolicyDecision
from cerberus.response.engine import ResponseEngine
from cerberus.response.rate_limiter import RateLimiter


def _finding(severity=Severity.CRITICAL, categories=("mass_rename",), pid=4892, rule_cats=()):
    evs = [Event(source="fs", type=c, host="H", pid=pid, user="u", raw={}, indicators={})
           for c in categories]
    f = Finding.from_cluster(host="H", pid=pid, user="u", evidence=evs)
    return dataclasses.replace(f, severity=severity, severity_base=severity, rule_categories=rule_cats)


class _FakePolicy:
    def __init__(self, decisions):
        self._d = decisions

    def decide(self, finding):
        return self._d


class _FakeExecutor:
    def __init__(self):
        self.run_calls = []

    def build(self, action):
        from cerberus.response.executor import _Built
        return _Built(command="CMD", reverted_command="REV", valid=True, reason="ok")

    def run(self, action):
        self.run_calls.append(action)
        return ActionResult(action=action, executed=True, success=True, output="ok",
                            command="CMD", reverted_command="REV", reason="authorized")


def _engine(tmp_path, mode, decisions, executor=None, killswitch=False):
    store = ActionStore(tmp_path / "a.db")
    store.init_schema()
    ks = tmp_path / "KILLSWITCH"
    if killswitch:
        ks.write_text("x", encoding="utf-8")
    return ResponseEngine(
        policy_engine=_FakePolicy(decisions),
        executor=executor or _FakeExecutor(),
        action_store=store,
        rate_limiter=RateLimiter(10, 1),
        mode=mode,
        killswitch_path=ks,
        auto_critical_categories=frozenset({"ransomware", "mass_rename", "c2", "data_exfil"}),
    ), store


def _dec(type_="kill_pid", confirm=False, pid=4892):
    return PolicyDecision(action=Action(type=type_, params={"pid": pid}),
                          policy_id="p1", require_confirmation=confirm)


@pytest.mark.asyncio
async def test_dry_run_never_executes_but_logs(tmp_path):
    ex = _FakeExecutor()
    eng, store = _engine(tmp_path, "dry_run", [_dec()], executor=ex)
    report = await eng.handle(_finding())
    assert ex.run_calls == []
    assert report.executed_count == 0
    row = store.fetch_recent()[0]
    assert row["executed"] == 0 and row["reason"] == "dry_run"
    assert row["command"] == "CMD"


@pytest.mark.asyncio
async def test_monitor_never_executes(tmp_path):
    ex = _FakeExecutor()
    eng, _ = _engine(tmp_path, "monitor", [_dec()], executor=ex)
    await eng.handle(_finding())
    assert ex.run_calls == []


@pytest.mark.asyncio
async def test_killswitch_forces_no_exec(tmp_path):
    ex = _FakeExecutor()
    eng, store = _engine(tmp_path, "auto_all", [_dec()], executor=ex, killswitch=True)
    await eng.handle(_finding(severity=Severity.CRITICAL))
    assert ex.run_calls == []
    assert store.fetch_recent()[0]["reason"] == "killswitch"


@pytest.mark.asyncio
async def test_auto_critical_executes_on_critical_matching_category(tmp_path):
    ex = _FakeExecutor()
    eng, _ = _engine(tmp_path, "auto_critical", [_dec()], executor=ex)
    await eng.handle(_finding(severity=Severity.CRITICAL, categories=("mass_rename",)))
    assert len(ex.run_calls) == 1


@pytest.mark.asyncio
async def test_auto_critical_skips_non_matching_category(tmp_path):
    ex = _FakeExecutor()
    eng, store = _engine(tmp_path, "auto_critical", [_dec()], executor=ex)
    await eng.handle(_finding(severity=Severity.CRITICAL, categories=("new_process",)))
    assert ex.run_calls == []
    assert store.fetch_recent()[0]["reason"] == "mode_gate"


@pytest.mark.asyncio
async def test_require_confirmation_blocks_auto(tmp_path):
    ex = _FakeExecutor()
    eng, store = _engine(tmp_path, "auto_all", [_dec(confirm=True)], executor=ex)
    await eng.handle(_finding(severity=Severity.CRITICAL))
    assert ex.run_calls == []
    assert store.fetch_recent()[0]["reason"] == "require_confirmation"


@pytest.mark.asyncio
async def test_rate_limit_blocks_excess(tmp_path):
    ex = _FakeExecutor()
    store = ActionStore(tmp_path / "a.db")
    store.init_schema()
    ks = tmp_path / "KILLSWITCH"
    eng = ResponseEngine(
        policy_engine=_FakePolicy([_dec(pid=i) for i in range(5)]),
        executor=ex, action_store=store,
        rate_limiter=RateLimiter(max_actions_per_minute=2, max_isolate_per_hour=1),
        mode="auto_all", killswitch_path=ks,
        auto_critical_categories=frozenset(),
    )
    await eng.handle(_finding(severity=Severity.CRITICAL))
    assert len(ex.run_calls) == 2
    reasons = [r["reason"] for r in store.fetch_recent(limit=10)]
    assert reasons.count("rate_limited") == 3


@pytest.mark.asyncio
async def test_only_policy_decides_not_ai(tmp_path):
    ex = _FakeExecutor()
    eng, store = _engine(tmp_path, "auto_all", [_dec(type_="kill_pid")], executor=ex)
    f = _finding(severity=Severity.CRITICAL)
    f = dataclasses.replace(f, ai_triage={"suggested_actions": ["isolate_host", "disable_user"]})
    await eng.handle(f)
    assert [a.type for a in ex.run_calls] == ["kill_pid"]


@pytest.mark.asyncio
async def test_auto_critical_matches_on_rule_category(tmp_path):
    ex = _FakeExecutor()
    eng, _ = _engine(tmp_path, "auto_critical", [_dec()], executor=ex)
    # new_process no está en auto_critical_categories, pero ransomware sí
    f = _finding(severity=Severity.HIGH, categories=("new_process",), rule_cats=("ransomware",))
    await eng.handle(f)
    assert len(ex.run_calls) == 1
