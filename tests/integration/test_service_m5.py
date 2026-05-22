import dataclasses

import pytest

from cerberus.core.event import Event, Severity
from cerberus.core.finding import Finding
from cerberus.core.runtime_state import RuntimeState
from cerberus.response.action_store import ActionStore
from cerberus.response.actions import Action, ActionResult, PolicyDecision
from cerberus.response.engine import ResponseEngine
from cerberus.response.rate_limiter import RateLimiter
from cerberus.service.integrity import IntegrityVerifier
from cerberus.service.ipc import InMemoryTransport, IpcClient, IpcDispatcher, IpcServer


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


def _engine(tmp_path, mode):
    store = ActionStore(tmp_path / "a.db")
    store.init_schema()
    ex = _FakeExecutor()
    eng = ResponseEngine(
        policy_engine=_FakePolicy(), executor=ex, action_store=store,
        rate_limiter=RateLimiter(10, 1), mode=mode, killswitch_path=tmp_path / "KS",
        auto_critical_categories=frozenset({"mass_rename"}))
    return eng, ex


@pytest.mark.asyncio
async def test_m5_hot_mode_via_ipc_changes_execution(tmp_path):
    eng, ex = _engine(tmp_path, "dry_run")
    rs = RuntimeState(tmp_path / "state.json")
    transport = InMemoryTransport()
    d = IpcDispatcher()

    def set_mode(args):
        rs.set_mode(args["mode"])
        eng.set_mode(args["mode"])
        return {"mode": args["mode"]}

    d.register("mode", set_mode)
    server = IpcServer(transport, d)
    server.start()
    client = IpcClient(transport)

    await eng.handle(_finding())
    assert ex.runs == 0                       # dry_run
    resp = client.request("mode", mode="auto_all")
    assert resp["ok"] and resp["data"]["mode"] == "auto_all"
    await eng.handle(_finding())
    assert ex.runs == 1                       # tras IPC hot-switch, ejecuta
    assert rs.get_mode(default="dry_run") == "auto_all"
    server.stop()


def test_m5_integrity_snapshot_and_tamper_detection(tmp_path):
    (tmp_path / "cerberus").mkdir()
    (tmp_path / "cerberus" / "x.py").write_text("a = 1", encoding="utf-8")
    v = IntegrityVerifier()
    manifest = v.build_manifest(tmp_path)
    assert v.verify(tmp_path, manifest).ok is True
    (tmp_path / "cerberus" / "x.py").write_text("a = 2", encoding="utf-8")
    assert v.verify(tmp_path, manifest).ok is False
