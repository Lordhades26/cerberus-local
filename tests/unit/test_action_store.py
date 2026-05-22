from pathlib import Path

import pytest

from cerberus.response.action_store import ActionStore
from cerberus.response.actions import Action, ActionResult


@pytest.fixture
def store(tmp_path: Path) -> ActionStore:
    s = ActionStore(tmp_path / "actions_log.db")
    s.init_schema()
    return s


def _result(executed=True, reverted="netsh ... delete"):
    a = Action(type="block_ip", params={"ip": "9.9.9.9"})
    return ActionResult(action=a, executed=executed, success=executed, output="ok",
                        command="netsh ... add", reverted_command=reverted,
                        reason="authorized")


def test_init_creates_table(store):
    assert store.table_exists("actions_log")


def test_insert_and_fetch_by_id(store):
    r = _result()
    aid = store.insert(r, finding_id="F1", policy_id="c2_response", mode="auto_all")
    row = store.fetch_by_id(aid)
    assert row is not None
    assert row["finding_id"] == "F1"
    assert row["policy_id"] == "c2_response"
    assert row["action_type"] == "block_ip"
    assert row["params"] == {"ip": "9.9.9.9"}
    assert row["executed"] == 1
    assert row["reverted_command"] == "netsh ... delete"


def test_fetch_recent_orders_desc(store):
    store.insert(_result(), finding_id="F1", policy_id="p", mode="auto_all")
    store.insert(_result(), finding_id="F2", policy_id="p", mode="auto_all")
    recent = store.fetch_recent(limit=10)
    assert len(recent) == 2


def test_fetch_by_id_missing_returns_none(store):
    assert store.fetch_by_id("nope") is None
