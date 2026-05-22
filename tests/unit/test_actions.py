import json

from cerberus.response.actions import Action, ActionReport, ActionResult, PolicyDecision

_VALID = {"kill_pid", "quarantine", "block_ip", "stop_service", "isolate_host", "disable_user"}


def test_action_types_constant():
    assert Action.VALID_TYPES == _VALID


def test_action_rejects_unknown_type():
    import pytest
    with pytest.raises(ValueError):
        Action(type="format_disk", params={})


def test_action_result_to_dict_serializable():
    a = Action(type="kill_pid", params={"pid": 1234})
    r = ActionResult(action=a, executed=False, success=False, output="",
                     command="taskkill /F /T /PID 1234", reverted_command=None,
                     reason="dry_run")
    d = r.to_dict()
    assert d["action_type"] == "kill_pid"
    assert d["params"] == {"pid": 1234}
    assert d["executed"] is False
    assert d["reason"] == "dry_run"
    json.dumps(d)


def test_policy_decision_carries_metadata():
    a = Action(type="block_ip", params={"ip": "9.9.9.9"})
    d = PolicyDecision(action=a, policy_id="c2_response", require_confirmation=False)
    assert d.policy_id == "c2_response"
    assert d.require_confirmation is False


def test_action_report_aggregates():
    a = Action(type="kill_pid", params={"pid": 1})
    r = ActionResult(action=a, executed=True, success=True, output="ok",
                     command="x", reverted_command=None, reason="authorized")
    rep = ActionReport(finding_id="F1", mode="auto_all", results=[r])
    assert rep.finding_id == "F1"
    assert rep.executed_count == 1
