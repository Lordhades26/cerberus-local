import dataclasses
from pathlib import Path

from cerberus.core.event import Event, Severity
from cerberus.core.finding import Finding
from cerberus.response.policy_engine import PolicyEngine


def _ev(source, type_, **ind):
    return Event(source=source, type=type_, host="H", pid=4892, user="DESK\\u",
                 raw={}, indicators=ind)


def _finding(severity, categories_events, ai_suggested=None):
    f = Finding.from_cluster(host="H", pid=4892, user="DESK\\u", evidence=categories_events)
    return dataclasses.replace(
        f, severity=severity, severity_base=severity,
        ai_triage={"suggested_actions": ai_suggested or [], "severity": int(severity)},
    )


def _write(d: Path, name: str, text: str) -> None:
    (d / name).write_text(text, encoding="utf-8")


def test_load_counts(tmp_path):
    _write(tmp_path, "p.yml", """
id: p1
match: {severity_min: HIGH, categories: [execution]}
require_confirmation: true
actions: [kill_pid]
""")
    eng = PolicyEngine(tmp_path)
    assert eng.load() == 1


def test_decide_no_match_when_category_absent(tmp_path):
    _write(tmp_path, "ransom.yml", """
id: ransomware_response
match: {severity_min: CRITICAL, categories: [ransomware]}
require_confirmation: false
actions: [kill_pid, block_ip]
""")
    eng = PolicyEngine(tmp_path)
    eng.load()
    evs = [_ev("proc", "new_process"), _ev("net", "outbound_conn", remote_ip="9.9.9.9"),
           _ev("fs", "mass_rename")]
    f = _finding(Severity.CRITICAL, evs)
    # categories del finding son tipos de evento; 'ransomware' no esta -> no casa
    assert eng.decide(f) == []


def test_decide_category_matches_event_type(tmp_path):
    _write(tmp_path, "c2.yml", """
id: c2_response
match: {severity_min: MEDIUM, categories: [beaconing_suspect]}
require_confirmation: false
actions: [block_ip]
""")
    eng = PolicyEngine(tmp_path)
    eng.load()
    evs = [_ev("net", "beaconing_suspect", remote_ip="9.9.9.9"), _ev("proc", "new_process")]
    f = _finding(Severity.HIGH, evs)
    decisions = eng.decide(f)
    assert len(decisions) == 1
    assert decisions[0].policy_id == "c2_response"
    assert decisions[0].action.type == "block_ip"
    assert decisions[0].action.params == {"ip": "9.9.9.9"}


def test_decide_skips_action_with_unresolvable_params(tmp_path):
    _write(tmp_path, "c2.yml", """
id: c2_response
match: {severity_min: MEDIUM, categories: []}
require_confirmation: false
actions: [block_ip]
""")
    eng = PolicyEngine(tmp_path)
    eng.load()
    f = _finding(Severity.HIGH, [_ev("proc", "new_process")])
    assert eng.decide(f) == []


def test_decide_ignores_ai_suggested_actions(tmp_path):
    _write(tmp_path, "exec.yml", """
id: execution_response
match: {severity_min: HIGH, categories: []}
require_confirmation: true
actions: [kill_pid]
""")
    eng = PolicyEngine(tmp_path)
    eng.load()
    f = _finding(Severity.HIGH, [_ev("proc", "new_process")],
                 ai_suggested=["isolate_host", "format_disk", "disable_user"])
    decisions = eng.decide(f)
    types = {d.action.type for d in decisions}
    assert types == {"kill_pid"}
    assert decisions[0].require_confirmation is True


def test_malformed_policy_skipped(tmp_path):
    _write(tmp_path, "bad.yml", "id: bad\nmatch: {severity_min: NOPE}\nactions: []\n")
    _write(tmp_path, "good.yml", """
id: good
match: {severity_min: LOW, categories: []}
require_confirmation: false
actions: [kill_pid]
""")
    eng = PolicyEngine(tmp_path)
    assert eng.load() == 1
