from pathlib import Path

from cerberus.core.event import Event, Severity
from cerberus.core.finding import Finding
from cerberus.detection.rule_engine import RuleEngine


def _ev(source, type_, **ind):
    return Event(source=source, type=type_, host="H", pid=10, user="u",
                 raw={}, indicators=ind)


def _finding(events):
    return Finding.from_cluster(host="H", pid=10, user="u", evidence=events)


def _write_rule(d: Path, name: str, text: str) -> None:
    (d / name).write_text(text, encoding="utf-8")


def test_load_counts_valid_rules(tmp_path: Path):
    _write_rule(tmp_path, "r1.yml", """
id: r1
severity: HIGH
category: test
condition:
  mode: any
  clauses:
    - {source: proc, type: new_process}
""")
    eng = RuleEngine(tmp_path)
    assert eng.load() == 1


def test_match_all_mode_requires_every_clause(tmp_path: Path):
    _write_rule(tmp_path, "ransom.yml", """
id: ransomware_v1
severity: CRITICAL
category: ransomware
condition:
  mode: all
  clauses:
    - source: fs
      type: mass_rename
      count_indicator: {name: rename_count, min: 20}
    - source: proc
      type: new_process
      cmdline_regex: "(?i)(powershell|cmd).+(-enc|frombase64)"
""")
    eng = RuleEngine(tmp_path)
    eng.load()
    # casa: mass_rename con 30 + powershell -enc
    f = _finding([
        _ev("fs", "mass_rename", rename_count=30),
        _ev("proc", "new_process", cmdline="powershell -enc AAAA"),
    ])
    matches = eng.match(f)
    assert len(matches) == 1
    assert matches[0].rule_id == "ransomware_v1"
    assert matches[0].severity == Severity.CRITICAL
    assert matches[0].category == "ransomware"


def test_match_all_mode_fails_if_threshold_not_met(tmp_path: Path):
    _write_rule(tmp_path, "ransom.yml", """
id: ransomware_v1
severity: CRITICAL
category: ransomware
condition:
  mode: all
  clauses:
    - {source: fs, type: mass_rename, count_indicator: {name: rename_count, min: 20}}
    - {source: proc, type: new_process, cmdline_regex: "-enc"}
""")
    eng = RuleEngine(tmp_path)
    eng.load()
    f = _finding([
        _ev("fs", "mass_rename", rename_count=5),   # < 20
        _ev("proc", "new_process", cmdline="powershell -enc AAAA"),
    ])
    assert eng.match(f) == []


def test_match_any_mode(tmp_path: Path):
    _write_rule(tmp_path, "beacon.yml", """
id: beacon_v1
severity: MEDIUM
category: c2
condition:
  mode: any
  clauses:
    - {source: net, type: beaconing_suspect}
""")
    eng = RuleEngine(tmp_path)
    eng.load()
    f = _finding([_ev("net", "beaconing_suspect", remote_ip="9.9.9.9")])
    matches = eng.match(f)
    assert len(matches) == 1 and matches[0].rule_id == "beacon_v1"


def test_malformed_rule_is_skipped(tmp_path: Path):
    _write_rule(tmp_path, "good.yml", """
id: good
severity: LOW
category: t
condition: {mode: any, clauses: [{source: proc, type: new_process}]}
""")
    _write_rule(tmp_path, "bad.yml", "id: bad\nseverity: NOPE\ncondition: {}\n")
    eng = RuleEngine(tmp_path)
    assert eng.load() == 1  # solo la buena


def test_reload_picks_up_new_rules(tmp_path: Path):
    eng = RuleEngine(tmp_path)
    assert eng.load() == 0
    _write_rule(tmp_path, "r.yml", """
id: r
severity: LOW
category: t
condition: {mode: any, clauses: [{source: proc, type: new_process}]}
""")
    assert eng.reload() == 1
