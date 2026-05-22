from pathlib import Path

from cerberus.detection.rule_engine import RuleEngine

_RULES_DIR = Path(__file__).resolve().parents[2] / "rules"


def test_default_rules_all_load():
    eng = RuleEngine(_RULES_DIR)
    count = eng.load()
    assert count == 5  # ransomware, powershell, beaconing, brute_force, suspicious_dns


def test_default_rules_ids_unique():
    import yaml
    ids = []
    for p in sorted(_RULES_DIR.glob("*.yml")):
        ids.append(yaml.safe_load(p.read_text(encoding="utf-8"))["id"])
    assert len(ids) == len(set(ids))
