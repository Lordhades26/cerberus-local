from pathlib import Path

import yaml

from cerberus.response.policy_engine import PolicyEngine

_DIR = Path(__file__).resolve().parents[2] / "policies"


def test_default_policies_all_load():
    eng = PolicyEngine(_DIR)
    assert eng.load() == 5


def test_default_policy_ids_unique():
    ids = [yaml.safe_load(p.read_text(encoding="utf-8"))["id"]
           for p in sorted(_DIR.glob("*.yml"))]
    assert len(ids) == len(set(ids))


def test_high_blast_actions_require_confirmation():
    for p in sorted(_DIR.glob("*.yml")):
        raw = yaml.safe_load(p.read_text(encoding="utf-8"))
        acts = set(raw.get("actions", []))
        if acts & {"isolate_host", "disable_user"}:
            assert raw.get("require_confirmation") is True, p.name
