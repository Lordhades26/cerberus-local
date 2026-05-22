from pathlib import Path

from cerberus.core.runtime_state import RuntimeState


def test_get_mode_default_when_missing(tmp_path: Path):
    rs = RuntimeState(tmp_path / "state.json")
    assert rs.get_mode(default="dry_run") == "dry_run"


def test_set_then_get_mode(tmp_path: Path):
    rs = RuntimeState(tmp_path / "state.json")
    rs.set_mode("auto_critical")
    assert rs.get_mode(default="dry_run") == "auto_critical"
    rs2 = RuntimeState(tmp_path / "state.json")
    assert rs2.get_mode(default="dry_run") == "auto_critical"


def test_set_mode_rejects_invalid(tmp_path: Path):
    import pytest
    rs = RuntimeState(tmp_path / "state.json")
    with pytest.raises(ValueError):
        rs.set_mode("nuke")


def test_corrupt_state_falls_back_to_default(tmp_path: Path):
    p = tmp_path / "state.json"
    p.write_text("{not json", encoding="utf-8")
    rs = RuntimeState(p)
    assert rs.get_mode(default="monitor") == "monitor"
