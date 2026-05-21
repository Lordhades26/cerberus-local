from pathlib import Path

import pytest

from cerberus.core.config import CerberusConfig, load_config


def test_load_default_config(tmp_path: Path):
    cfg_file = tmp_path / "c.yml"
    cfg_file.write_text(
        """
mode: dry_run
host_name: null
paths:
  data_dir: /tmp/cerberus
  events_db: /tmp/cerberus/events.db
  reports_dir: /tmp/cerberus_reports
  log_file: /tmp/cerberus.log
collectors:
  proc:
    enabled: true
    poll_interval_seconds: 1.0
reporting:
  interval_seconds: 300
  retention_days: 7
"""
    )
    cfg = load_config(cfg_file)
    assert isinstance(cfg, CerberusConfig)
    assert cfg.mode == "dry_run"
    assert cfg.collectors.proc.poll_interval_seconds == 1.0
    assert cfg.reporting.retention_days == 7


def test_invalid_mode_raises(tmp_path: Path):
    cfg_file = tmp_path / "c.yml"
    cfg_file.write_text("mode: nuke_everything\npaths: {}\ncollectors: {}\nreporting: {}\n")
    with pytest.raises(ValueError):
        load_config(cfg_file)


def test_host_name_autodetected_when_null(tmp_path: Path):
    cfg_file = tmp_path / "c.yml"
    cfg_file.write_text(
        """
mode: dry_run
host_name: null
paths: {data_dir: /tmp/c, events_db: /tmp/c.db, reports_dir: /tmp/r, log_file: /tmp/l}
collectors: {proc: {enabled: true, poll_interval_seconds: 1.0}}
reporting: {interval_seconds: 60, retention_days: 1}
"""
    )
    cfg = load_config(cfg_file)
    assert cfg.host_name
    assert isinstance(cfg.host_name, str)
