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


def test_load_m2_collectors_and_correlator(tmp_path):
    from pathlib import Path
    cfg_file = tmp_path / "c.yml"
    cfg_file.write_text(
        """
mode: dry_run
host_name: null
paths:
  data_dir: /tmp/cerberus
  events_db: /tmp/cerberus/events.db
  findings_db: /tmp/cerberus/findings.db
  reports_dir: /tmp/cerberus_reports
  log_file: /tmp/cerberus.log
collectors:
  proc: {enabled: true, poll_interval_seconds: 1.0}
  net:
    enabled: true
    poll_interval_seconds: 2.0
    beaconing_window_seconds: 60
    beaconing_min_connections: 10
  fs:
    enabled: true
    watch_paths: ["/tmp/watch"]
    mass_rename_threshold: 20
    mass_rename_window_seconds: 5
    high_entropy_threshold: 7.5
  evt:
    enabled: true
    channels: ["Security"]
correlator:
  window_seconds: 10
  min_sources_for_finding: 2
reporting:
  interval_seconds: 300
  retention_days: 7
""",
        encoding="utf-8",
    )
    from cerberus.core.config import load_config
    cfg = load_config(cfg_file)
    assert cfg.paths.findings_db == Path("/tmp/cerberus/findings.db")
    assert cfg.collectors.net.beaconing_min_connections == 10
    assert cfg.collectors.fs.watch_paths == [Path("/tmp/watch")]
    assert cfg.collectors.fs.high_entropy_threshold == 7.5
    assert cfg.collectors.evt.channels == ["Security"]
    assert cfg.correlator.window_seconds == 10
    assert cfg.correlator.min_sources_for_finding == 2


def test_m2_collectors_have_defaults_when_absent(tmp_path):
    cfg_file = tmp_path / "c.yml"
    cfg_file.write_text(
        """
mode: dry_run
host_name: null
paths:
  data_dir: /tmp/c
  events_db: /tmp/c.db
  findings_db: /tmp/f.db
  reports_dir: /tmp/r
  log_file: /tmp/l
collectors: {proc: {enabled: true, poll_interval_seconds: 1.0}}
reporting: {interval_seconds: 60, retention_days: 1}
""",
        encoding="utf-8",
    )
    from cerberus.core.config import load_config
    cfg = load_config(cfg_file)
    # net/fs/evt/correlator ausentes -> defaults razonables, enabled segun default
    assert cfg.collectors.net.enabled is True
    assert cfg.collectors.fs.mass_rename_threshold == 20
    assert cfg.collectors.evt.channels  # lista no vacia por defecto
    assert cfg.correlator.window_seconds == 10
