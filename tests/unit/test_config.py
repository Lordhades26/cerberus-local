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


def test_load_detection_config(tmp_path):
    cfg_file = tmp_path / "c.yml"
    cfg_file.write_text(
        """
mode: dry_run
host_name: null
paths:
  data_dir: /tmp/c
  events_db: /tmp/c/e.db
  findings_db: /tmp/c/f.db
  reports_dir: /tmp/c/r
  log_file: /tmp/c/l.log
collectors: {proc: {enabled: true, poll_interval_seconds: 1.0}}
detection:
  rule_engine: {enabled: true, rules_dir: rules}
  ai_analyst:
    enabled: true
    model: qwen2.5-coder:14b
    base_url: null
    timeout_seconds: 20.0
    max_severity_delta: 1
reporting: {interval_seconds: 60, retention_days: 1}
""",
        encoding="utf-8",
    )
    from cerberus.core.config import load_config
    cfg = load_config(cfg_file)
    assert cfg.detection.rule_engine.enabled is True
    assert str(cfg.detection.rule_engine.rules_dir) == "rules"
    assert cfg.detection.ai_analyst.model == "qwen2.5-coder:14b"
    assert cfg.detection.ai_analyst.base_url is None
    assert cfg.detection.ai_analyst.max_severity_delta == 1


def test_detection_defaults_when_absent(tmp_path):
    cfg_file = tmp_path / "c.yml"
    cfg_file.write_text(
        """
mode: dry_run
host_name: null
paths:
  data_dir: /tmp/c
  events_db: /tmp/c/e.db
  findings_db: /tmp/c/f.db
  reports_dir: /tmp/c/r
  log_file: /tmp/c/l.log
collectors: {proc: {enabled: true, poll_interval_seconds: 1.0}}
reporting: {interval_seconds: 60, retention_days: 1}
""",
        encoding="utf-8",
    )
    from cerberus.core.config import load_config
    cfg = load_config(cfg_file)
    assert cfg.detection.rule_engine.enabled is True
    assert cfg.detection.ai_analyst.enabled is True
    assert cfg.detection.ai_analyst.max_severity_delta == 1


def test_load_response_config_and_auto_modes(tmp_path):
    cfg_file = tmp_path / "c.yml"
    cfg_file.write_text(
        """
mode: auto_critical
host_name: null
paths:
  data_dir: /tmp/c
  events_db: /tmp/c/e.db
  findings_db: /tmp/c/f.db
  actions_db: /tmp/c/a.db
  reports_dir: /tmp/c/r
  log_file: /tmp/c/l.log
  killswitch_path: /tmp/c/KILLSWITCH
  quarantine_dir: /tmp/c/quarantine
collectors: {proc: {enabled: true, poll_interval_seconds: 1.0}}
response:
  enabled: true
  policies_dir: policies
  auto_critical_categories: [ransomware, c2, data_exfil]
  rate: {max_actions_per_minute: 10, max_isolate_per_hour: 1}
reporting: {interval_seconds: 60, retention_days: 1}
""",
        encoding="utf-8",
    )
    from cerberus.core.config import load_config
    cfg = load_config(cfg_file)
    assert cfg.mode == "auto_critical"
    assert cfg.paths.actions_db == Path("/tmp/c/a.db")
    assert "KILLSWITCH" in str(cfg.paths.killswitch_path)
    assert cfg.response.enabled is True
    assert "ransomware" in cfg.response.auto_critical_categories
    assert cfg.response.rate.max_actions_per_minute == 10
    assert cfg.response.rate.max_isolate_per_hour == 1


def test_response_defaults_when_absent(tmp_path):
    cfg_file = tmp_path / "c.yml"
    cfg_file.write_text(
        """
mode: dry_run
host_name: null
paths:
  data_dir: /tmp/c
  events_db: /tmp/c/e.db
  findings_db: /tmp/c/f.db
  reports_dir: /tmp/c/r
  log_file: /tmp/c/l.log
collectors: {proc: {enabled: true, poll_interval_seconds: 1.0}}
reporting: {interval_seconds: 60, retention_days: 1}
""",
        encoding="utf-8",
    )
    from cerberus.core.config import load_config
    cfg = load_config(cfg_file)
    assert cfg.response.enabled is True
    assert cfg.response.rate.max_actions_per_minute == 10
    assert str(cfg.paths.actions_db).endswith("actions_log.db")
    assert str(cfg.paths.killswitch_path).endswith("KILLSWITCH")


def test_invalid_mode_still_rejected(tmp_path):
    import pytest
    cfg_file = tmp_path / "c.yml"
    cfg_file.write_text("mode: nuke\npaths: {}\ncollectors: {}\nreporting: {}\n")
    from cerberus.core.config import load_config
    with pytest.raises(ValueError):
        load_config(cfg_file)


def test_load_ipc_and_integrity_config(tmp_path):
    cfg_file = tmp_path / "c.yml"
    cfg_file.write_text(
        """
mode: dry_run
host_name: null
paths:
  data_dir: /tmp/c
  events_db: /tmp/c/e.db
  findings_db: /tmp/c/f.db
  reports_dir: /tmp/c/r
  log_file: /tmp/c/l.log
  state_file: /tmp/c/state.json
  manifest_path: /tmp/c/manifest.json
collectors: {proc: {enabled: true, poll_interval_seconds: 1.0}}
ipc:
  enabled: true
  pipe_name: "pipe-cerberus"
integrity:
  enabled: true
reporting: {interval_seconds: 60, retention_days: 1}
""",
        encoding="utf-8",
    )
    from cerberus.core.config import load_config
    cfg = load_config(cfg_file)
    assert cfg.paths.state_file == Path("/tmp/c/state.json")
    assert cfg.paths.manifest_path == Path("/tmp/c/manifest.json")
    assert cfg.ipc.enabled is True
    assert "pipe" in cfg.ipc.pipe_name
    assert cfg.integrity.enabled is True


def test_ipc_integrity_defaults_when_absent(tmp_path):
    cfg_file = tmp_path / "c.yml"
    cfg_file.write_text(
        """
mode: dry_run
host_name: null
paths:
  data_dir: /tmp/c
  events_db: /tmp/c/e.db
  findings_db: /tmp/c/f.db
  reports_dir: /tmp/c/r
  log_file: /tmp/c/l.log
collectors: {proc: {enabled: true, poll_interval_seconds: 1.0}}
reporting: {interval_seconds: 60, retention_days: 1}
""",
        encoding="utf-8",
    )
    from cerberus.core.config import load_config
    cfg = load_config(cfg_file)
    assert cfg.ipc.enabled is True
    assert cfg.ipc.pipe_name
    assert cfg.integrity.enabled is True
    assert str(cfg.paths.state_file).endswith("state.json")
    assert str(cfg.paths.manifest_path).endswith("manifest.json")


def test_net_dns_capture_default_false(tmp_path):
    cfg_file = tmp_path / "c.yml"
    cfg_file.write_text(
        """
mode: dry_run
host_name: null
paths:
  data_dir: /tmp/c
  events_db: /tmp/c/e.db
  findings_db: /tmp/c/f.db
  reports_dir: /tmp/c/r
  log_file: /tmp/c/l.log
collectors:
  proc: {enabled: true, poll_interval_seconds: 1.0}
  net:
    enabled: true
    poll_interval_seconds: 2.0
    beaconing_window_seconds: 60
    beaconing_min_connections: 10
reporting: {interval_seconds: 60, retention_days: 1}
""",
        encoding="utf-8",
    )
    from cerberus.core.config import load_config
    cfg = load_config(cfg_file)
    assert cfg.collectors.net.dns_capture is False


def test_net_dns_capture_true(tmp_path):
    cfg_file = tmp_path / "c.yml"
    cfg_file.write_text(
        """
mode: dry_run
host_name: null
paths:
  data_dir: /tmp/c
  events_db: /tmp/c/e.db
  findings_db: /tmp/c/f.db
  reports_dir: /tmp/c/r
  log_file: /tmp/c/l.log
collectors:
  proc: {enabled: true, poll_interval_seconds: 1.0}
  net:
    enabled: true
    poll_interval_seconds: 2.0
    beaconing_window_seconds: 60
    beaconing_min_connections: 10
    dns_capture: true
reporting: {interval_seconds: 60, retention_days: 1}
""",
        encoding="utf-8",
    )
    from cerberus.core.config import load_config
    cfg = load_config(cfg_file)
    assert cfg.collectors.net.dns_capture is True
