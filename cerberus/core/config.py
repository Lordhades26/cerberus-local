from __future__ import annotations

import socket
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import yaml

Mode = Literal["dry_run", "monitor"]
_VALID_MODES = {"dry_run", "monitor"}


@dataclass(frozen=True)
class ProcCollectorConfig:
    enabled: bool
    poll_interval_seconds: float


@dataclass(frozen=True)
class CollectorsConfig:
    proc: ProcCollectorConfig


@dataclass(frozen=True)
class PathsConfig:
    data_dir: Path
    events_db: Path
    reports_dir: Path
    log_file: Path


@dataclass(frozen=True)
class ReportingConfig:
    interval_seconds: int
    retention_days: int


@dataclass(frozen=True)
class CerberusConfig:
    mode: Mode
    host_name: str
    paths: PathsConfig
    collectors: CollectorsConfig
    reporting: ReportingConfig


def load_config(path: Path | str) -> CerberusConfig:
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    mode = raw.get("mode", "dry_run")
    if mode not in _VALID_MODES:
        raise ValueError(f"Invalid mode {mode!r}; valid: {sorted(_VALID_MODES)}")
    host = raw.get("host_name") or socket.gethostname()
    paths_raw = raw.get("paths", {})
    paths = PathsConfig(
        data_dir=Path(paths_raw.get("data_dir", "")),
        events_db=Path(paths_raw.get("events_db", "")),
        reports_dir=Path(paths_raw.get("reports_dir", "")),
        log_file=Path(paths_raw.get("log_file", "")),
    )
    coll_raw = raw.get("collectors", {})
    proc_raw = coll_raw.get("proc", {})
    collectors = CollectorsConfig(
        proc=ProcCollectorConfig(
            enabled=bool(proc_raw.get("enabled", True)),
            poll_interval_seconds=float(proc_raw.get("poll_interval_seconds", 1.0)),
        )
    )
    rep_raw = raw.get("reporting", {})
    reporting = ReportingConfig(
        interval_seconds=int(rep_raw.get("interval_seconds", 300)),
        retention_days=int(rep_raw.get("retention_days", 7)),
    )
    return CerberusConfig(
        mode=mode, host_name=host, paths=paths,
        collectors=collectors, reporting=reporting,
    )
