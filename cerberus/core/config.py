from __future__ import annotations

import socket
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

import yaml

Mode = Literal["dry_run", "monitor", "auto_critical", "auto_all"]
_VALID_MODES = {"dry_run", "monitor", "auto_critical", "auto_all"}

_DEFAULT_EVT_CHANNELS = [
    "Security",
    "Microsoft-Windows-Sysmon/Operational",
    "Microsoft-Windows-PowerShell/Operational",
]


@dataclass(frozen=True)
class ProcCollectorConfig:
    enabled: bool
    poll_interval_seconds: float


@dataclass(frozen=True)
class NetCollectorConfig:
    enabled: bool
    poll_interval_seconds: float
    beaconing_window_seconds: int
    beaconing_min_connections: int
    dns_capture: bool


@dataclass(frozen=True)
class FsCollectorConfig:
    enabled: bool
    watch_paths: list[Path]
    mass_rename_threshold: int
    mass_rename_window_seconds: int
    high_entropy_threshold: float


@dataclass(frozen=True)
class EvtCollectorConfig:
    enabled: bool
    channels: list[str]


@dataclass(frozen=True)
class CollectorsConfig:
    proc: ProcCollectorConfig
    net: NetCollectorConfig
    fs: FsCollectorConfig
    evt: EvtCollectorConfig


@dataclass(frozen=True)
class CorrelatorConfig:
    window_seconds: int
    min_sources_for_finding: int


@dataclass(frozen=True)
class RuleEngineConfig:
    enabled: bool
    rules_dir: Path


@dataclass(frozen=True)
class AIAnalystConfig:
    enabled: bool
    model: str
    base_url: str | None
    timeout_seconds: float
    max_severity_delta: int


@dataclass(frozen=True)
class DetectionConfig:
    rule_engine: RuleEngineConfig
    ai_analyst: AIAnalystConfig


@dataclass(frozen=True)
class RateConfig:
    max_actions_per_minute: int
    max_isolate_per_hour: int


@dataclass(frozen=True)
class ResponseConfig:
    enabled: bool
    policies_dir: Path
    auto_critical_categories: frozenset[str]
    rate: RateConfig


@dataclass(frozen=True)
class PathsConfig:
    data_dir: Path
    events_db: Path
    findings_db: Path
    actions_db: Path
    reports_dir: Path
    log_file: Path
    killswitch_path: Path
    quarantine_dir: Path
    state_file: Path
    manifest_path: Path


@dataclass(frozen=True)
class IpcConfig:
    enabled: bool
    pipe_name: str


@dataclass(frozen=True)
class IntegrityConfig:
    enabled: bool


@dataclass(frozen=True)
class DashboardConfig:
    enabled: bool
    host: str
    port: int
    refresh_seconds: int


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
    correlator: CorrelatorConfig
    detection: DetectionConfig
    response: ResponseConfig
    ipc: IpcConfig
    integrity: IntegrityConfig
    dashboard: DashboardConfig
    reporting: ReportingConfig


def _proc(raw: dict[str, Any]) -> ProcCollectorConfig:
    return ProcCollectorConfig(
        enabled=bool(raw.get("enabled", True)),
        poll_interval_seconds=float(raw.get("poll_interval_seconds", 1.0)),
    )


def _net(raw: dict[str, Any]) -> NetCollectorConfig:
    return NetCollectorConfig(
        enabled=bool(raw.get("enabled", True)),
        poll_interval_seconds=float(raw.get("poll_interval_seconds", 2.0)),
        beaconing_window_seconds=int(raw.get("beaconing_window_seconds", 60)),
        beaconing_min_connections=int(raw.get("beaconing_min_connections", 10)),
        dns_capture=bool(raw.get("dns_capture", False)),
    )


def _fs(raw: dict[str, Any]) -> FsCollectorConfig:
    return FsCollectorConfig(
        enabled=bool(raw.get("enabled", True)),
        watch_paths=[Path(p) for p in raw.get("watch_paths", [])],
        mass_rename_threshold=int(raw.get("mass_rename_threshold", 20)),
        mass_rename_window_seconds=int(raw.get("mass_rename_window_seconds", 5)),
        high_entropy_threshold=float(raw.get("high_entropy_threshold", 7.5)),
    )


def _evt(raw: dict[str, Any]) -> EvtCollectorConfig:
    channels = raw.get("channels") or list(_DEFAULT_EVT_CHANNELS)
    return EvtCollectorConfig(
        enabled=bool(raw.get("enabled", True)),
        channels=list(channels),
    )


def _detection(raw: dict[str, Any]) -> DetectionConfig:
    re_raw = raw.get("rule_engine", {})
    ai_raw = raw.get("ai_analyst", {})
    return DetectionConfig(
        rule_engine=RuleEngineConfig(
            enabled=bool(re_raw.get("enabled", True)),
            rules_dir=Path(re_raw.get("rules_dir", "rules")),
        ),
        ai_analyst=AIAnalystConfig(
            enabled=bool(ai_raw.get("enabled", True)),
            model=str(ai_raw.get("model", "HADES-DOLPHIN-EDR:latest")),
            base_url=ai_raw.get("base_url"),
            timeout_seconds=float(ai_raw.get("timeout_seconds", 20.0)),
            max_severity_delta=int(ai_raw.get("max_severity_delta", 1)),
        ),
    )


_DEFAULT_AUTO_CRITICAL_CATEGORIES = ["ransomware", "c2", "data_exfil"]


def _response(raw: dict[str, Any]) -> ResponseConfig:
    rate_raw = raw.get("rate", {})
    cats = raw.get("auto_critical_categories") or list(_DEFAULT_AUTO_CRITICAL_CATEGORIES)
    return ResponseConfig(
        enabled=bool(raw.get("enabled", True)),
        policies_dir=Path(raw.get("policies_dir", "policies")),
        auto_critical_categories=frozenset(str(c) for c in cats),
        rate=RateConfig(
            max_actions_per_minute=int(rate_raw.get("max_actions_per_minute", 10)),
            max_isolate_per_hour=int(rate_raw.get("max_isolate_per_hour", 1)),
        ),
    )


def load_config(path: Path | str) -> CerberusConfig:
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    mode = raw.get("mode", "dry_run")
    if mode not in _VALID_MODES:
        raise ValueError(f"Invalid mode {mode!r}; valid: {sorted(_VALID_MODES)}")
    host = raw.get("host_name") or socket.gethostname()

    paths_raw = raw.get("paths", {})
    data_dir = Path(paths_raw.get("data_dir", ""))
    paths = PathsConfig(
        data_dir=data_dir,
        events_db=Path(paths_raw.get("events_db", "")),
        findings_db=Path(paths_raw.get("findings_db", "")),
        actions_db=Path(paths_raw.get("actions_db") or (data_dir / "db" / "actions_log.db")),
        reports_dir=Path(paths_raw.get("reports_dir", "")),
        log_file=Path(paths_raw.get("log_file", "")),
        killswitch_path=Path(paths_raw.get("killswitch_path") or (data_dir / "KILLSWITCH")),
        quarantine_dir=Path(paths_raw.get("quarantine_dir") or (data_dir / "Quarantine")),
        state_file=Path(paths_raw.get("state_file") or (data_dir / "state.json")),
        manifest_path=Path(paths_raw.get("manifest_path") or (data_dir / "manifest.json")),
    )

    coll_raw = raw.get("collectors", {})
    collectors = CollectorsConfig(
        proc=_proc(coll_raw.get("proc", {})),
        net=_net(coll_raw.get("net", {})),
        fs=_fs(coll_raw.get("fs", {})),
        evt=_evt(coll_raw.get("evt", {})),
    )

    corr_raw = raw.get("correlator", {})
    correlator = CorrelatorConfig(
        window_seconds=int(corr_raw.get("window_seconds", 10)),
        min_sources_for_finding=int(corr_raw.get("min_sources_for_finding", 2)),
    )

    detection = _detection(raw.get("detection", {}))
    response = _response(raw.get("response", {}))

    ipc_raw = raw.get("ipc", {})
    ipc = IpcConfig(
        enabled=bool(ipc_raw.get("enabled", True)),
        pipe_name=str(ipc_raw.get("pipe_name", r"\\.\pipe\cerberus")),
    )
    integrity_raw = raw.get("integrity", {})
    integrity = IntegrityConfig(enabled=bool(integrity_raw.get("enabled", True)))

    dash_raw = raw.get("dashboard", {})
    dashboard = DashboardConfig(
        enabled=bool(dash_raw.get("enabled", True)),
        host=str(dash_raw.get("host", "127.0.0.1")),
        port=int(dash_raw.get("port", 8787)),
        refresh_seconds=int(dash_raw.get("refresh_seconds", 5)),
    )

    rep_raw = raw.get("reporting", {})
    reporting = ReportingConfig(
        interval_seconds=int(rep_raw.get("interval_seconds", 300)),
        retention_days=int(rep_raw.get("retention_days", 7)),
    )

    return CerberusConfig(
        mode=mode,
        host_name=host,
        paths=paths,
        collectors=collectors,
        correlator=correlator,
        detection=detection,
        response=response,
        ipc=ipc,
        integrity=integrity,
        dashboard=dashboard,
        reporting=reporting,
    )
