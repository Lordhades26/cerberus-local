from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from cerberus.core.event import Severity
from cerberus.core.finding import Finding
from cerberus.core.logger import get_logger
from cerberus.response.actions import Action, PolicyDecision

_log = get_logger("cerberus.response.policy_engine")


@dataclass(frozen=True)
class _Policy:
    id: str
    severity_min: Severity
    categories: frozenset[str]
    require_confirmation: bool
    action_types: tuple[str, ...]


def _parse_policy(raw: dict[str, Any]) -> _Policy:
    pid = str(raw["id"])
    match = raw.get("match", {})
    severity_min = Severity[str(match["severity_min"]).upper()]
    categories = frozenset(str(c) for c in (match.get("categories") or []))
    actions = tuple(str(a) for a in raw["actions"])
    for a in actions:
        if a not in Action.VALID_TYPES:
            raise ValueError(f"invalid action type in policy: {a!r}")
    return _Policy(
        id=pid, severity_min=severity_min, categories=categories,
        require_confirmation=bool(raw.get("require_confirmation", False)),
        action_types=actions,
    )


def _first_indicator(finding: Finding, key: str) -> Any | None:
    for ev in finding.evidence:
        val = ev.indicators.get(key)
        if val:
            return val
    return None


class PolicyEngine:
    """Decide acciones SOLO desde (severity, categories del finding). No lee ai_triage (G1)."""

    def __init__(self, policies_dir: Path | str) -> None:
        self._dir = Path(policies_dir)
        self._policies: list[_Policy] = []

    def load(self) -> int:
        policies: list[_Policy] = []
        if self._dir.exists():
            for path in sorted(self._dir.glob("*.yml")):
                try:
                    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
                    policies.append(_parse_policy(raw))
                except (KeyError, ValueError, TypeError, yaml.YAMLError) as exc:
                    _log.error("policy_invalid", extra={"path": str(path), "error": str(exc)})
        self._policies = policies
        return len(policies)

    def reload(self) -> int:
        return self.load()

    def _resolve_params(self, action_type: str, finding: Finding) -> dict[str, Any] | None:
        if action_type == "kill_pid":
            return {"pid": finding.pid} if finding.pid is not None else None
        if action_type == "block_ip":
            ip = _first_indicator(finding, "remote_ip")
            return {"ip": ip} if ip else None
        if action_type == "quarantine":
            path = _first_indicator(finding, "exe") or _first_indicator(finding, "path")
            return {"path": path} if path else None
        if action_type == "stop_service":
            name = _first_indicator(finding, "service_name")
            return {"name": name} if name else None
        if action_type == "disable_user":
            return {"username": finding.user} if finding.user else None
        if action_type == "isolate_host":
            return {}
        return None

    def decide(self, finding: Finding) -> list[PolicyDecision]:
        decisions: list[PolicyDecision] = []
        for policy in self._policies:
            if finding.severity < policy.severity_min:
                continue
            if policy.categories and not (policy.categories & finding.categories):
                continue
            for action_type in policy.action_types:
                params = self._resolve_params(action_type, finding)
                if params is None:
                    _log.info("action_skipped_unresolvable",
                              extra={"policy": policy.id, "action": action_type})
                    continue
                decisions.append(PolicyDecision(
                    action=Action(type=action_type, params=params),
                    policy_id=policy.id,
                    require_confirmation=policy.require_confirmation,
                ))
        return decisions
