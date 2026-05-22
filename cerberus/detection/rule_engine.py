from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from cerberus.core.event import Severity
from cerberus.core.finding import Finding
from cerberus.core.logger import get_logger

_log = get_logger("cerberus.detection.rule_engine")


@dataclass(frozen=True)
class RuleMatch:
    rule_id: str
    severity: Severity
    category: str


@dataclass(frozen=True)
class _Clause:
    source: str
    type: str
    cmdline_regex: re.Pattern[str] | None
    count_name: str | None
    count_min: float


@dataclass(frozen=True)
class _Rule:
    id: str
    severity: Severity
    category: str
    mode: str  # "all" | "any"
    clauses: tuple[_Clause, ...]


def _parse_rule(raw: dict[str, Any]) -> _Rule:
    rid = str(raw["id"])
    severity = Severity[str(raw["severity"]).upper()]  # KeyError si inválida
    category = str(raw["category"])
    cond = raw["condition"]
    mode = str(cond["mode"]).lower()
    if mode not in ("all", "any"):
        raise ValueError(f"invalid mode {mode!r}")
    clauses: list[_Clause] = []
    for c in cond["clauses"]:
        ci = c.get("count_indicator") or {}
        regex = c.get("cmdline_regex")
        clauses.append(_Clause(
            source=str(c["source"]),
            type=str(c["type"]),
            cmdline_regex=re.compile(regex) if regex else None,
            count_name=str(ci["name"]) if ci else None,
            count_min=float(ci["min"]) if ci else 0.0,
        ))
    if not clauses:
        raise ValueError("rule has no clauses")
    return _Rule(id=rid, severity=severity, category=category,
                 mode=mode, clauses=tuple(clauses))


class RuleEngine:
    def __init__(self, rules_dir: Path | str) -> None:
        self._rules_dir = Path(rules_dir)
        self._rules: list[_Rule] = []

    def load(self) -> int:
        rules: list[_Rule] = []
        if self._rules_dir.exists():
            for path in sorted(self._rules_dir.glob("*.yml")):
                try:
                    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
                    rules.append(_parse_rule(raw))
                except (KeyError, ValueError, TypeError, re.error,
                        yaml.YAMLError) as exc:
                    _log.error("rule_invalid",
                               extra={"path": str(path), "error": str(exc)})
        self._rules = rules
        return len(rules)

    def reload(self) -> int:
        return self.load()

    @staticmethod
    def _clause_matches(clause: _Clause, finding: Finding) -> bool:
        for ev in finding.evidence:
            if ev.source != clause.source or ev.type != clause.type:
                continue
            if clause.cmdline_regex is not None:
                cmdline = str(ev.indicators.get("cmdline", ""))
                if not clause.cmdline_regex.search(cmdline):
                    continue
            if clause.count_name is not None:
                try:
                    val = float(ev.indicators.get(clause.count_name, 0))
                except (TypeError, ValueError):
                    val = 0.0
                if val < clause.count_min:
                    continue
            return True
        return False

    def match(self, finding: Finding) -> list[RuleMatch]:
        out: list[RuleMatch] = []
        for rule in self._rules:
            results = [self._clause_matches(c, finding) for c in rule.clauses]
            ok = all(results) if rule.mode == "all" else any(results)
            if ok:
                out.append(RuleMatch(rule_id=rule.id, severity=rule.severity,
                                     category=rule.category))
        return out
