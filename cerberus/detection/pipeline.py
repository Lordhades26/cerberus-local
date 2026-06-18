from __future__ import annotations

import dataclasses

from cerberus.core.event import Severity
from cerberus.core.finding import Finding
from cerberus.core.logger import get_logger
from cerberus.detection.ai_analyst import AIAnalyst
from cerberus.detection.rule_engine import RuleEngine

_log = get_logger("cerberus.detection.pipeline")


class DetectionPipeline:
    """Enriquece un Finding: RuleEngine fija severity_base + rule_ids (causal,
    heurístico); AIAnalyst (si está habilitado) ajusta severity ±delta y añade
    ai_triage (complementario). Devuelve un Finding nuevo (frozen) vía replace.
    """

    def __init__(
        self,
        rule_engine: RuleEngine,
        ai_analyst: AIAnalyst | None,
        ai_enabled: bool,
    ) -> None:
        self._rules = rule_engine
        self._ai = ai_analyst
        self._ai_enabled = ai_enabled

    async def process(self, finding: Finding) -> Finding:
        matches = self._rules.match(finding)
        if matches:
            severity_base = Severity(max(int(m.severity) for m in matches))
            rule_ids = tuple(m.rule_id for m in matches)
            rule_categories = tuple(set(m.category for m in matches))
        else:
            severity_base = finding.severity
            rule_ids = ()
            rule_categories = ()

        final_severity = severity_base
        ai_triage = None
        if self._ai_enabled and self._ai is not None:
            triage = await self._ai.triage(finding, severity_base)
            final_severity = triage.severity
            ai_triage = triage.to_dict()

        _log.info("finding_enriched",
                  extra={"finding_id": finding.id, "rule_ids": list(rule_ids),
                         "severity_base": int(severity_base),
                         "severity_final": int(final_severity)})
        return dataclasses.replace(
            finding,
            severity=final_severity,
            severity_base=severity_base,
            rule_ids=rule_ids,
            rule_categories=rule_categories,
            ai_triage=ai_triage,
        )
