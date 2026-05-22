from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any, Protocol

from cerberus.ai.ollama_client import OllamaError
from cerberus.core.event import Severity
from cerberus.core.finding import Finding
from cerberus.core.logger import get_logger

_log = get_logger("cerberus.detection.ai_analyst")


class _Client(Protocol):
    def ask_json(self, model: str, prompt: str) -> dict[str, Any]: ...


@dataclass(frozen=True)
class Triage:
    severity: Severity
    family_guess: str | None
    reasoning: str
    suggested_actions: list[str]
    confidence: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": int(self.severity),
            "family_guess": self.family_guess,
            "reasoning": self.reasoning,
            "suggested_actions": list(self.suggested_actions),
            "confidence": self.confidence,
        }


def _clamp(value: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, value))


def _coerce_severity(raw: Any) -> Severity:
    if isinstance(raw, str):
        return Severity[raw.strip().upper()]
    return Severity(int(raw))


class AIAnalyst:
    """Triage consultivo vía LLM. Función pura: devuelve Triage, sin efectos.

    Guardrails (§10.5.3): clamp ±delta sobre severity_base (G2); validación de
    schema con fallback a severity_base (G5); fallback ante error de Ollama (G6);
    nunca ejecuta acciones ni escribe a disco (G1/G4).
    """

    def __init__(
        self,
        ollama_client: _Client,
        model: str,
        prompt_template: str,
        max_severity_delta: int = 1,
    ) -> None:
        self._client = ollama_client
        self._model = model
        self._template = prompt_template
        self._delta = max_severity_delta

    def _render_prompt(self, finding: Finding) -> str:
        lines = [
            f"host={finding.host} pid={finding.pid} user={finding.user}",
            f"sources={sorted(finding.sources)} categories={sorted(finding.categories)}",
        ]
        for ev in finding.evidence:
            ind = ", ".join(f"{k}={v}" for k, v in ev.indicators.items() if v)
            lines.append(f"- {ev.source}/{ev.type}: {ind}")
        return self._template.replace("__EVIDENCE__", "\n".join(lines))

    def _fallback(self, severity_base: Severity, reason: str) -> Triage:
        return Triage(severity=severity_base, family_guess=None,
                      reasoning=reason, suggested_actions=[], confidence=0.0)

    def _build(self, data: dict[str, Any], severity_base: Severity) -> Triage:
        try:
            ai_sev = _coerce_severity(data["severity"])
        except (KeyError, ValueError, TypeError):
            _log.warning("ai_schema_invalid", extra={"keys": list(data.keys())})
            return self._fallback(severity_base, "ai_schema_invalid")
        lo = _clamp(int(severity_base) - self._delta, 0, 4)
        hi = _clamp(int(severity_base) + self._delta, 0, 4)
        final = Severity(_clamp(int(ai_sev), lo, hi))
        if final != ai_sev:
            _log.warning("ai_severity_clamped",
                         extra={"ai": int(ai_sev), "base": int(severity_base),
                                "final": int(final)})
        actions = data.get("suggested_actions", [])
        if not isinstance(actions, list):
            actions = []
        return Triage(
            severity=final,
            family_guess=data.get("family_guess"),
            reasoning=str(data.get("reasoning", "")),
            suggested_actions=[str(a) for a in actions],
            confidence=float(data.get("confidence", 0.0) or 0.0),
        )

    async def triage(self, finding: Finding, severity_base: Severity) -> Triage:
        prompt = self._render_prompt(finding)
        try:
            data = await asyncio.to_thread(self._client.ask_json, self._model, prompt)
        except OllamaError:
            return self._fallback(severity_base, "ai_unavailable")
        if not isinstance(data, dict):
            return self._fallback(severity_base, "ai_schema_invalid")
        return self._build(data, severity_base)
