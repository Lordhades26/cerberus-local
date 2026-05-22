from __future__ import annotations

from pathlib import Path
from typing import Protocol

from cerberus.core.event import Severity
from cerberus.core.finding import Finding
from cerberus.core.logger import get_logger
from cerberus.response.action_store import ActionStore
from cerberus.response.actions import Action, ActionReport, ActionResult, PolicyDecision
from cerberus.response.rate_limiter import RateLimiter

_log = get_logger("cerberus.response.engine")


class _PolicyEngine(Protocol):
    def decide(self, finding: Finding) -> list[PolicyDecision]: ...


class _Executor(Protocol):
    def build(self, action: Action) -> object: ...
    def run(self, action: Action) -> ActionResult: ...


class ResponseEngine:
    """Orquesta la respuesta. Gates fail-closed: killswitch -> modo -> confirmation -> rate.
    Solo la PolicyEngine decide acciones (G1); los gates no consultan ai_triage (G3).
    """

    def __init__(
        self,
        policy_engine: _PolicyEngine,
        executor: _Executor,
        action_store: ActionStore,
        rate_limiter: RateLimiter,
        mode: str,
        killswitch_path: Path,
        auto_critical_categories: frozenset[str],
    ) -> None:
        self._policy = policy_engine
        self._executor = executor
        self._store = action_store
        self._rate = rate_limiter
        self._mode = mode
        self._killswitch_path = Path(killswitch_path)
        self._auto_critical_categories = auto_critical_categories

    def _killswitch_active(self) -> bool:
        return self._killswitch_path.exists()

    def _decide_execute(self, decision: PolicyDecision, finding: Finding) -> tuple[bool, str]:
        if self._killswitch_active():
            return False, "killswitch"
        if self._mode in ("dry_run", "monitor"):
            return False, self._mode
        if self._mode == "auto_critical":
            if not (finding.severity == Severity.CRITICAL
                    and (finding.categories & self._auto_critical_categories)):
                return False, "mode_gate"
        elif self._mode == "auto_all":
            if finding.severity < Severity.HIGH:
                return False, "mode_gate"
        if decision.require_confirmation:
            return False, "require_confirmation"
        if not self._rate.allow(decision.action.type):
            return False, "rate_limited"
        return True, "authorized"

    async def handle(self, finding: Finding) -> ActionReport:
        decisions = self._policy.decide(finding)
        results: list[ActionResult] = []
        for decision in decisions:
            should, reason = self._decide_execute(decision, finding)
            if should:
                result = self._executor.run(decision.action)
            else:
                built = self._executor.build(decision.action)
                result = ActionResult(
                    action=decision.action, executed=False, success=False, output="",
                    command=getattr(built, "command", ""),
                    reverted_command=getattr(built, "reverted_command", None),
                    reason=reason,
                )
            self._store.insert(result, finding_id=finding.id,
                               policy_id=decision.policy_id, mode=self._mode)
            _log.info("response_action",
                      extra={"finding_id": finding.id, "policy": decision.policy_id,
                             "action": decision.action.type, "executed": result.executed,
                             "reason": result.reason})
            results.append(result)
        return ActionReport(finding_id=finding.id, mode=self._mode, results=results)
