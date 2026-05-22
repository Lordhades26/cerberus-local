from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, ClassVar


@dataclass(frozen=True)
class Action:
    VALID_TYPES: ClassVar[set[str]] = {
        "kill_pid", "quarantine", "block_ip",
        "stop_service", "isolate_host", "disable_user",
    }
    type: str
    params: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.type not in self.VALID_TYPES:
            raise ValueError(
                f"Invalid action type {self.type!r}; must be one of {sorted(self.VALID_TYPES)}"
            )


@dataclass(frozen=True)
class PolicyDecision:
    action: Action
    policy_id: str
    require_confirmation: bool


@dataclass(frozen=True)
class ActionResult:
    action: Action
    executed: bool
    success: bool
    output: str
    command: str
    reverted_command: str | None
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_type": self.action.type,
            "params": self.action.params,
            "executed": self.executed,
            "success": self.success,
            "output": self.output,
            "command": self.command,
            "reverted_command": self.reverted_command,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class ActionReport:
    finding_id: str
    mode: str
    results: list[ActionResult]

    @property
    def executed_count(self) -> int:
        return sum(1 for r in self.results if r.executed)
