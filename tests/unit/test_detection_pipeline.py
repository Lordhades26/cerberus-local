import pytest

from cerberus.core.event import Event, Severity
from cerberus.core.finding import Finding
from cerberus.detection.ai_analyst import Triage
from cerberus.detection.pipeline import DetectionPipeline
from cerberus.detection.rule_engine import RuleMatch


def _ev(source, type_, **ind):
    return Event(source=source, type=type_, host="H", pid=10, user="u",
                 raw={}, indicators=ind)


def _finding():
    return Finding.from_cluster(
        host="H", pid=10, user="u",
        evidence=[_ev("fs", "mass_rename", rename_count=30),
                  _ev("proc", "new_process", cmdline="powershell -enc")],
    )


class _FakeRuleEngine:
    def __init__(self, matches):
        self._matches = matches

    def match(self, finding):
        return self._matches


class _FakeAnalyst:
    def __init__(self, triage):
        self._triage = triage
        self.called_with_base = None

    async def triage(self, finding, severity_base):
        self.called_with_base = severity_base
        return self._triage


@pytest.mark.asyncio
async def test_pipeline_sets_severity_base_from_rules():
    rules = _FakeRuleEngine([
        RuleMatch("r_low", Severity.LOW, "x"),
        RuleMatch("r_crit", Severity.CRITICAL, "ransomware"),
    ])
    pipe = DetectionPipeline(rules, ai_analyst=None, ai_enabled=False)
    out = await pipe.process(_finding())
    assert out.severity_base == Severity.CRITICAL   # max de las reglas
    assert out.severity == Severity.CRITICAL         # sin IA -> = base
    assert set(out.rule_ids) == {"r_low", "r_crit"}
    assert out.ai_triage is None


@pytest.mark.asyncio
async def test_pipeline_no_rule_match_uses_finding_default():
    pipe = DetectionPipeline(_FakeRuleEngine([]), ai_analyst=None, ai_enabled=False)
    out = await pipe.process(_finding())
    assert out.severity_base == Severity.MEDIUM      # default del Finding
    assert out.rule_ids == ()


@pytest.mark.asyncio
async def test_pipeline_applies_ai_triage_when_enabled():
    rules = _FakeRuleEngine([RuleMatch("r_high", Severity.HIGH, "execution")])
    triage = Triage(severity=Severity.HIGH, family_guess="loader",
                    reasoning="r", suggested_actions=["kill_pid"], confidence=0.8)
    analyst = _FakeAnalyst(triage)
    pipe = DetectionPipeline(rules, ai_analyst=analyst, ai_enabled=True)
    out = await pipe.process(_finding())
    assert analyst.called_with_base == Severity.HIGH   # base pasada a la IA
    assert out.severity == Severity.HIGH
    assert out.severity_base == Severity.HIGH
    assert out.ai_triage["family_guess"] == "loader"
    assert out.rule_ids == ("r_high",)


@pytest.mark.asyncio
async def test_pipeline_ai_disabled_skips_analyst():
    rules = _FakeRuleEngine([RuleMatch("r", Severity.MEDIUM, "x")])
    analyst = _FakeAnalyst(Triage(Severity.CRITICAL, None, "", [], 1.0))
    pipe = DetectionPipeline(rules, ai_analyst=analyst, ai_enabled=False)
    out = await pipe.process(_finding())
    assert analyst.called_with_base is None   # nunca llamado
    assert out.severity == Severity.MEDIUM
    assert out.ai_triage is None
