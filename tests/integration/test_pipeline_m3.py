from pathlib import Path

import pytest

from cerberus.core.event import Event, Severity
from cerberus.core.event_bus import EventBus
from cerberus.core.finding import Finding
from cerberus.detection.ai_analyst import AIAnalyst
from cerberus.detection.correlator import Correlator
from cerberus.detection.finding_store import FindingStore
from cerberus.detection.pipeline import DetectionPipeline
from cerberus.detection.rule_engine import RuleEngine

_RULES_DIR = Path(__file__).resolve().parents[2] / "rules"

_TEMPLATE = "classify:\n<finding_data>\n__EVIDENCE__\n</finding_data>"


class _FakeClient:
    def ask_json(self, model, prompt):
        # IA "consultiva": intenta subir a CRITICAL; el clamp la limita a base+1
        return {"severity": "CRITICAL", "family_guess": "lockbit-like",
                "reasoning": "mass rename + encoded ps", "confidence": 0.85,
                "suggested_actions": ["kill_pid", "isolate_host"]}


@pytest.mark.asyncio
async def test_m3_detection_pipeline_enriches_and_persists(tmp_path: Path):
    findings_db = tmp_path / "findings.db"
    fstore = FindingStore(findings_db)
    fstore.init_schema()

    rule_engine = RuleEngine(_RULES_DIR)
    assert rule_engine.load() == 5
    analyst = AIAnalyst(_FakeClient(), model="m", prompt_template=_TEMPLATE,
                        max_severity_delta=1)
    pipeline = DetectionPipeline(rule_engine, ai_analyst=analyst, ai_enabled=True)

    persisted: list[Finding] = []

    async def on_finding(f: Finding) -> None:
        enriched = await pipeline.process(f)
        fstore.insert(enriched)
        persisted.append(enriched)

    bus = EventBus()
    corr = Correlator(window_seconds=10, min_sources_for_finding=2, on_finding=on_finding)
    corr.attach(bus)
    bus.start()

    # ransomware: mass_rename(>=20) + new_process powershell -enc, mismo pid
    await bus.publish(Event(source="fs", type="mass_rename", host="H", pid=4892,
                            user="u", raw={}, indicators={"rename_count": 30}))
    await bus.publish(Event(source="proc", type="new_process", host="H", pid=4892,
                            user="u", raw={}, indicators={"cmdline": "powershell -enc AAAA"}))
    await bus.drain()
    await corr.flush()
    await bus.stop()

    assert len(persisted) == 1
    f = persisted[0]
    # RuleEngine fija base CRITICAL (ransomware_pattern_v1)
    assert f.severity_base == Severity.CRITICAL
    assert "ransomware_pattern_v1" in f.rule_ids
    # IA pedía CRITICAL; base CRITICAL -> queda CRITICAL (dentro de ±1)
    assert f.severity == Severity.CRITICAL
    assert f.ai_triage is not None
    assert f.ai_triage["family_guess"] == "lockbit-like"

    rows = fstore.fetch_all()
    assert rows[0]["severity_base"] == int(Severity.CRITICAL)
    assert "ransomware_pattern_v1" in rows[0]["rule_ids"]
    assert rows[0]["ai_triage"]["confidence"] == 0.85
    fstore.close()


@pytest.mark.asyncio
async def test_m3_clamp_holds_when_base_low(tmp_path: Path):
    # Finding sin regla que case -> base MEDIUM (default); IA pide CRITICAL -> clamp a HIGH
    rule_engine = RuleEngine(tmp_path)  # dir vacío -> 0 reglas
    rule_engine.load()
    analyst = AIAnalyst(_FakeClient(), model="m", prompt_template=_TEMPLATE,
                        max_severity_delta=1)
    pipeline = DetectionPipeline(rule_engine, ai_analyst=analyst, ai_enabled=True)

    f = Finding.from_cluster(
        host="H", pid=7, user="u",
        evidence=[Event(source="proc", type="new_process", host="H", pid=7,
                        user="u", raw={}, indicators={}),
                  Event(source="net", type="outbound_conn", host="H", pid=7,
                        user="u", raw={}, indicators={})],
    )
    out = await pipeline.process(f)
    assert out.severity_base == Severity.MEDIUM
    assert out.severity == Severity.HIGH   # MEDIUM + 1 (clamp), no CRITICAL
