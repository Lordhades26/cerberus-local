import pytest

from cerberus.ai.ollama_client import OllamaError
from cerberus.core.event import Event, Severity
from cerberus.core.finding import Finding
from cerberus.detection.ai_analyst import AIAnalyst, Triage

_TEMPLATE = "classify:\n<finding_data>\n__EVIDENCE__\n</finding_data>"


def _finding():
    evs = [Event(source="proc", type="new_process", host="H", pid=10, user="u",
                 raw={}, indicators={"cmdline": "powershell -enc AAAA"})]
    return Finding.from_cluster(host="H", pid=10, user="u", evidence=evs)


class _FakeClient:
    def __init__(self, payload=None, exc=None):
        self._payload = payload
        self._exc = exc

    def ask_json(self, model, prompt):
        if self._exc:
            raise self._exc
        return self._payload


@pytest.mark.asyncio
async def test_triage_valid_within_delta_passes_through():
    client = _FakeClient(payload={
        "severity": "HIGH", "family_guess": "loader",
        "reasoning": "enc cmd", "suggested_actions": ["kill_pid"], "confidence": 0.8,
    })
    a = AIAnalyst(client, model="m", prompt_template=_TEMPLATE, max_severity_delta=1)
    t = await a.triage(_finding(), severity_base=Severity.HIGH)
    assert t.severity == Severity.HIGH
    assert t.family_guess == "loader"
    assert t.suggested_actions == ["kill_pid"]
    assert 0.0 <= t.confidence <= 1.0


@pytest.mark.asyncio
async def test_triage_clamps_severity_up_to_base_plus_one():
    # base LOW, IA dice CRITICAL -> clamp a MEDIUM (LOW+1)
    client = _FakeClient(payload={"severity": "CRITICAL", "confidence": 0.9,
                                  "suggested_actions": []})
    a = AIAnalyst(client, model="m", prompt_template=_TEMPLATE, max_severity_delta=1)
    t = await a.triage(_finding(), severity_base=Severity.LOW)
    assert t.severity == Severity.MEDIUM


@pytest.mark.asyncio
async def test_triage_clamps_severity_down_to_base_minus_one():
    # base CRITICAL, IA dice INFO -> clamp a HIGH (CRITICAL-1)
    client = _FakeClient(payload={"severity": "INFO", "confidence": 0.1,
                                  "suggested_actions": []})
    a = AIAnalyst(client, model="m", prompt_template=_TEMPLATE, max_severity_delta=1)
    t = await a.triage(_finding(), severity_base=Severity.CRITICAL)
    assert t.severity == Severity.HIGH


@pytest.mark.asyncio
async def test_triage_malformed_json_falls_back_to_base():
    client = _FakeClient(payload={"garbage": True})  # falta severity
    a = AIAnalyst(client, model="m", prompt_template=_TEMPLATE, max_severity_delta=1)
    t = await a.triage(_finding(), severity_base=Severity.MEDIUM)
    assert t.severity == Severity.MEDIUM
    assert t.suggested_actions == []
    assert t.confidence == 0.0


@pytest.mark.asyncio
async def test_triage_ollama_error_falls_back_to_base():
    client = _FakeClient(exc=OllamaError("offline"))
    a = AIAnalyst(client, model="m", prompt_template=_TEMPLATE, max_severity_delta=1)
    t = await a.triage(_finding(), severity_base=Severity.HIGH)
    assert t.severity == Severity.HIGH
    assert t.reasoning == "ai_unavailable"


@pytest.mark.asyncio
async def test_triage_is_pure_no_filesystem_writes(tmp_path, monkeypatch):
    # Guardrail G1/G4: triage no escribe a disco aunque la IA "sugiera" acciones
    monkeypatch.chdir(tmp_path)
    client = _FakeClient(payload={"severity": "HIGH",
                                  "suggested_actions": ["kill_pid", "quarantine"],
                                  "confidence": 0.9})
    a = AIAnalyst(client, model="m", prompt_template=_TEMPLATE, max_severity_delta=1)
    await a.triage(_finding(), severity_base=Severity.HIGH)
    # ningún archivo creado por el triage
    assert list(tmp_path.iterdir()) == []


def test_triage_to_dict_serializable():
    import json
    t = Triage(severity=Severity.HIGH, family_guess="x", reasoning="r",
               suggested_actions=["a"], confidence=0.5)
    d = t.to_dict()
    assert d["severity"] == int(Severity.HIGH)
    json.dumps(d)
