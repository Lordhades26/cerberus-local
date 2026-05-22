from pathlib import Path

import pytest

from cerberus.core.db import EventStore
from cerberus.core.event import Event
from cerberus.core.event_bus import EventBus
from cerberus.core.finding import Finding
from cerberus.detection.correlator import Correlator
from cerberus.detection.finding_store import FindingStore
from cerberus.reporting.markdown import MarkdownReportWriter


@pytest.mark.asyncio
async def test_m2_pipeline_correlates_persists_and_reports(tmp_path: Path):
    """Eventos sintéticos de 3 fuentes con el mismo pid -> 1 finding correlacionado,
    persistido en findings.db y reflejado en el reporte Markdown."""
    events_db = tmp_path / "events.db"
    findings_db = tmp_path / "findings.db"
    reports = tmp_path / "reports"

    store = EventStore(events_db)
    store.init_schema()
    fstore = FindingStore(findings_db)
    fstore.init_schema()
    writer = MarkdownReportWriter(reports, host="H")
    bus = EventBus()

    collected_events: list[Event] = []
    collected_findings: list[Finding] = []

    async def persist_event(ev: Event) -> None:
        store.insert(ev)
        collected_events.append(ev)

    async def on_finding(f: Finding) -> None:
        fstore.insert(f)
        collected_findings.append(f)

    bus.subscribe(persist_event)
    corr = Correlator(window_seconds=10, min_sources_for_finding=2, on_finding=on_finding)
    corr.attach(bus)
    bus.start()

    # Simular telemetría de 3 collectors para el mismo proceso (pid=4892)
    await bus.publish(Event(source="fs", type="mass_rename", host="H", pid=4892,
                            user="u", raw={}, indicators={"rename_count": 30}))
    await bus.publish(Event(source="proc", type="new_process", host="H", pid=4892,
                            user="u", raw={}, indicators={"cmdline": "powershell -enc AAAA"}))
    await bus.publish(Event(source="net", type="outbound_conn", host="H", pid=4892,
                            user="u", raw={}, indicators={"remote_ip": "185.10.10.10"}))
    # Un evento aislado de otro pid que NO debe generar finding
    await bus.publish(Event(source="proc", type="new_process", host="H", pid=99,
                            user="u", raw={}, indicators={}))
    await bus.drain()
    await corr.flush()
    await bus.stop()

    # Persistencia de eventos
    assert store.count() == 4
    # Exactamente un finding (pid 4892 multi-fuente; pid 99 single-source descartado)
    assert fstore.count() == 1
    rows = fstore.fetch_all()
    assert rows[0]["pid"] == 4892
    assert set(rows[0]["sources"]) == {"fs", "proc", "net"}
    store.close()
    fstore.close()

    # Reporte refleja eventos + findings
    report_path = writer.write(collected_events, findings=collected_findings)
    text = report_path.read_text(encoding="utf-8")
    assert "## Findings" in text
    assert "**Total findings:** 1" in text
    assert "mass_rename" in text
    assert "## net" in text and "## proc" in text and "## fs" in text
