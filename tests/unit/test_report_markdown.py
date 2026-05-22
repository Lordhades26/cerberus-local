from datetime import UTC, datetime
from pathlib import Path

from cerberus.core.event import Event
from cerberus.reporting.markdown import MarkdownReportWriter


def _ev(source, type_, **kw):
    base = dict(host="H", pid=1, user=None, raw={}, indicators={})
    base.update(kw)
    return Event(source=source, type=type_, **base)


def test_render_empty_report():
    out = MarkdownReportWriter.render([], host="H")
    assert "# CERBERUS-LOCAL — Reporte" in out
    assert "Sin eventos" in out


def test_render_report_groups_by_source():
    events = [
        _ev("proc", "new_process", pid=10, indicators={"name": "a.exe"}),
        _ev("proc", "new_process", pid=11, indicators={"name": "b.exe"}),
        _ev("proc", "process_exit", pid=12),
    ]
    out = MarkdownReportWriter.render(events, host="H")
    assert "## proc" in out
    assert "new_process" in out
    assert "process_exit" in out
    assert "**Total eventos:** 3" in out


def test_write_creates_file(tmp_path: Path):
    writer = MarkdownReportWriter(reports_dir=tmp_path, host="H")
    events = [_ev("proc", "new_process", pid=10, indicators={"name": "x.exe"})]
    path = writer.write(events, when=datetime(2026, 5, 21, 14, 30, tzinfo=UTC))
    assert path.exists()
    name = path.name
    assert name.startswith("2026-05-21_14-30") and name.endswith(".md")
    content = path.read_text(encoding="utf-8")
    assert "## proc" in content


def test_render_with_findings_section():
    from cerberus.core.finding import Finding

    def _e(source, type_, pid=10):
        return Event(source=source, type=type_, host="H", pid=pid,
                     user="u", raw={}, indicators={})

    events = [_e("proc", "new_process"), _e("net", "outbound_conn")]
    finding = Finding.from_cluster(host="H", pid=10, user="u", evidence=events)
    out = MarkdownReportWriter.render(events, host="H", findings=[finding])
    assert "## Findings" in out
    assert "**Total findings:** 1" in out
    assert finding.id in out
    assert "proc" in out and "net" in out


def test_render_no_findings_shows_zero():
    out = MarkdownReportWriter.render([], host="H", findings=[])
    assert "**Total findings:** 0" in out


def test_write_with_findings(tmp_path: Path):
    from cerberus.core.finding import Finding
    writer = MarkdownReportWriter(reports_dir=tmp_path, host="H")
    events = [Event(source="proc", type="new_process", host="H", pid=10,
                    user="u", raw={}, indicators={}),
              Event(source="fs", type="mass_rename", host="H", pid=10,
                    user="u", raw={}, indicators={})]
    finding = Finding.from_cluster(host="H", pid=10, user="u", evidence=events)
    path = writer.write(events, findings=[finding])
    content = path.read_text(encoding="utf-8")
    assert "## Findings" in content
    assert "mass_rename" in content


def test_render_findings_shows_rule_and_triage():
    import dataclasses

    from cerberus.core.event import Severity
    from cerberus.core.finding import Finding

    def _e(source, type_):
        return Event(source=source, type=type_, host="H", pid=10,
                     user="u", raw={}, indicators={})

    base = Finding.from_cluster(host="H", pid=10, user="u",
                                evidence=[_e("fs", "mass_rename"), _e("proc", "new_process")])
    enriched = dataclasses.replace(
        base, severity=Severity.CRITICAL, severity_base=Severity.CRITICAL,
        rule_ids=("ransomware_pattern_v1",),
        ai_triage={"severity": 4, "family_guess": "lockbit", "confidence": 0.8,
                   "reasoning": "x", "suggested_actions": []},
    )
    out = MarkdownReportWriter.render([], host="H", findings=[enriched])
    assert "ransomware_pattern_v1" in out
    assert "lockbit" in out
    assert "CRITICAL" in out


def test_render_actions_section():
    from cerberus.response.actions import Action, ActionReport, ActionResult
    a = Action(type="kill_pid", params={"pid": 10})
    r = ActionResult(action=a, executed=False, success=False, output="",
                     command="taskkill /F /T /PID 10", reverted_command=None, reason="dry_run")
    rep = ActionReport(finding_id="F1", mode="dry_run", results=[r])
    out = MarkdownReportWriter.render([], host="H", findings=[], action_reports=[rep])
    assert "## Acciones" in out
    assert "kill_pid" in out
    assert "dry_run" in out
