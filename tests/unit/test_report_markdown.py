from datetime import datetime, timezone
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
    path = writer.write(events, when=datetime(2026, 5, 21, 14, 30, tzinfo=timezone.utc))
    assert path.exists()
    name = path.name
    assert name.startswith("2026-05-21_14-30") and name.endswith(".md")
    content = path.read_text(encoding="utf-8")
    assert "## proc" in content
