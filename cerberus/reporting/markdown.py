from __future__ import annotations

from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path

from cerberus.core.event import Event, Severity
from cerberus.core.finding import Finding
from cerberus.response.actions import ActionReport


class MarkdownReportWriter:
    def __init__(self, reports_dir: Path, host: str) -> None:
        self.reports_dir = Path(reports_dir)
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.host = host

    @staticmethod
    def render(
        events: list[Event],
        host: str,
        when: datetime | None = None,
        findings: list[Finding] | None = None,
        action_reports: list[ActionReport] | None = None,
    ) -> str:
        when = when or datetime.now(UTC)
        findings = findings or []
        action_reports = action_reports or []
        lines: list[str] = []
        lines.append("# CERBERUS-LOCAL — Reporte")
        lines.append("")
        lines.append(f"**Host:** {host}")
        lines.append(f"**Generado:** {when.isoformat()}")
        lines.append(f"**Total eventos:** {len(events)}")
        lines.append(f"**Total findings:** {len(findings)}")
        lines.append("")

        # --- Findings primero (lo más relevante) ---
        lines.append("## Findings")
        lines.append("")
        if not findings:
            lines.append("Sin findings correlacionados en el intervalo.")
            lines.append("")
        else:
            lines.append("| ID | Severidad | Base | PID | Reglas | IA (familia/conf.) |")
            lines.append("|----|-----------|------|-----|--------|--------------------|")
            for f in findings:
                sev = Severity(f.severity).name
                base = Severity(f.severity_base).name
                rules = ", ".join(f.rule_ids) if f.rule_ids else "—"
                if f.ai_triage:
                    fam = f.ai_triage.get("family_guess") or "—"
                    conf = f.ai_triage.get("confidence", 0.0)
                    ai_cell = f"{fam} ({conf})"
                else:
                    ai_cell = "—"
                lines.append(
                    f"| `{f.id}` | {sev} | {base} | {f.pid} | {rules} | {ai_cell} |"
                )
            lines.append("")

        # --- Acciones de respuesta ---
        if action_reports:
            lines.append("## Acciones")
            lines.append("")
            lines.append("| Finding | Modo | Acción | Ejecutada | Éxito | Razón |")
            lines.append("|---------|------|--------|-----------|-------|-------|")
            for rep in action_reports:
                for r in rep.results:
                    lines.append(
                        f"| `{rep.finding_id}` | {rep.mode} | {r.action.type} | "
                        f"{r.executed} | {r.success} | {r.reason} |"
                    )
            lines.append("")

        # --- Eventos por fuente ---
        if not events:
            lines.append("## Eventos")
            lines.append("")
            lines.append("Sin eventos en el intervalo.")
            return "\n".join(lines)

        by_source: dict[str, list[Event]] = defaultdict(list)
        for ev in events:
            by_source[ev.source].append(ev)
        for source in sorted(by_source):
            evs = by_source[source]
            lines.append(f"## {source}")
            lines.append("")
            type_counts = Counter(ev.type for ev in evs)
            lines.append("| Tipo | Cantidad |")
            lines.append("|------|----------|")
            for t, n in sorted(type_counts.items()):
                lines.append(f"| `{t}` | {n} |")
            lines.append("")
            lines.append("<details><summary>Ejemplos (hasta 10)</summary>")
            lines.append("")
            for ev in evs[:10]:
                ind = ", ".join(f"{k}={v}" for k, v in ev.indicators.items() if v)
                lines.append(f"- `{ev.timestamp.isoformat()}` pid={ev.pid} {ev.type} — {ind}")
            lines.append("")
            lines.append("</details>")
            lines.append("")
        return "\n".join(lines)

    def write(
        self,
        events: list[Event],
        when: datetime | None = None,
        findings: list[Finding] | None = None,
        action_reports: list[ActionReport] | None = None,
    ) -> Path:
        when = when or datetime.now(UTC)
        filename = when.strftime("%Y-%m-%d_%H-%M") + ".md"
        path = self.reports_dir / filename
        path.write_text(
            self.render(events, host=self.host, when=when, findings=findings,
                        action_reports=action_reports),
            encoding="utf-8",
        )
        return path
