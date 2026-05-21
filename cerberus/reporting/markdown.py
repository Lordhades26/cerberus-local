from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

from cerberus.core.event import Event


class MarkdownReportWriter:
    def __init__(self, reports_dir: Path, host: str) -> None:
        self.reports_dir = Path(reports_dir)
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.host = host

    @staticmethod
    def render(events: list[Event], host: str, when: datetime | None = None) -> str:
        when = when or datetime.now(timezone.utc)
        lines: list[str] = []
        lines.append("# CERBERUS-LOCAL — Reporte")
        lines.append("")
        lines.append(f"**Host:** {host}")
        lines.append(f"**Generado:** {when.isoformat()}")
        lines.append(f"**Total eventos:** {len(events)}")
        lines.append("")
        if not events:
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

    def write(self, events: list[Event], when: datetime | None = None) -> Path:
        when = when or datetime.now(timezone.utc)
        filename = when.strftime("%Y-%m-%d_%H-%M") + ".md"
        path = self.reports_dir / filename
        path.write_text(self.render(events, host=self.host, when=when), encoding="utf-8")
        return path
