from __future__ import annotations

from ..models import ScanReport


def render_terminal(report: ScanReport, verbose: bool = False) -> str:
    counts = report.summary_counts()
    lines = [
        f"Target: {report.target}",
        f"Findings: {len(report.findings)}",
        "Severity counts: "
        f"critical={counts['critical']} "
        f"high={counts['high']} "
        f"medium={counts['medium']} "
        f"low={counts['low']}",
        f"Tool quality score: {report.score_summary.tool_quality_score}",
    ]
    if verbose:
        for finding in report.findings:
            lines.append(
                f"[{finding.severity.value.upper()}] "
                f"{finding.rule_id} "
                f"{finding.location.path}: "
                f"{finding.message}"
            )
    return "\n".join(lines)
