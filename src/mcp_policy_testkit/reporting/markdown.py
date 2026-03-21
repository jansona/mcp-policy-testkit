from __future__ import annotations

from jinja2 import Template

from ..models import ScanReport

MARKDOWN_TEMPLATE = Template(
    """# MCP Policy Test Report

Target: `{{ report.target }}`

## Summary

- Findings: {{ report.findings | length }}
- Tool quality score: {{ report.score_summary.tool_quality_score }}
- Counts:
  critical={{ counts.critical }},
  high={{ counts.high }},
  medium={{ counts.medium }},
  low={{ counts.low }}

## Findings

{% if report.findings %}
{% for finding in report.findings %}
### [{{ finding.severity.value|upper }}] {{ finding.title }} (`{{ finding.rule_id }}`)

- Category: `{{ finding.category.value }}`
- Location:
  `{{ finding.location.path }}`
  {% if finding.location.pointer %}`{{ finding.location.pointer }}`{% endif %}
- Message: {{ finding.message }}
- Recommendation: {{ finding.recommendation }}
{% if finding.evidence %}- Evidence: `{{ finding.evidence }}`{% endif %}

{% endfor %}
{% else %}
No findings.
{% endif %}
"""
)


def render_markdown(report: ScanReport) -> str:
    return MARKDOWN_TEMPLATE.render(report=report, counts=report.summary_counts())
