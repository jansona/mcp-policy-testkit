from __future__ import annotations

import json

from ..models import ScanReport

SARIF_LEVELS = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
}


def render_sarif(report: ScanReport) -> str:
    rules = {}
    results = []
    for finding in report.findings:
        rules[finding.rule_id] = {
            "id": finding.rule_id,
            "name": finding.title,
            "shortDescription": {"text": finding.message},
            "help": {"text": finding.recommendation},
        }
        results.append(
            {
                "ruleId": finding.rule_id,
                "level": SARIF_LEVELS[finding.severity.value],
                "message": {"text": finding.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.location.path},
                        }
                    }
                ],
            }
        )
    payload = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {"driver": {"name": "mcp-policy-testkit", "rules": list(rules.values())}},
                "results": results,
            }
        ],
    }
    return json.dumps(payload, indent=2)
