from __future__ import annotations

from collections import defaultdict

from ..models import Category, Finding, ScanTarget, Severity, SourceLocation
from .base import Rule


class ToolShadowingRule(Rule):
    rule_id = "TQL006"
    title = "Tool shadowing or duplicated signature"
    description = (
        "Detects duplicated signatures across documents or suspicious look-alike contracts."
    )
    severity = Severity.MEDIUM
    category = Category.SAFETY

    def evaluate(self, target: ScanTarget) -> list[Finding]:
        findings: list[Finding] = []
        buckets: dict[tuple[str, tuple[str, ...]], list[str]] = defaultdict(list)
        for tool in target.tools:
            schema = tool.input_schema.raw
            props = schema.get("properties", {}) if isinstance(schema, dict) else {}
            signature = (tool.name.lower(), tuple(sorted(props.keys())))
            buckets[signature].append(tool.source.path)
        for signature, paths in buckets.items():
            if len(set(paths)) > 1:
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        severity=self.severity,
                        category=self.category,
                        message=(
                            f"Tool '{signature[0]}' appears with the same "
                            "signature across multiple sources."
                        ),
                        recommendation=(
                            "Review whether one tool is shadowing another "
                            "and namespace tools by server identity."
                        ),
                        evidence=", ".join(sorted(set(paths))),
                        location=SourceLocation(
                            path=sorted(set(paths))[0],
                            tool_name=signature[0],
                        ),
                    )
                )
        return findings
