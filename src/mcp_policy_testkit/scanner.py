from __future__ import annotations

from pathlib import Path

import yaml

from .models import ScanReport
from .parser import parse_target
from .remote import fetch_remote_target
from .rules import RuleRegistry
from .utils import is_url


def scan(
    target: str,
    enabled_rules: list[str] | None = None,
    disabled_rules: list[str] | None = None,
    lint_config_only: bool = False,
    project_config: str | None = None,
) -> ScanReport:
    if project_config:
        config_data = yaml.safe_load(Path(project_config).read_text(encoding="utf-8")) or {}
        enabled_rules = enabled_rules or config_data.get("enable_rules")
        disabled_rules = disabled_rules or config_data.get("disable_rules")
    scan_target = fetch_remote_target(target) if is_url(target) else parse_target(target)
    registry = RuleRegistry()
    findings = registry.evaluate(scan_target, enabled=enabled_rules, disabled=disabled_rules)
    if lint_config_only:
        findings = [finding for finding in findings if finding.category.value == "config"]
    findings.sort(key=lambda item: (item.location.path, item.rule_id, item.message))
    score = max(0, 100 - sum(finding.score_impact for finding in findings))
    return ScanReport(
        target=scan_target.target,
        findings=findings,
        score_summary={"tool_quality_score": score},
        metadata={"mode": scan_target.mode, "tool_count": len(scan_target.tools)},
    )
