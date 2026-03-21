from __future__ import annotations

from pathlib import Path

import yaml

from .models import ScanReport
from .parser import parse_target
from .remote import MCPHandshakeError, fetch_remote_target, fetch_runtime_target
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
    if scan_target.mode == "local":
        handshake_errors = []
        for runtime_target in scan_target.runtime_targets:
            try:
                live_target = fetch_runtime_target(runtime_target)
            except MCPHandshakeError as exc:
                handshake_errors.append(
                    {
                        "transport": runtime_target.transport,
                        "source": runtime_target.source.path,
                        "message": str(exc),
                    }
                )
                continue
            scan_target.tools.extend(live_target.tools)
            scan_target.prompts.extend(live_target.prompts)
            if live_target.metadata:
                servers = scan_target.metadata.setdefault("live_servers", [])
                servers.append(live_target.metadata)
        if handshake_errors:
            scan_target.metadata["handshake_errors"] = handshake_errors
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
        metadata={
            "mode": scan_target.mode,
            "tool_count": len(scan_target.tools),
            "prompt_count": len(scan_target.prompts),
            **scan_target.metadata,
        },
    )
