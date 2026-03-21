from __future__ import annotations

from ..models import ScanTarget
from .base import Rule
from .config_rules import (
    DangerousCommandRule,
    EnvExposureRule,
    SecretDetectionRule,
    UnsafePathMappingRule,
)
from .shadow_rules import ToolShadowingRule
from .source_rules import (
    CommandInjectionPatternRule,
    DynamicExecutionRule,
    ResourceExhaustionRule,
    UnsanitizedFileAccessRule,
)
from .tool_rules import (
    AmbiguousToolContractRule,
    DestructiveToolDisclosureRule,
    DuplicateToolNameRule,
    PromptInjectionMetadataRule,
    SchemaQualityRule,
)

DEFAULT_RULES: list[Rule] = [
    SecretDetectionRule(),
    EnvExposureRule(),
    UnsafePathMappingRule(),
    DangerousCommandRule(),
    DuplicateToolNameRule(),
    AmbiguousToolContractRule(),
    PromptInjectionMetadataRule(),
    SchemaQualityRule(),
    DestructiveToolDisclosureRule(),
    ToolShadowingRule(),
    CommandInjectionPatternRule(),
    DynamicExecutionRule(),
    UnsanitizedFileAccessRule(),
    ResourceExhaustionRule(),
]


class RuleRegistry:
    def __init__(self, rules: list[Rule] | None = None) -> None:
        self._rules = {rule.rule_id: rule for rule in (rules or DEFAULT_RULES)}

    @property
    def rules(self) -> list[Rule]:
        return list(self._rules.values())

    def select(
        self,
        enabled: list[str] | None = None,
        disabled: list[str] | None = None,
    ) -> list[Rule]:
        active = self.rules
        if enabled:
            enabled_set = set(enabled)
            active = [rule for rule in active if rule.rule_id in enabled_set]
        if disabled:
            disabled_set = set(disabled)
            active = [rule for rule in active if rule.rule_id not in disabled_set]
        return active

    def evaluate(
        self,
        target: ScanTarget,
        enabled: list[str] | None = None,
        disabled: list[str] | None = None,
    ):
        findings = []
        for rule in self.select(enabled=enabled, disabled=disabled):
            if rule.supports(target):
                findings.extend(rule.evaluate(target))
        return findings
