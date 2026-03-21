from __future__ import annotations

from abc import ABC, abstractmethod

from ..models import Category, Finding, RuleMetadata, ScanTarget, Severity


class Rule(ABC):
    rule_id: str
    title: str
    description: str
    severity: Severity
    category: Category
    applies_to: tuple[str, ...] = ("local", "remote")

    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            rule_id=self.rule_id,
            title=self.title,
            severity=self.severity,
            category=self.category,
            description=self.description,
        )

    def supports(self, target: ScanTarget) -> bool:
        return target.mode in self.applies_to

    @abstractmethod
    def evaluate(self, target: ScanTarget) -> list[Finding]:
        raise NotImplementedError
