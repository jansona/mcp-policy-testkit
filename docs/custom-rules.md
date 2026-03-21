# Custom Rules

Custom rules should subclass `Rule` and implement `evaluate(target) -> list[Finding]`.

## Minimal example

```python
from mcp_policy_testkit.models import Category, Finding, Severity, SourceLocation
from mcp_policy_testkit.rules.base import Rule


class ExampleRule(Rule):
    rule_id = "CUS001"
    title = "Example custom policy"
    description = "Flags every target for demonstration purposes."
    severity = Severity.LOW
    category = Category.CONFIG

    def evaluate(self, target):
        return [
            Finding(
                rule_id=self.rule_id,
                title=self.title,
                severity=self.severity,
                category=self.category,
                message="Example finding",
                recommendation="Replace the example with a real rule.",
                location=SourceLocation(path=target.target),
            )
        ]
```

Register custom rules by constructing `RuleRegistry` with your rule instances, or by extending the built-in registry module in your own wrapper CLI.

