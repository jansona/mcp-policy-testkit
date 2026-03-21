from __future__ import annotations

import re
from collections import Counter

from ..models import Category, Finding, ScanTarget, Severity
from .base import Rule

AMBIGUOUS_NAME_PATTERN = re.compile(r"^(do|run|tool|handle|process|misc)[-_]?\w*$", re.IGNORECASE)
INJECTION_TEXT_PATTERN = re.compile(
    (
        r"ignore previous|important instruction|send credentials|"
        r"reveal secret|bypass policy|system prompt"
    ),
    re.IGNORECASE,
)
DESTRUCTIVE_WORD_PATTERN = re.compile(r"delete|remove|destroy|wipe|drop|overwrite", re.IGNORECASE)


class DuplicateToolNameRule(Rule):
    rule_id = "TQL001"
    title = "Duplicate tool name"
    description = "Detects duplicated tool names that can cause shadowing or confusion."
    severity = Severity.HIGH
    category = Category.TOOL_QUALITY

    def evaluate(self, target: ScanTarget) -> list[Finding]:
        findings: list[Finding] = []
        counts = Counter(tool.name for tool in target.tools)
        for tool in target.tools:
            if counts[tool.name] > 1:
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        severity=self.severity,
                        category=self.category,
                        message=f"Tool name '{tool.name}' is duplicated.",
                        recommendation=(
                            "Use unique tool names and add a namespace or capability prefix."
                        ),
                        evidence=tool.name,
                        location=tool.source,
                        score_impact=8,
                    )
                )
        return findings


class AmbiguousToolContractRule(Rule):
    rule_id = "TQL002"
    title = "Ambiguous tool contract"
    description = "Detects ambiguous names and underspecified descriptions."
    severity = Severity.MEDIUM
    category = Category.TOOL_QUALITY

    def evaluate(self, target: ScanTarget) -> list[Finding]:
        findings: list[Finding] = []
        for tool in target.tools:
            if AMBIGUOUS_NAME_PATTERN.search(tool.name) or len(tool.description.split()) < 5:
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        severity=self.severity,
                        category=self.category,
                        message=(
                            f"Tool '{tool.name}' has an ambiguous name "
                            "or insufficient description."
                        ),
                        recommendation=(
                            "Use a task-specific name and describe expected inputs, "
                            "outputs, and side effects."
                        ),
                        evidence=tool.description or tool.name,
                        location=tool.source,
                        score_impact=6,
                    )
                )
        return findings


class PromptInjectionMetadataRule(Rule):
    rule_id = "TQL003"
    title = "Hidden instruction in tool metadata"
    description = "Detects prompt-injection or tool-poisoning language in tool descriptions."
    severity = Severity.HIGH
    category = Category.SAFETY

    def evaluate(self, target: ScanTarget) -> list[Finding]:
        findings: list[Finding] = []
        for tool in target.tools:
            haystack = f"{tool.name}\n{tool.description}"
            if INJECTION_TEXT_PATTERN.search(haystack):
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        severity=self.severity,
                        category=self.category,
                        message=(
                            f"Tool '{tool.name}' contains prompt-injection "
                            "or hidden instruction language."
                        ),
                        recommendation=(
                            "Remove instructions unrelated to the tool's purpose "
                            "and keep metadata task-focused."
                        ),
                        evidence=tool.description,
                        location=tool.source,
                        score_impact=10,
                    )
                )
        return findings


class SchemaQualityRule(Rule):
    rule_id = "TQL004"
    title = "Weak parameter schema"
    description = "Detects missing types, missing required fields, and unbounded parameters."
    severity = Severity.MEDIUM
    category = Category.TOOL_QUALITY

    def evaluate(self, target: ScanTarget) -> list[Finding]:
        findings: list[Finding] = []
        for tool in target.tools:
            schema = tool.input_schema.raw
            properties = schema.get("properties", {}) if isinstance(schema, dict) else {}
            if not properties:
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        severity=self.severity,
                        category=self.category,
                        message=f"Tool '{tool.name}' is missing explicit input properties.",
                        recommendation=(
                            "Define JSON Schema properties with types, descriptions, "
                            "and required fields."
                        ),
                        evidence=str(schema),
                        location=tool.source,
                        score_impact=8,
                    )
                )
                continue
            for prop_name, prop_schema in properties.items():
                if not isinstance(prop_schema, dict) or "type" not in prop_schema:
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            title=self.title,
                            severity=self.severity,
                            category=self.category,
                            message=(
                                f"Tool '{tool.name}' parameter '{prop_name}' "
                                "is missing a declared type."
                            ),
                            recommendation=(
                                "Declare an explicit type and constraints "
                                "for every parameter."
                            ),
                            evidence=str(prop_schema),
                            location=tool.source,
                            score_impact=4,
                        )
                    )
                    continue
                if prop_schema.get("type") == "string" and not any(
                    key in prop_schema
                    for key in ("enum", "pattern", "minLength", "maxLength", "format")
                ):
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            title=self.title,
                            severity=Severity.LOW,
                            category=self.category,
                            message=(
                                f"Tool '{tool.name}' parameter '{prop_name}' "
                                "is an unconstrained string."
                            ),
                            recommendation="Add string bounds or a pattern to reduce misuse.",
                            evidence=str(prop_schema),
                            location=tool.source,
                            score_impact=2,
                        )
                    )
        return findings


class DestructiveToolDisclosureRule(Rule):
    rule_id = "TQL005"
    title = "Destructive tool missing warning"
    description = "Detects tools that appear destructive but are not labeled as such."
    severity = Severity.MEDIUM
    category = Category.TOOL_QUALITY

    def evaluate(self, target: ScanTarget) -> list[Finding]:
        findings: list[Finding] = []
        for tool in target.tools:
            if (
                DESTRUCTIVE_WORD_PATTERN.search(tool.name)
                or DESTRUCTIVE_WORD_PATTERN.search(tool.description)
            ):
                if (
                    "destructive" not in tool.description.lower()
                    and "confirm" not in tool.description.lower()
                ):
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            title=self.title,
                            severity=self.severity,
                            category=self.category,
                            message=(
                                f"Tool '{tool.name}' appears destructive but "
                                "its description lacks a clear warning."
                            ),
                            recommendation=(
                                "Explicitly label destructive side effects "
                                "and require confirmation semantics."
                            ),
                            evidence=tool.description,
                            location=tool.source,
                            score_impact=5,
                        )
                    )
        return findings
