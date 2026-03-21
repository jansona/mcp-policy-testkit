from __future__ import annotations

import re

from ..models import Category, Finding, ScanTarget, Severity, SourceLocation
from .base import Rule

COMMAND_CONCAT_PATTERN = re.compile(
    r"(os\.system|subprocess\.(run|Popen)|execSync|spawn)\s*\(.+[+{]",
    re.MULTILINE,
)
DYNAMIC_EXEC_PATTERN = re.compile(r"\b(eval|exec|Function)\s*\(")
FILE_OPEN_PATTERN = re.compile(
    r"\b(open|readFile|writeFile|fs\.readFileSync|fs\.writeFileSync)\s*\("
)
SANITIZE_HINT_PATTERN = re.compile(r"sanitize|normpath|resolve|realpath|Path\(")
RESOURCE_PATTERN = re.compile(
    r"while\s+True|range\s*\(\s*10{4,}\s*\)|new Array\(\d{6,}\)|\[\]\s*\*\s*10{4,}"
)


class CommandInjectionPatternRule(Rule):
    rule_id = "SRC001"
    title = "Possible command injection pattern"
    description = "Detects shell command construction using string concatenation or templates."
    severity = Severity.HIGH
    category = Category.SAFETY
    applies_to = ("local",)

    def evaluate(self, target: ScanTarget) -> list[Finding]:
        findings: list[Finding] = []
        for artifact in target.source_artifacts:
            match = COMMAND_CONCAT_PATTERN.search(artifact.content)
            if match:
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        severity=self.severity,
                        category=self.category,
                        message=(
                            "Source code appears to build shell commands via "
                            "string concatenation or templating."
                        ),
                        recommendation=(
                            "Use argument arrays and strict parameter "
                            "validation instead of interpolated shell commands."
                        ),
                        evidence=match.group(0),
                        location=SourceLocation(path=artifact.path),
                    )
                )
        return findings


class DynamicExecutionRule(Rule):
    rule_id = "SRC002"
    title = "Dynamic execution usage"
    description = "Detects eval/exec-like dynamic execution patterns."
    severity = Severity.HIGH
    category = Category.SAFETY
    applies_to = ("local",)

    def evaluate(self, target: ScanTarget) -> list[Finding]:
        findings: list[Finding] = []
        for artifact in target.source_artifacts:
            match = DYNAMIC_EXEC_PATTERN.search(artifact.content)
            if match:
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        severity=self.severity,
                        category=self.category,
                        message="Source code uses dynamic evaluation or execution.",
                        recommendation=(
                            "Remove dynamic code execution or replace it "
                            "with a constrained dispatcher."
                        ),
                        evidence=match.group(0),
                        location=SourceLocation(path=artifact.path),
                    )
                )
        return findings


class UnsanitizedFileAccessRule(Rule):
    rule_id = "SRC003"
    title = "Possible unsanitized file access"
    description = "Detects file operations without nearby sanitization hints."
    severity = Severity.MEDIUM
    category = Category.SAFETY
    applies_to = ("local",)

    def evaluate(self, target: ScanTarget) -> list[Finding]:
        findings: list[Finding] = []
        for artifact in target.source_artifacts:
            match = FILE_OPEN_PATTERN.search(artifact.content)
            if match and not SANITIZE_HINT_PATTERN.search(artifact.content):
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        severity=self.severity,
                        category=self.category,
                        message=(
                            "Source file performs open/read/write operations "
                            "without obvious path sanitization."
                        ),
                        recommendation=(
                            "Normalize and validate paths against an "
                            "allowlisted root before file access."
                        ),
                        evidence=match.group(0),
                        location=SourceLocation(path=artifact.path),
                    )
                )
        return findings


class ResourceExhaustionRule(Rule):
    rule_id = "SRC004"
    title = "Possible resource exhaustion pattern"
    description = "Detects simple unbounded allocation or looping patterns."
    severity = Severity.MEDIUM
    category = Category.SAFETY
    applies_to = ("local",)

    def evaluate(self, target: ScanTarget) -> list[Finding]:
        findings: list[Finding] = []
        for artifact in target.source_artifacts:
            match = RESOURCE_PATTERN.search(artifact.content)
            if match:
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        severity=self.severity,
                        category=self.category,
                        message=(
                            "Source file contains a pattern that may cause "
                            "resource exhaustion."
                        ),
                        recommendation=(
                            "Add explicit limits, chunking, or bounded loops "
                            "to the implementation."
                        ),
                        evidence=match.group(0),
                        location=SourceLocation(path=artifact.path),
                    )
                )
        return findings
