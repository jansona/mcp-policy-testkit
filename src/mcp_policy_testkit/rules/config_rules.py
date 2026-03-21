from __future__ import annotations

import math
import re
from typing import Any

from ..models import Category, Finding, ScanTarget, Severity, SourceLocation
from .base import Rule

SECRET_KEY_PATTERN = re.compile(r"(api[_-]?key|token|secret|password|credential)", re.IGNORECASE)
SECRET_VALUE_PATTERN = re.compile(r"(sk-[A-Za-z0-9]{12,}|ghp_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16})")
SENSITIVE_PATHS = ("/", "/etc", "/var", "/Users", "/home", "~", "/root")
SENSITIVE_ENV_NAMES = {
    "aws_secret_access_key",
    "openai_api_key",
    "github_token",
    "access_token",
}
DESTRUCTIVE_COMMAND_PATTERN = re.compile(
    r"\brm\s+-rf\b|\bmkfs\b|\bshutdown\b|\bchmod\s+777\b",
    re.IGNORECASE,
)


def _iter_values(value: Any, pointer: str = ""):
    if isinstance(value, dict):
        for key, item in value.items():
            next_pointer = f"{pointer}/{key}"
            yield next_pointer, key, item
            yield from _iter_values(item, next_pointer)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            next_pointer = f"{pointer}/{index}"
            yield next_pointer, str(index), item
            yield from _iter_values(item, next_pointer)


def _entropy(text: str) -> float:
    probabilities = [text.count(char) / len(text) for char in set(text)]
    return -sum(p * math.log2(p) for p in probabilities)


class SecretDetectionRule(Rule):
    rule_id = "CFG001"
    title = "Hardcoded secret detected"
    description = "Detects likely secrets in configuration files."
    severity = Severity.CRITICAL
    category = Category.CONFIG

    def evaluate(self, target: ScanTarget) -> list[Finding]:
        findings: list[Finding] = []
        for path, document in target.raw_documents:
            for pointer, key, value in _iter_values(document):
                if not isinstance(value, str):
                    continue
                if SECRET_KEY_PATTERN.search(key) and value.strip():
                    looks_secret = SECRET_VALUE_PATTERN.search(value)
                    high_entropy = len(value) >= 20 and _entropy(value) > 3.5
                    if looks_secret or high_entropy:
                        findings.append(
                            Finding(
                                rule_id=self.rule_id,
                                title=self.title,
                                severity=self.severity,
                                category=self.category,
                                message=f"Configuration field '{key}' appears to contain a secret.",
                                recommendation=(
                                    "Move the secret to a secure secret manager "
                                    "or environment injection."
                                ),
                                evidence=value[:8] + "...",
                                location=SourceLocation(path=path, pointer=pointer),
                            )
                        )
        return findings


class EnvExposureRule(Rule):
    rule_id = "CFG002"
    title = "Sensitive environment variable exposure"
    description = "Detects dangerous environment variable pass-through."
    severity = Severity.HIGH
    category = Category.CONFIG

    def evaluate(self, target: ScanTarget) -> list[Finding]:
        findings: list[Finding] = []
        for path, document in target.raw_documents:
            for pointer, key, value in _iter_values(document):
                if key.lower() != "env":
                    continue
                if isinstance(value, dict):
                    for env_name, env_value in value.items():
                        lowered = str(env_name).lower()
                        if lowered in SENSITIVE_ENV_NAMES or SECRET_KEY_PATTERN.search(lowered):
                            findings.append(
                                Finding(
                                    rule_id=self.rule_id,
                                    title=self.title,
                                    severity=self.severity,
                                    category=self.category,
                                    message=(
                                        f"Environment variable '{env_name}' should not be "
                                        "broadly exposed to an MCP server."
                                    ),
                                    recommendation=(
                                        "Whitelist only non-sensitive variables or inject "
                                        "credentials through a dedicated secret mechanism."
                                    ),
                                    evidence=str(env_value),
                                    location=SourceLocation(
                                        path=path,
                                        pointer=f"{pointer}/{env_name}",
                                    ),
                                )
                            )
        return findings


class UnsafePathMappingRule(Rule):
    rule_id = "CFG003"
    title = "Unsafe path mapping"
    description = "Detects overly broad or sensitive filesystem mappings."
    severity = Severity.HIGH
    category = Category.CONFIG

    def evaluate(self, target: ScanTarget) -> list[Finding]:
        findings: list[Finding] = []
        for path, document in target.raw_documents:
            for pointer, key, value in _iter_values(document):
                if not isinstance(value, str):
                    continue
                lowered_key = key.lower()
                if (
                    "path" not in lowered_key
                    and "mount" not in lowered_key
                    and "root" not in lowered_key
                ):
                    continue
                is_sensitive = any(
                    value == sensitive or value.startswith(f"{sensitive}/")
                    for sensitive in SENSITIVE_PATHS
                )
                if is_sensitive:
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            title=self.title,
                            severity=self.severity,
                            category=self.category,
                            message=f"Path mapping '{value}' is overly broad or sensitive.",
                            recommendation=(
                                "Restrict mappings to a dedicated project subdirectory "
                                "and avoid system roots."
                            ),
                            evidence=value,
                            location=SourceLocation(path=path, pointer=pointer),
                        )
                    )
                elif "*" in value or "?" in value:
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            title=self.title,
                            severity=Severity.MEDIUM,
                            category=self.category,
                            message=(
                                f"Wildcard path mapping '{value}' can grant unintended "
                                "file access."
                            ),
                            recommendation="Replace wildcard mappings with explicit directories.",
                            evidence=value,
                            location=SourceLocation(path=path, pointer=pointer),
                        )
                    )
        return findings


class DangerousCommandRule(Rule):
    rule_id = "CFG004"
    title = "Dangerous command declaration"
    description = "Detects destructive shell commands in manifest or configuration files."
    severity = Severity.CRITICAL
    category = Category.CONFIG

    def evaluate(self, target: ScanTarget) -> list[Finding]:
        findings: list[Finding] = []
        for command in target.commands:
            if DESTRUCTIVE_COMMAND_PATTERN.search(command.command):
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        severity=self.severity,
                        category=self.category,
                        message="Configuration declares a destructive shell command.",
                        recommendation=(
                            "Remove destructive commands from MCP configuration and gate "
                            "dangerous operations inside audited tools."
                        ),
                        evidence=command.command,
                        location=command.source,
                    )
                )
        return findings
