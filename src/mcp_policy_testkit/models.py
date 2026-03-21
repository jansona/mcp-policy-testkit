from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Category(str, Enum):
    CONFIG = "config"
    TOOL_QUALITY = "tool_quality"
    SAFETY = "safety"
    SOURCE = "source"


SEVERITY_ORDER = {
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class SourceLocation(BaseModel):
    path: str
    pointer: Optional[str] = None
    line: Optional[int] = None
    column: Optional[int] = None
    tool_name: Optional[str] = None


class Finding(BaseModel):
    rule_id: str
    title: str
    severity: Severity
    category: Category
    message: str
    recommendation: str
    evidence: Optional[str] = None
    location: SourceLocation
    score_impact: int = 0


class ToolParameterSchema(BaseModel):
    raw: Dict[str, Any] = Field(default_factory=dict)
    required: List[str] = Field(default_factory=list)


class ToolDefinition(BaseModel):
    name: str
    description: str = ""
    input_schema: ToolParameterSchema = Field(default_factory=ToolParameterSchema)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    source: SourceLocation


class PromptDefinition(BaseModel):
    name: str
    description: str = ""
    arguments: List[Dict[str, Any]] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    source: SourceLocation


class ConfigCommand(BaseModel):
    command: str
    source: SourceLocation


class RuntimeTarget(BaseModel):
    transport: str
    source: SourceLocation
    name: str = ""
    command: Optional[str] = None
    args: List[str] = Field(default_factory=list)
    cwd: Optional[str] = None
    env: Dict[str, str] = Field(default_factory=dict)
    url: Optional[str] = None


class SourceArtifact(BaseModel):
    path: str
    language: Optional[str] = None
    content: str


class ScanTarget(BaseModel):
    target: str
    mode: str
    raw_documents: List[Tuple[str, Dict[str, Any]]] = Field(default_factory=list)
    configs: List[Dict[str, Any]] = Field(default_factory=list)
    tools: List[ToolDefinition] = Field(default_factory=list)
    prompts: List[PromptDefinition] = Field(default_factory=list)
    commands: List[ConfigCommand] = Field(default_factory=list)
    source_artifacts: List[SourceArtifact] = Field(default_factory=list)
    runtime_targets: List[RuntimeTarget] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class RuleMetadata(BaseModel):
    rule_id: str
    title: str
    severity: Severity
    category: Category
    description: str


class ScoreSummary(BaseModel):
    tool_quality_score: int = 100


class ScanReport(BaseModel):
    target: str
    findings: List[Finding] = Field(default_factory=list)
    score_summary: ScoreSummary = Field(default_factory=ScoreSummary)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    def highest_severity(self) -> Optional[Severity]:
        if not self.findings:
            return None
        return max(
            self.findings,
            key=lambda item: SEVERITY_ORDER[item.severity],
        ).severity

    def summary_counts(self) -> Dict[str, int]:
        counts = {severity.value: 0 for severity in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts
