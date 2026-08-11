from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field, HttpUrl


class ScanMode(str, Enum):
    PASSIVE = "passive"


Severity = Literal["info", "low", "medium", "high", "critical"]


class PassiveDiscoveryRequest(BaseModel):
    target: HttpUrl
    use_ai: bool = False


class Observation(BaseModel):
    category: str
    source: str = "passive-http"
    url: str
    value: Any
    metadata: dict[str, Any] = Field(default_factory=dict)


class Finding(BaseModel):
    id: str
    source: str | None = None
    method: str
    endpoint: str
    category: str
    severity: Severity
    confidence: float = Field(ge=0, le=1)
    evidence: list[str] = Field(default_factory=list)
    source_tools: list[str] = Field(default_factory=list)
    potential_impact: str
    remediation: str
    status: str
    correlation: dict[str, Any] | None = None


class ScanReport(BaseModel):
    project: str = "APIShield Agent"
    scan_mode: ScanMode
    target: str | None = None
    planning_mode: str = ""
    planning_fallback_reason: str | None = None
    endpoint_count: int = 0
    plan: list[dict[str, Any]] = Field(default_factory=list)
    timeline: list[dict[str, Any]] = Field(default_factory=list)
    observations: list[Observation] = Field(default_factory=list)
    summary: dict[str, Any] = Field(default_factory=dict)
    findings: list[Finding] = Field(default_factory=list)
    remediation_report: list[dict[str, Any]] = Field(default_factory=list)
    disclaimer: str = "Passive findings are review signals and do not establish that harm occurred."
