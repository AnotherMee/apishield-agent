from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field, HttpUrl


class ScanMode(str, Enum):
    PASSIVE = "passive"
    AUTHORIZED_ACTIVE = "authorized_active"


Severity = Literal["info", "low", "medium", "high", "critical"]


class PassiveDiscoveryRequest(BaseModel):
    target: HttpUrl
    use_ai: bool = False


class AuthorizationAttestation(BaseModel):
    acknowledged: Literal[True]
    statement: str = Field(
        default="I own this target or am explicitly authorized to test it.",
        min_length=10,
        max_length=500,
    )


class ActiveScanRequest(BaseModel):
    target: HttpUrl
    authorization: AuthorizationAttestation
    provider: str | None = Field(default=None, max_length=50)
    profile: str | None = Field(default=None, max_length=100)
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
    disclaimer: str = "Only assess APIs you own or are explicitly authorized to test."


class ScannerCapability(BaseModel):
    provider: str
    configured: bool
    available: bool
    status: Literal["ready", "not-configured", "disabled", "unavailable"]
    detail: str


class ActiveScanJob(BaseModel):
    id: str | None = None
    scan_mode: ScanMode = ScanMode.AUTHORIZED_ACTIVE
    target: str
    provider: str
    status: Literal[
        "authorization-required",
        "target-outside-approved-scope",
        "not-configured",
        "zap-unavailable",
        "queued",
        "running",
        "completed",
        "failed",
        "cancelled",
    ]
    capability: ScannerCapability
    findings: list[Finding] = Field(default_factory=list)
    detail: str
    progress: int = Field(default=0, ge=0, le=100)
    timeline: list[dict[str, Any]] = Field(default_factory=list)
    report: ScanReport | None = None
