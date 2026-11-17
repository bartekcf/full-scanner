from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class ScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    url: str = Field(min_length=8, max_length=2048)
    profile: Literal["public"] = "public"
    authorization_ref: str | None = Field(
        default=None,
        max_length=256,
        description="Informational only; not proof of authorization.",
    )

class ScanAccepted(BaseModel):
    scan_id: str
    status: Literal["queued"]


class Summary(BaseModel):
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    technologies_detected: int = 0
    versioned_technologies: int = 0
    potential_cves: int = 0
    zap_findings: int = 0


class TechnologyEvidence(BaseModel):
    type: str
    name: str
    value: str


class Technology(BaseModel):
    name: str
    vendor: str
    category: str
    version: str | None = None
    version_status: Literal["verified", "declared", "fingerprinted", "partial", "unknown"]
    confidence: Literal["high", "medium", "low"]
    sources: list[str] = Field(default_factory=list)
    evidence: list[TechnologyEvidence] = Field(default_factory=list)
    is_edge: bool | None = None
    version_conflict: bool = False
    observed_versions: list[str] = Field(default_factory=list)
    cpe: str | None = None


class CveFinding(BaseModel):
    cve_id: str | None = None
    product: str
    detected_version: str
    match_status: Literal[
        "confirmed_affected_version", "potentially_affected", "insufficient_evidence", "not_affected"
    ]
    cvss_score: float | None = None
    cvss_version: str | None = None
    severity: str | None = None
    epss: float | None = None
    epss_date: str | None = None
    cisa_kev: bool | None = None
    description: str = ""
    affected_range: str = ""
    recommended_version: str | None = None
    confidence: Literal["high", "medium", "low"]
    sources: list[str] = Field(default_factory=list)
    source_updated_at: str | None = None
    technology_name: str
    advisory_ids: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    vendor_advisories: list[str] = Field(default_factory=list)
    source_update_dates: dict[str, str] = Field(default_factory=dict)
    backport_status: str = "unknown"
    backport_note: str | None = None


class HttpCheck(BaseModel):
    check: str
    status: str
    evidence: str
    recommendation: str


class AuditCheck(BaseModel):
    check: str
    status: str
    detail: str


class Finding(BaseModel):
    id: str
    title: str
    severity: str
    confidence: str
    description: str
    evidence: str
    recommendation: str
    url: str


class ScanDetails(BaseModel):
    scan_id: str
    url: str
    status: Literal["queued", "running", "completed", "failed"]
    profile: Literal["public"] = "public"
    http_status: int | None = None
    dns_addresses: list[str] = Field(default_factory=list)
    tls_metadata: dict[str, Any] | None = None
    created_at: datetime | None = None
    tool_versions: dict[str, str] = Field(default_factory=dict)
    summary: Summary
    findings: list[Finding]
    technologies: list[Technology] = Field(default_factory=list)
    cves: list[CveFinding] = Field(default_factory=list)
    http_checks: list[HttpCheck] = Field(default_factory=list)
    checks: list[AuditCheck] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    error: str | None = None
