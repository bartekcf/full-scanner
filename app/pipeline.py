from __future__ import annotations

import logging
from dataclasses import dataclass, asdict
from typing import Any

from app.config import EGRESS_PROXY_URL
from app.cve import CveIntelligence
from app.models import Finding
from app.tls_metadata import collect_tls_metadata
from app.zap import ScanOutcome, ZapClient
from app.fingerprint_tools import run_bounded_http_fingerprint, run_projectdiscovery_httpx
from app.technology import merge_observations, normalize_tool_observation

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class AuditOutcome:
    final_url: str
    redirects: list[dict[str, Any]]
    raw_tools: dict[str, Any]
    summary: dict[str, int]
    findings: list[Finding]
    technologies: list[dict[str, Any]]
    cves: list[dict[str, Any]]
    http_checks: list[dict[str, str]]
    checks: list[dict[str, str]]
    errors: list[str]
    http_status: int
    tool_versions: dict[str, str]
    dns_addresses: list[str]
    tls_metadata: dict[str, Any]

async def run_audit(
    url: str,
    zap: ZapClient,
    cve_intelligence: CveIntelligence,
    *,
    dns_addresses: list[str] | None = None,
    egress_proxy_url: str = EGRESS_PROXY_URL,
    enable_projectdiscovery_httpx: bool = False,
    enable_bounded_http_fingerprint: bool = False,
    fingerprint_tool_timeout_seconds: int = 15,
    max_response_bytes: int = 2_000_000,
) -> AuditOutcome:
    """Run the shared, low-impact audit pipeline; all external requests use approved proxies."""
    scan: ScanOutcome = await zap.scan(url, list(dns_addresses or []))
    url = scan.final_url
    raw_tools = {}
    observations = list(scan.technologies)
    tool_versions = dict(scan.tool_versions)
    errors: list[str] = []
    tool_checks: list[dict[str, str]] = []
    tool_specs = (
        ("projectdiscovery_httpx", "ProjectDiscovery httpx", enable_projectdiscovery_httpx, run_projectdiscovery_httpx, False),
        ("bounded_http_fingerprint", "Bounded HTTP fingerprint", enable_bounded_http_fingerprint, run_bounded_http_fingerprint, True),
    )
    for source, label, enabled, runner, normalized in tool_specs:
        if not enabled:
            tool_checks.append(
                {"check": source, "status": "disabled", "detail": "disabled_by_configuration"}
            )
            continue
        try:
            if normalized:
                tool_result = await runner(
                    url, egress_proxy_url, fingerprint_tool_timeout_seconds, max_response_bytes
                )
            else:
                tool_result = await runner(url, egress_proxy_url, fingerprint_tool_timeout_seconds)
        except Exception as exc:
            logger.warning("Fingerprint tool %s failed (%s)", source, type(exc).__name__)
            tool_result = None
            tool_error = "tool_failed"
        else:
            tool_error = tool_result.error
        raw_tools[source] = asdict(tool_result) if tool_result is not None else {"error": tool_error}
        if tool_result is not None:
            tool_versions[label] = tool_result.tool_version
        if tool_result is None or tool_error:
            safe_error = tool_error if tool_error in {
                "proxy_required", "tool_unavailable", "tool_timeout", "tool_output_too_large",
                "response_size_limit", "content_encoding_unsupported", "tool_failed"
            } else "tool_failed"
            errors.append(f"{source}_{safe_error}")
            if tool_result is not None and tool_result.normalized:
                observations.extend(tool_result.observations)
            tool_checks.append({"check": source, "status": "partial", "detail": safe_error})
            continue
        if tool_result.normalized:
            observations.extend(tool_result.observations)
        else:
            for item in tool_result.observations:
                technology = normalize_tool_observation(item, source)
                if technology is not None:
                    observations.append(technology)
        tool_checks.append(
            {
                "check": source,
                "status": "completed",
                "detail": f"one bounded target request through egress proxy; {len(tool_result.observations)} observations",
            }
        )

    technologies = merge_observations(observations)
    tls_metadata = await collect_tls_metadata(url, egress_proxy_url, timeout_seconds=8.0)
    try:
        cve_result = await cve_intelligence.correlate(technologies)
        cve_errors = list(cve_result.errors)
        cves = cve_result.cves
    except Exception as exc:
        logger.warning("CVE correlation failed (%s)", type(exc).__name__)
        cve_errors = ["cve_intelligence_unavailable"]
        cves = []
    errors.extend(cve_errors)
    if tls_metadata.get("status") == "error":
        errors.append("tls_metadata_" + str(tls_metadata.get("error_code") or "unavailable"))

    summary = dict(scan.summary)
    summary.update(
        {
            "technologies_detected": len(technologies),
            "versioned_technologies": sum(1 for technology in technologies if technology.get("version")),
            "potential_cves": sum(
                1 for cve in cves if cve.get("match_status") in {"confirmed_affected_version", "potentially_affected"}
            ),
            "zap_findings": len(scan.findings),
        }
    )
    validated_addresses = sorted(set(scan.dns_addresses))
    checks = [
        {
            "check": "single_http_get",
            "status": "completed",
            "detail": "bounded ZAP requests with validated redirects; fingerprint tools request the final URL without following redirects",
        },
        {
            "check": "technology_fingerprinting",
            "status": "completed",
            "detail": "response signatures merged with individually enabled fingerprint tools; conflicts retained",
        },
        {"check": "owasp_zap_passive", "status": "completed", "detail": "passive rules evaluated on the ZAP response"},
        *tool_checks,
        {
            "check": "cve_correlation",
            "status": "partial" if cve_errors else "completed",
            "detail": "exact-product and version-gated vulnerability sources",
        },
        {
            "check": "dns_metadata",
            "status": "completed" if validated_addresses else "not_collected",
            "detail": (
                "public IPs observed during final URL validation: " + ", ".join(validated_addresses)
                + "; egress proxy resolves the hostname independently"
                if validated_addresses
                else "DNS was not resolved or no validation addresses were supplied"
            ),
        },
        {
            "check": "tls_certificate_metadata",
            "status": (
                "not_applicable"
                if tls_metadata.get("status") == "not_applicable"
                else "completed"
                if tls_metadata.get("status") == "ok"
                else "failed"
            ),
            "detail": (
                f"TLS {tls_metadata.get('tls_version')} via egress proxy; peer certificate verification "
                f"{'passed' if tls_metadata.get('verified') else 'not passed'}"
                if tls_metadata.get("status") == "ok"
                else "no TLS metadata: " + str(tls_metadata.get("error_code") or tls_metadata.get("status"))
            ),
        },
        {"check": "active_testing", "status": "not_run", "detail": "no spider, active scan, port scan, or exploit checks are run"},
    ]
    return AuditOutcome(
        final_url=url,
        redirects=scan.redirects,
        raw_tools=raw_tools,
        summary=summary,
        findings=scan.findings,
        technologies=technologies,
        cves=cves,
        http_checks=scan.http_checks,
        checks=checks,
        errors=errors,
        http_status=scan.http_status,
        tool_versions=tool_versions,
        dns_addresses=validated_addresses,
        tls_metadata=tls_metadata,
    )
