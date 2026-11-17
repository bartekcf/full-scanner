from __future__ import annotations

import asyncio
import base64
import logging
import time
import platform
from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin, urlsplit

from app.url_policy import TargetValidationError, validate_target_with_addresses

import httpx

from app.config import Settings
from app.technology import fingerprint_response, inspect_http_headers
from app.models import Finding

logger = logging.getLogger(__name__)


class ZapError(RuntimeError):
    code = "zap_unavailable"


class TargetTimedOut(ZapError):
    code = "target_timeout"


class TargetUnavailable(ZapError):
    code = "target_unavailable"


class RedirectError(ZapError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class PassiveScanTimedOut(ZapError):
    code = "passive_scan_timeout"


@dataclass(frozen=True)
class TargetObservation:
    status_code: int
    headers: dict[str, str]
    body: bytes


@dataclass(frozen=True)
class ScanOutcome:
    final_url: str
    dns_addresses: list[str]
    redirects: list[dict[str, Any]]
    summary: dict[str, int]
    findings: list[Finding]
    technologies: list[dict[str, Any]]
    http_checks: list[dict[str, str]]
    http_status: int
    tool_versions: dict[str, str]

class ZapClient:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._api: httpx.AsyncClient | None = None
        self.zap_version = "unknown"
        self.raw: dict[str, Any] = {}

    async def start(self) -> None:
        self._api = httpx.AsyncClient(
            base_url=self.settings.zap_api_url,
            timeout=httpx.Timeout(6.0, connect=3.0),
            trust_env=False,
            headers={"X-ZAP-API-Key": self.settings.zap_api_key},
        )
        try:
            await self._request_api(
                "network",
                "action",
                "setHttpProxy",
                {"host": "egress-zap", "port": "3128", "realm": "", "username": "", "password": ""},
            )
            await self._request_api("network", "action", "setHttpProxyEnabled", {"enabled": "true"})
            if not await self._egress_proxy_ready():
                raise ZapError()
            version_payload = await self._request_api("core", "view", "version")
            self.zap_version = str(version_payload.get("version") or "unknown")
        except Exception:
            await self.close()
            raise

    async def close(self) -> None:
        if self._api is not None:
            await self._api.aclose()
            self._api = None

    async def _request_api(self, component: str, kind: str, operation: str, params: dict[str, str] | None = None) -> dict[str, Any]:
        if self._api is None:
            raise ZapError()
        query = dict(params or {})
        try:
            response = await self._api.get(f"/JSON/{component}/{kind}/{operation}/", params=query)
            response.raise_for_status()
            payload = response.json()
        except (httpx.HTTPError, ValueError):
            logger.warning("ZAP API request failed (%s/%s/%s)", component, kind, operation)
            raise ZapError() from None
        if not isinstance(payload, dict) or ("code" in payload and "message" in payload):
            logger.warning("ZAP API returned an error (%s/%s/%s)", component, kind, operation)
            raise ZapError()
        return payload

    async def _egress_proxy_ready(self) -> bool:
        proxy_payload = await self._request_api("network", "view", "getHttpProxy")
        enabled_payload = await self._request_api("network", "view", "isHttpProxyEnabled")
        proxy = proxy_payload.get("getHttpProxy")
        return (
            isinstance(proxy, dict)
            and proxy.get("host") == "egress-zap"
            and str(proxy.get("port")) == "3128"
            and enabled_payload.get("isHttpProxyEnabled") == "true"
        )

    async def is_ready(self) -> bool:
        try:
            payload = await self._request_api("core", "view", "version")
            return bool(payload.get("version")) and await self._egress_proxy_ready()
        except ZapError:
            return False

    async def scan(self, url: str, dns_addresses: list[str]) -> ScanOutcome:
        await self._wait_for_passive_scan()
        await self._request_api("core", "action", "newSession", {"name": "passive-scanner", "overwrite": "true"})
        await self._request_api("pscan", "action", "setEnabled", {"enabled": "true"})
        await self._request_api("pscan", "action", "enableAllScanners")
        await self._request_api(
            "pscan",
            "action",
            "setMaxBodySizeInBytes",
            {"maxSize": str(self.settings.max_response_bytes)},
        )
        redirects: list[dict[str, Any]] = []
        self.raw["redirects"] = redirects
        visited = {url}
        while True:
            self.raw["last_requested_url"] = url
            target = await self._fetch_target_once(url)
            self.raw["response"] = {
                "status": target.status_code,
                "headers": target.headers,
                "body_base64": base64.b64encode(target.body).decode(),
                "capture_limit_bytes": self.settings.max_response_bytes,
            }
            if target.status_code == 502 and target.body.startswith(b"ZAP Error ["):
                raise TargetUnavailable()
            if target.status_code not in {301, 302, 303, 307, 308}:
                break

            location = target.headers.get("location")
            hop = {"url": url, "status": target.status_code, "location": location}
            redirects.append(hop)
            if len(redirects) > 5:
                raise RedirectError("redirect_limit")
            if not location or not location.strip():
                raise RedirectError("redirect_missing_location")
            try:
                next_url, next_addresses = await validate_target_with_addresses(
                    urljoin(url, location), self.settings.dns_timeout_seconds
                )
            except (TargetValidationError, ValueError) as exc:
                hop["error"] = getattr(exc, "code", "invalid_url")
                raise RedirectError("redirect_target_rejected") from exc
            hop["next_url"] = next_url
            hop["https_to_http"] = urlsplit(url).scheme == "https" and urlsplit(next_url).scheme == "http"
            if next_url in visited:
                raise RedirectError("redirect_loop")
            visited.add(next_url)

            # Drain the passive queue and reset history before analyzing the next response.
            await self._wait_for_passive_scan()
            await self._request_api("core", "action", "newSession", {"name": "passive-scanner", "overwrite": "true"})
            url, dns_addresses = next_url, list(next_addresses)
        technologies = fingerprint_response(target.headers, target.body)
        http_checks = inspect_http_headers(target.headers, url.split(":", 1)[0])
        await self._wait_for_passive_scan()
        findings = await self._fetch_alerts()
        counts = {"high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in findings:
            if finding.severity in counts:
                counts[finding.severity] += 1
        return ScanOutcome(
            final_url=url,
            dns_addresses=dns_addresses,
            redirects=redirects,
            summary=counts,
            findings=findings,
            technologies=technologies,
            http_checks=http_checks,
            http_status=target.status_code,
            tool_versions={
                "OWASP ZAP": self.zap_version,
                "httpx": httpx.__version__,
                "Python": platform.python_version(),
            },
        )

    async def _fetch_target_once(self, url: str) -> TargetObservation:
        timeout = httpx.Timeout(float(self.settings.target_timeout_seconds), connect=8.0)
        try:
            async with asyncio.timeout(self.settings.target_timeout_seconds):
                async with httpx.AsyncClient(
                    proxy=self.settings.zap_proxy_url,
                    timeout=timeout,
                    follow_redirects=False,
                    verify=False,
                    trust_env=False,
                    headers={
                        "User-Agent": "PassiveSecurityScanner/1.0",
                        "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.1",
                        "Accept-Encoding": "identity",
                    },
                ) as client:
                    async with client.stream("GET", url) as response:
                        body = bytearray()
                        content_length = response.headers.get("content-length")
                        try:
                            oversized = content_length is not None and int(content_length) > self.settings.max_response_bytes
                        except ValueError:
                            raise TargetUnavailable()
                        if not oversized:
                            async for chunk in response.aiter_raw():
                                remaining = self.settings.max_response_bytes - len(body)
                                if len(chunk) > remaining:
                                    body.extend(chunk[:remaining])
                                    break
                                body.extend(chunk)
                        return TargetObservation(
                            status_code=response.status_code,
                            headers=dict(response.headers),
                            body=bytes(body),
                        )
        except (asyncio.TimeoutError, httpx.TimeoutException) as exc:
            raise TargetTimedOut() from exc
        except httpx.HTTPError as exc:
            raise TargetUnavailable() from exc

    async def _wait_for_passive_scan(self) -> None:
        deadline = time.monotonic() + self.settings.passive_scan_timeout_seconds
        consecutive_idle_reads = 0
        while time.monotonic() < deadline:
            payload = await self._request_api("pscan", "view", "recordsToScan")
            tasks_payload = await self._request_api("pscan", "view", "currentTasks")
            try:
                remaining = int(payload["recordsToScan"])
                tasks = tasks_payload["currentTasks"]
            except (KeyError, TypeError, ValueError):
                raise ZapError() from None
            if not isinstance(tasks, list):
                raise ZapError()
            if remaining == 0 and not tasks:
                consecutive_idle_reads += 1
                if consecutive_idle_reads >= 2:
                    return
            else:
                consecutive_idle_reads = 0
            await asyncio.sleep(0.5)
        raise PassiveScanTimedOut()

    async def _fetch_alerts(self) -> list[Finding]:
        findings: list[Finding] = []
        start = 0
        page_size = 1000
        while True:
            payload = await self._request_api(
                "core",
                "view",
                "alerts",
                {"start": str(start), "count": str(page_size)},
            )
            alerts = payload.get("alerts")
            if not isinstance(alerts, list):
                raise ZapError()
            self.raw.setdefault("alerts", []).extend(alerts)
            for alert in alerts:
                if not isinstance(alert, dict):
                    continue
                plugin_id = alert.get("pluginId")
                if plugin_id is None:
                    raise ZapError()
                risk = str(alert.get("risk", "unknown")).strip().lower()
                severity = "info" if risk == "informational" else risk or "unknown"
                findings.append(
                    Finding(
                        id=str(plugin_id),
                        title=str(alert.get("name", "")),
                        severity=severity,
                        confidence=str(alert.get("confidence", "unknown")),
                        description=str(alert.get("description", "")),
                        evidence=str(alert.get("evidence", "")),
                        recommendation=str(alert.get("solution", "")),
                        url=str(alert.get("url", "")),
                    )
                )
            if len(alerts) < page_size:
                return findings
            start += len(alerts)
