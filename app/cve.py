from __future__ import annotations

import asyncio
import json
import logging
import re
import sqlite3
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import cmp_to_key
from pathlib import Path
from typing import Any

import httpx

logger = logging.getLogger(__name__)

NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
OSV_QUERY_URL = "https://api.osv.dev/v1/query"
GITHUB_ADVISORIES_URL = "https://api.github.com/advisories"
_IGNORED_CVE_IDS = frozenset({"CVE-2007-3205"})
_OSV_PACKAGES: dict[str, tuple[str, str, str]] = {
    "react": ("npm", "react", "npm"),
    "next.js": ("npm", "next", "npm"),
    "vue.js": ("npm", "vue", "npm"),
    "nuxt": ("npm", "nuxt", "npm"),
    "angular": ("npm", "@angular/core", "npm"),
    "svelte": ("npm", "svelte", "npm"),
    "jquery": ("npm", "jquery", "npm"),
    "bootstrap": ("npm", "bootstrap", "npm"),
    "alpine.js": ("npm", "alpinejs", "npm"),
    "tailwind css": ("npm", "tailwindcss", "npm"),
    "laravel": ("Packagist", "laravel/framework", "composer"),
    "symfony": ("Packagist", "symfony/symfony", "composer"),
    "yii": ("Packagist", "yiisoft/yii2", "composer"),
    "codeigniter": ("Packagist", "codeigniter4/framework", "composer"),
    "cakephp": ("Packagist", "cakephp/cakephp", "composer"),
    "drupal": ("Packagist", "drupal/core", "composer"),
    "joomla": ("Packagist", "joomla/joomla-cms", "composer"),
    "magento": ("Packagist", "magento/product-community-edition", "composer"),
    "prestashop": ("Packagist", "prestashop/prestashop", "composer"),
    "django": ("PyPI", "Django", "pip"),
    "flask": ("PyPI", "Flask", "pip"),
    "fastapi": ("PyPI", "fastapi", "pip"),
    "spring": ("Maven", "org.springframework:spring-core", "maven"),
    "spring boot": ("Maven", "org.springframework.boot:spring-boot", "maven"),
}
_CACHE_TTL_SECONDS = 24 * 60 * 60
_MAX_SOURCE_RESPONSE_BYTES = 4 * 1024 * 1024


@dataclass(frozen=True)
class CveOutcome:
    cves: list[dict[str, Any]]
    errors: list[str]


def _version_parts(value: str) -> tuple[tuple[int, ...], tuple[tuple[int, str], ...]]:
    candidate = value.strip().lstrip("vV")
    match = re.fullmatch(r"(\d+(?:\.\d+)*)(.*)", candidate)
    if not match:
        raise ValueError("unsupported version")
    release = tuple(int(item) for item in match.group(1).split("."))
    suffix = match.group(2).strip(" ._-+").lower()
    suffix_tokens: list[tuple[int, str]] = []
    for token in re.findall(r"\d+|[a-z]+", suffix):
        suffix_tokens.append((0, f"{int(token):020d}") if token.isdigit() else (1, token))
    return release, tuple(suffix_tokens)


def compare_versions(left: str, right: str) -> int:
    """Compare common dotted numeric releases and prerelease suffixes without guessing on invalid inputs."""
    left_release, left_suffix = _version_parts(left)
    right_release, right_suffix = _version_parts(right)
    width = max(len(left_release), len(right_release))
    left_padded = left_release + (0,) * (width - len(left_release))
    right_padded = right_release + (0,) * (width - len(right_release))
    if left_padded != right_padded:
        return -1 if left_padded < right_padded else 1
    if not left_suffix and not right_suffix:
        return 0
    if not left_suffix:
        return 1
    if not right_suffix:
        return -1

    ranks = {"dev": 0, "snapshot": 0, "alpha": 1, "a": 1, "beta": 2, "b": 2, "rc": 3, "pre": 3, "preview": 3}

    def suffix_key(tokens: tuple[tuple[int, str], ...]) -> tuple[tuple[int, Any], ...]:
        return tuple(
            (0, int(token)) if kind == 0 else (1, ranks.get(token, 4), token)
            for kind, token in tokens
        )

    left_key = suffix_key(left_suffix)
    right_key = suffix_key(right_suffix)
    return (left_key > right_key) - (left_key < right_key)


def version_in_range(
    version: str,
    *,
    criteria_version: str = "*",
    version_start_including: str | None = None,
    version_start_excluding: str | None = None,
    version_end_including: str | None = None,
    version_end_excluding: str | None = None,
) -> bool | None:
    """Return None if a supplied version bound cannot be compared safely."""
    try:
        if criteria_version not in {"*", "-"} and compare_versions(version, criteria_version) != 0:
            return False
        if version_start_including and compare_versions(version, version_start_including) < 0:
            return False
        if version_start_excluding and compare_versions(version, version_start_excluding) <= 0:
            return False
        if version_end_including and compare_versions(version, version_end_including) > 0:
            return False
        if version_end_excluding and compare_versions(version, version_end_excluding) >= 0:
            return False
    except ValueError:
        return None
    return True


def _split_cpe(criteria: str) -> tuple[str, str, str] | None:
    fields = criteria.split(":")
    if len(fields) < 6 or fields[0:2] != ["cpe", "2.3"]:
        return None
    return fields[2].lower(), fields[3].lower(), fields[4].lower()


def _walk_matches(value: Any, in_complex_condition: bool = False) -> list[tuple[dict[str, Any], bool]]:
    matches: list[tuple[dict[str, Any], bool]] = []
    if isinstance(value, list):
        for item in value:
            matches.extend(_walk_matches(item, in_complex_condition))
    elif isinstance(value, dict):
        operator = str(value.get("operator", "OR")).upper()
        complex_condition = in_complex_condition or operator == "AND" or bool(value.get("negate"))
        cpe_matches = value.get("cpeMatch")
        if isinstance(cpe_matches, list):
            for item in cpe_matches:
                if isinstance(item, dict):
                    matches.append((item, complex_condition))
        for key, child in value.items():
            if key in {"cpeMatch", "operator", "negate"}:
                continue
            matches.extend(_walk_matches(child, complex_condition))
    return matches


def match_cve_version(
    cve_item: dict[str, Any],
    *,
    vendor: str,
    product: str,
    version: str,
    part: str = "a",
) -> tuple[bool, bool]:
    """Return (version matched, context conditions need review) for NVD configurations."""
    configurations = cve_item.get("configurations", [])
    if not isinstance(configurations, list):
        return False, False
    saw_product = False
    conditions_unverified = False
    for match, complex_condition in _walk_matches(configurations):
        if match.get("vulnerable") is not True:
            continue
        cpe = _split_cpe(str(match.get("criteria", "")))
        if cpe is None or cpe[0] != part.lower() or cpe[1] != vendor.lower() or cpe[2] != product.lower():
            continue
        saw_product = True
        criteria_version = str(match.get("criteria", "")).split(":")[5]
        in_range = version_in_range(
            version,
            criteria_version=criteria_version,
            version_start_including=match.get("versionStartIncluding"),
            version_start_excluding=match.get("versionStartExcluding"),
            version_end_including=match.get("versionEndIncluding"),
            version_end_excluding=match.get("versionEndExcluding"),
        )
        if in_range is True:
            conditions_unverified = conditions_unverified or complex_condition
            return True, conditions_unverified
        if in_range is None:
            conditions_unverified = True
    return False, conditions_unverified if saw_product else False


def _version_from_cpe(cpe: str) -> str | None:
    fields = cpe.split(":")
    if len(fields) != 13 or fields[:2] != ["cpe", "2.3"] or fields[5] in {"*", "-"}:
        return None
    return fields[5]


def _cvss(cve: dict[str, Any]) -> tuple[float | None, str | None, str | None]:
    metrics = cve.get("metrics", {})
    if not isinstance(metrics, dict):
        return None, None, None
    for key, version in (("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0")):
        entries = metrics.get(key)
        if not isinstance(entries, list) or not entries:
            continue
        data = entries[0]
        if not isinstance(data, dict):
            continue
        cvss_data = data.get("cvssData", {})
        if not isinstance(cvss_data, dict):
            continue
        try:
            score = float(cvss_data["baseScore"])
        except (KeyError, TypeError, ValueError):
            score = None
        severity = data.get("baseSeverity") or cvss_data.get("baseSeverity")
        return score, version, str(severity).lower() if severity else None
    return None, None, None


def _description(cve: dict[str, Any]) -> str:
    descriptions = cve.get("descriptions", [])
    if not isinstance(descriptions, list):
        return ""
    for item in descriptions:
        if isinstance(item, dict) and item.get("lang") == "en" and isinstance(item.get("value"), str):
            return item["value"][:2000]
    for item in descriptions:
        if isinstance(item, dict) and isinstance(item.get("value"), str):
            return item["value"][:2000]
    return ""


def _range_text(match: dict[str, Any]) -> str:
    parts = [str(match.get("criteria", ""))]
    for key in ("versionStartIncluding", "versionStartExcluding", "versionEndIncluding", "versionEndExcluding"):
        value = match.get(key)
        if value:
            parts.append(f"{key}={value}")
    return "; ".join(parts)


def _osv_version_match(
    vulnerability: dict[str, Any],
    *,
    ecosystem: str,
    package_name: str,
    version: str,
) -> bool | None:
    affected_entries = vulnerability.get("affected", [])
    if not isinstance(affected_entries, list):
        return None
    saw_package = False
    saw_comparable_range = False
    for affected in affected_entries:
        if not isinstance(affected, dict):
            continue
        package = affected.get("package")
        if not isinstance(package, dict) or package.get("ecosystem") != ecosystem or package.get("name") != package_name:
            continue
        saw_package = True
        versions = affected.get("versions", [])
        if isinstance(versions, list) and version in versions:
            return True
        ranges = affected.get("ranges", [])
        if not isinstance(ranges, list):
            continue
        for version_range in ranges:
            if not isinstance(version_range, dict) or version_range.get("type") not in {
                "SEMVER", "ECOSYSTEM", "UNIVERSAL"
            }:
                continue
            events = version_range.get("events")
            if not isinstance(events, list):
                continue
            result = _osv_events_match(version, events)
            if result is not None:
                saw_comparable_range = True
                if result:
                    return True
    if saw_comparable_range or saw_package:
        return False if saw_comparable_range else None
    return None


def _osv_events_match(version: str, events: list[Any]) -> bool | None:
    affected = False
    saw_event = False
    try:
        for event in events:
            if not isinstance(event, dict) or len(event) != 1:
                return None
            key, bound = next(iter(event.items()))
            if not isinstance(bound, str):
                return None
            saw_event = True
            if key == "introduced":
                affected = bound in {"0", "*"} or compare_versions(version, bound) >= 0
            elif key == "fixed":
                if compare_versions(version, bound) < 0:
                    return affected
                affected = False
            elif key == "last_affected":
                if compare_versions(version, bound) <= 0:
                    return affected
                affected = False
            elif key == "limit":
                if compare_versions(version, bound) < 0:
                    return affected
                affected = False
            else:
                return None
    except ValueError:
        return None
    return affected if saw_event else None


def _github_range_match(version: str, expression: str) -> bool | None:
    if not expression or len(expression) > 512:
        return None
    alternatives = expression.split("||")
    saw_supported = False
    for alternative in alternatives:
        value = alternative.strip()
        if not value:
            return None
        hyphen = re.fullmatch(
            r"(v?\d+(?:\.\d+)*(?:-[A-Za-z0-9.-]+)?)\s+-\s+(v?\d+(?:\.\d+)*(?:-[A-Za-z0-9.-]+)?)",
            value,
        )
        try:
            if hyphen:
                lower, upper = hyphen.groups()
                saw_supported = True
                if compare_versions(version, lower) >= 0 and compare_versions(version, upper) <= 0:
                    return True
                continue
            tokens = re.split(r"[\s,]+", value)
            position = 0
            matches = True
            while position < len(tokens):
                token = tokens[position]
                if not token:
                    position += 1
                    continue
                if token in {">", ">=", "<", "<=", "=", "^", "~", "~>"}:
                    position += 1
                    if position >= len(tokens):
                        return None
                    operator = token
                    bound = tokens[position]
                else:
                    match = re.fullmatch(r"(<=|>=|~>|<|>|=|\^|~)?(.*)", token)
                    if match is None:
                        return None
                    operator, bound = match.groups()
                    operator = operator or "="
                position += 1
                if bound in {"*", "x", "X"}:
                    saw_supported = True
                    continue
                wildcard = re.fullmatch(r"(\d+(?:\.\d+)*)(?:\.[xX*])+", bound)
                if wildcard:
                    if operator != "=":
                        return None
                    prefix = tuple(int(part) for part in wildcard.group(1).split("."))
                    release, _ = _version_parts(version)
                    saw_supported = True
                    if release[: len(prefix)] != prefix:
                        matches = False
                    continue
                if not re.fullmatch(r"v?\d+(?:\.\d+)*(?:-[A-Za-z0-9.-]+)?", bound):
                    return None
                saw_supported = True
                if operator in {"^", "~", "~>"}:
                    base = bound.lstrip("v")
                    parts = [int(part) for part in base.split("-", 1)[0].split(".")]
                    if operator == "^":
                        if parts[0] > 0:
                            upper_parts = [parts[0] + 1, 0, 0]
                        elif len(parts) > 1 and parts[1] > 0:
                            upper_parts = [0, parts[1] + 1, 0]
                        else:
                            upper_parts = [0, 0, (parts[2] if len(parts) > 2 else 0) + 1]
                    elif len(parts) == 1:
                        upper_parts = [parts[0] + 1, 0, 0]
                    else:
                        upper_parts = [parts[0], parts[1] + 1, 0]
                    lower_ok = compare_versions(version, base) >= 0
                    upper_ok = compare_versions(version, ".".join(map(str, upper_parts))) < 0
                    matches = matches and lower_ok and upper_ok
                    continue
                comparison = compare_versions(version, bound)
                matches = matches and {
                    "=": comparison == 0,
                    ">": comparison > 0,
                    ">=": comparison >= 0,
                    "<": comparison < 0,
                    "<=": comparison <= 0,
                }[operator]
            if matches and saw_supported:
                return True
        except (KeyError, ValueError):
            return None
    return False if saw_supported else None


def _advisory_references(items: Any) -> list[str]:
    if not isinstance(items, list):
        return []
    references: list[str] = []
    for item in items:
        url = item.get("url") if isinstance(item, dict) else item
        if isinstance(url, str) and url.startswith(("https://", "http://")) and len(url) <= 2048:
            if url not in references:
                references.append(url)
        if len(references) >= 100:
            break
    return references


def _fixed_versions(vulnerability: dict[str, Any], ecosystem: str, package_name: str) -> list[str]:
    versions: set[str] = set()
    for affected in vulnerability.get("affected", []):
        if not isinstance(affected, dict):
            continue
        package = affected.get("package")
        if not isinstance(package, dict) or package.get("ecosystem") != ecosystem or package.get("name") != package_name:
            continue
        for version_range in affected.get("ranges", []):
            if not isinstance(version_range, dict):
                continue
            for event in version_range.get("events", []):
                if isinstance(event, dict) and isinstance(event.get("fixed"), str):
                    versions.add(event["fixed"])
    comparable: list[str] = []
    for version in versions:
        try:
            compare_versions(version, version)
        except ValueError:
            continue
        comparable.append(version)
    return sorted(comparable, key=cmp_to_key(compare_versions))


class CveIntelligence:
    def __init__(
        self,
        cache_path: str,
        proxy_url: str,
        api_key: str | None = None,
        github_token: str | None = None,
        *,
        nvd_min_interval: float = 6.0,
        github_min_interval: float = 1.0,
    ):
        self.cache_path = cache_path
        self.proxy_url = proxy_url
        self.api_key = api_key
        self.github_token = github_token
        self.nvd_min_interval = max(0.0, nvd_min_interval)
        self.github_min_interval = max(0.0, github_min_interval)
        self._client: httpx.AsyncClient | None = None
        self._db: sqlite3.Connection | None = None
        self._nvd_lock = asyncio.Lock()
        self._github_lock = asyncio.Lock()
        self._last_nvd_request = 0.0
        self._last_github_request = 0.0
        self._cache_unavailable = False

    async def start(self) -> None:
        try:
            path = Path(self.cache_path)
            if self.cache_path != ":memory:":
                path.parent.mkdir(parents=True, exist_ok=True)
            self._db = sqlite3.connect(self.cache_path)
            self._db.execute(
                "CREATE TABLE IF NOT EXISTS json_cache (cache_key TEXT PRIMARY KEY, updated_at REAL NOT NULL, payload TEXT NOT NULL)"
            )
            self._db.commit()
        except (OSError, sqlite3.Error):
            logger.error("CVE cache unavailable; using an in-memory cache")
            if self._db is not None:
                self._db.close()
            self._db = sqlite3.connect(":memory:")
            self._db.execute(
                "CREATE TABLE IF NOT EXISTS json_cache (cache_key TEXT PRIMARY KEY, updated_at REAL NOT NULL, payload TEXT NOT NULL)"
            )
            self._db.commit()
            self._cache_unavailable = True
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(12.0, connect=5.0),
            proxy=self.proxy_url,
            follow_redirects=False,
            trust_env=False,
            headers={
                "User-Agent": "PassiveSecurityScanner/1.0",
                "Accept": "application/json",
                "Accept-Encoding": "identity",
            },
        )

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None
        if self._db is not None:
            self._db.close()
            self._db = None

    def _cache_get(
        self,
        key: str,
        *,
        allow_stale: bool = False,
        ttl: int = _CACHE_TTL_SECONDS,
    ) -> tuple[dict[str, Any] | None, bool]:
        if self._db is None:
            return None, False
        row = self._db.execute("SELECT updated_at, payload FROM json_cache WHERE cache_key = ?", (key,)).fetchone()
        if row is None:
            return None, False
        updated_at, encoded = row
        try:
            payload = json.loads(encoded)
        except (TypeError, ValueError):
            return None, False
        if not isinstance(payload, dict):
            return None, False
        fresh = time.time() - float(updated_at) < ttl
        if fresh or allow_stale:
            return payload, fresh
        return None, False

    def _cache_put(self, key: str, payload: dict[str, Any]) -> None:
        if self._db is None:
            return
        self._db.execute(
            "INSERT INTO json_cache(cache_key, updated_at, payload) VALUES(?, ?, ?) "
            "ON CONFLICT(cache_key) DO UPDATE SET updated_at=excluded.updated_at, payload=excluded.payload",
            (key, time.time(), json.dumps(payload, separators=(",", ":"))),
        )
        self._db.commit()

    async def _request_bounded_json(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        json_body: dict[str, Any] | None = None,
    ) -> tuple[int, dict[str, str], dict[str, Any] | None]:
        if self._client is None:
            raise httpx.ConnectError("CVE HTTP client is unavailable")
        async with self._client.stream(
            method,
            url,
            params=params,
            headers=headers,
            json=json_body,
        ) as response:
            status_code = response.status_code
            response_headers = dict(response.headers)
            if status_code == 429 or status_code >= 500:
                return status_code, response_headers, None
            response.raise_for_status()
            encoding = response.headers.get("content-encoding", "").strip().lower()
            if encoding not in {"", "identity"}:
                raise ValueError("compressed source response is not accepted")
            content_length = response.headers.get("content-length")
            if content_length is not None:
                try:
                    if int(content_length) > _MAX_SOURCE_RESPONSE_BYTES:
                        raise ValueError("source response exceeds size limit")
                except ValueError as exc:
                    raise ValueError("invalid or oversized source content length") from exc
            body = bytearray()
            async for chunk in response.aiter_raw():
                if len(body) + len(chunk) > _MAX_SOURCE_RESPONSE_BYTES:
                    raise ValueError("source response exceeds size limit")
                body.extend(chunk)
            payload = json.loads(bytes(body))
            if isinstance(payload, list):
                payload = {"items": payload}
            if not isinstance(payload, dict):
                raise ValueError("source returned an unsupported JSON response")
            return status_code, response_headers, payload

    async def _get_json(
        self,
        key: str,
        url: str,
        params: dict[str, str] | None = None,
        *,
        ttl: int = _CACHE_TTL_SECONDS,
        nvd: bool = False,
        github: bool = False,
        json_body: dict[str, Any] | None = None,
    ) -> tuple[dict[str, Any] | None, bool]:
        cached, fresh = self._cache_get(key, ttl=ttl)
        if cached is not None and fresh:
            return cached, False
        stale, _ = self._cache_get(key, allow_stale=True, ttl=ttl)
        if self._client is None:
            return stale, stale is not None

        for attempt in range(3):
            try:
                if nvd:
                    async with self._nvd_lock:
                        delay = self.nvd_min_interval - (asyncio.get_running_loop().time() - self._last_nvd_request)
                        if self._last_nvd_request and delay > 0:
                            await asyncio.sleep(delay)
                        self._last_nvd_request = asyncio.get_running_loop().time()
                        request_headers = {"apiKey": self.api_key} if self.api_key else None
                        status_code, response_headers, payload = await self._request_bounded_json(
                            "GET", url, params=params, headers=request_headers
                        )
                elif github:
                    async with self._github_lock:
                        delay = self.github_min_interval - (
                            asyncio.get_running_loop().time() - self._last_github_request
                        )
                        if self._last_github_request and delay > 0:
                            await asyncio.sleep(delay)
                        self._last_github_request = asyncio.get_running_loop().time()
                        request_headers = (
                            {"Authorization": f"Bearer {self.github_token}", "X-GitHub-Api-Version": "2022-11-28"}
                            if self.github_token
                            else {"X-GitHub-Api-Version": "2022-11-28"}
                        )
                        status_code, response_headers, payload = await self._request_bounded_json(
                            "GET", url, params=params, headers=request_headers
                        )
                else:
                    status_code, response_headers, payload = await self._request_bounded_json(
                        "POST" if json_body is not None else "GET",
                        url,
                        params=params,
                        json_body=json_body,
                    )
                if status_code == 429 or status_code >= 500:
                    if attempt < 2:
                        retry_header = response_headers.get("Retry-After", "")
                        try:
                            delay = min(5.0, max(0.0, float(retry_header)))
                        except ValueError:
                            delay = 0.5 * (2**attempt)
                        await asyncio.sleep(delay)
                        continue
                    raise httpx.HTTPStatusError(
                        "source returned a retryable status",
                        request=httpx.Request("GET", url),
                        response=httpx.Response(status_code),
                    )
                if payload is None:
                    raise ValueError("source returned no JSON payload")
                self._cache_put(key, payload)
                return payload, False
            except (httpx.HTTPError, ValueError) as exc:
                if attempt < 2 and isinstance(
                    exc, (httpx.TimeoutException, httpx.ConnectError, httpx.RemoteProtocolError)
                ):
                    await asyncio.sleep(0.5 * (2**attempt))
                    continue
                logger.warning("CVE source request failed (%s)", key.split(":", 1)[0])
                return stale, stale is not None
        return stale, stale is not None

    async def correlate(self, technologies: list[dict[str, Any]]) -> CveOutcome:
        cves: list[dict[str, Any]] = []
        errors: list[str] = ["local_cache_unavailable"] if self._cache_unavailable else []
        record_index: dict[tuple[str, str], dict[str, Any]] = {}

        def add_record(record: dict[str, Any]) -> None:
            technology_name = str(record.get("technology_name") or record.get("product") or "unknown")
            cve_id = record.get("cve_id")
            identifiers = [cve_id] if isinstance(cve_id, str) and cve_id else []
            identifiers.extend(
                str(identifier)
                for identifier in record.get("advisory_ids", [])
                if isinstance(identifier, str) and identifier
            )
            if any(identifier.strip().upper() in _IGNORED_CVE_IDS for identifier in identifiers):
                return
            existing = next(
                (record_index[(technology_name, identifier)] for identifier in identifiers
                 if (technology_name, identifier) in record_index),
                None,
            )
            if existing is None:
                cves.append(record)
                existing = record
            else:
                for field in ("sources", "references", "vendor_advisories", "advisory_ids"):
                    values = record.get(field, [])
                    if isinstance(values, list):
                        existing[field] = list(dict.fromkeys([*existing.get(field, []), *values]))
                for field in ("cvss_score", "cvss_version", "severity", "recommended_version", "source_updated_at"):
                    if existing.get(field) is None and record.get(field) is not None:
                        existing[field] = record[field]
                if not existing.get("description") and record.get("description"):
                    existing["description"] = record["description"]
                if existing.get("match_status") == "insufficient_evidence" and record.get("match_status") == "potentially_affected":
                    existing["match_status"] = "potentially_affected"
                existing["source_update_dates"] = {
                    **existing.get("source_update_dates", {}),
                    **record.get("source_update_dates", {}),
                }
            for identifier in identifiers:
                record_index[(technology_name, identifier)] = existing
            cve_id = record.get("cve_id")
            if isinstance(cve_id, str) and cve_id:
                record_index[(technology_name, cve_id)] = existing

        nvd_candidates: dict[str, dict[str, Any]] = {}
        for technology in technologies:
            version = technology.get("version")
            cpe = technology.get("cpe")
            if (
                not version
                or technology.get("version_status") not in {"declared", "verified"}
                or technology.get("version_conflict")
                or not isinstance(cpe, str)
                or _version_from_cpe(cpe) != version
            ):
                continue
            if len(cpe.split(":")) == 13:
                nvd_candidates[cpe] = technology

        for cpe, technology in nvd_candidates.items():
            payload, stale = await self._get_json(
                f"nvd:{cpe}",
                NVD_CVE_URL,
                {"cpeName": cpe, "resultsPerPage": "2000"},
                nvd=True,
            )
            if stale:
                errors.append("nvd_stale_cache")
            if payload is None:
                errors.append("nvd_unavailable")
                continue
            vulnerabilities = payload.get("vulnerabilities", [])
            if not isinstance(vulnerabilities, list):
                errors.append("nvd_invalid_response")
                continue
            fields = cpe.split(":")
            vendor, product, version = fields[3], fields[4], fields[5]
            for wrapper in vulnerabilities:
                if not isinstance(wrapper, dict) or not isinstance(wrapper.get("cve"), dict):
                    continue
                cve = wrapper["cve"]
                cve_id = cve.get("id")
                if not isinstance(cve_id, str) or not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve_id):
                    continue
                is_match, complex_condition = match_cve_version(
                    cve,
                    vendor=vendor,
                    product=product,
                    version=version,
                    part=fields[2],
                )
                if not is_match:
                    continue
                cvss_score, cvss_version, severity = _cvss(cve)
                range_match: dict[str, Any] = {}
                for match, _ in _walk_matches(cve.get("configurations", [])):
                    cpe_parts = _split_cpe(str(match.get("criteria", "")))
                    if (
                        cpe_parts
                        and cpe_parts[0] == fields[2]
                        and match.get("vulnerable") is True
                        and cpe_parts[1] == vendor
                        and cpe_parts[2] == product
                        and version_in_range(
                            version,
                            criteria_version=str(match.get("criteria", "")).split(":")[5],
                            version_start_including=match.get("versionStartIncluding"),
                            version_start_excluding=match.get("versionStartExcluding"),
                            version_end_including=match.get("versionEndIncluding"),
                            version_end_excluding=match.get("versionEndExcluding"),
                        ) is True
                    ):
                        range_match = match
                        break
                raw_references = cve.get("references", [])
                references = _advisory_references(raw_references)
                vendor_advisories = []
                if isinstance(raw_references, list):
                    for reference in raw_references:
                        if not isinstance(reference, dict) or not isinstance(reference.get("url"), str):
                            continue
                        tags = reference.get("tags", [])
                        if isinstance(tags, list) and any(
                            str(tag).lower() in {"vendor advisory", "vendor-advisory"} for tag in tags
                        ):
                            vendor_advisories.append(reference["url"])
                source_updated = cve.get("lastModified")
                add_record(
                    {
                        "cve_id": cve_id,
                        "advisory_ids": [],
                        "product": technology.get("name", product),
                        "detected_version": version,
                        "match_status": "potentially_affected",
                        "cvss_score": cvss_score,
                        "cvss_version": cvss_version,
                        "severity": severity,
                        "epss": None,
                        "epss_date": None,
                        "cisa_kev": None,
                        "description": _description(cve),
                        "affected_range": _range_text(range_match) if range_match else "NVD CPE version range matched",
                        "recommended_version": None,
                        "confidence": "low" if complex_condition else "medium",
                        "sources": ["NVD"] + (["Vendor Advisory"] if vendor_advisories else []),
                        "references": references,
                        "vendor_advisories": list(dict.fromkeys(vendor_advisories)),
                        "source_updated_at": source_updated,
                        "source_update_dates": {"NVD": source_updated} if source_updated else {},
                        "technology_name": technology.get("name", product),
                        "backport_status": "unknown",
                        "backport_note": "Remote fingerprints cannot establish the installed distribution build or backported fixes.",
                    }
                )

        for technology in technologies:
            version = technology.get("version")
            if not isinstance(version, str) or technology.get("version_conflict"):
                continue
            version_status = technology.get("version_status")
            sources = technology.get("sources", [])
            corroborated_fingerprint = version_status == "fingerprinted" and isinstance(sources, list) and len(set(sources)) >= 2
            if version_status not in {"declared", "verified"} and not corroborated_fingerprint:
                continue
            try:
                compare_versions(version, version)
            except ValueError:
                continue
            package_info = _OSV_PACKAGES.get(str(technology.get("name", "")).lower())
            if package_info is None:
                continue
            ecosystem, package_name, github_ecosystem = package_info
            package_version = {
                "ecosystem": ecosystem,
                "name": package_name,
            }
            page_token: str | None = None
            osv_vulnerabilities: list[dict[str, Any]] = []
            for page in range(5):
                cache_part = page_token or "first"
                osv_payload, osv_stale = await self._get_json(
                    f"osv:{ecosystem}:{package_name}@{version}:{cache_part}",
                    OSV_QUERY_URL,
                    json_body={
                        "package": package_version,
                        "version": version,
                        **({"page_token": page_token} if page_token else {}),
                    },
                )
                if osv_stale:
                    errors.append("osv_stale_cache")
                if osv_payload is None:
                    errors.append("osv_unavailable")
                    break
                page_vulns = osv_payload.get("vulns", [])
                if not isinstance(page_vulns, list):
                    errors.append("osv_invalid_response")
                    break
                osv_vulnerabilities.extend(item for item in page_vulns if isinstance(item, dict))
                page_token = osv_payload.get("next_page_token")
                if not isinstance(page_token, str) or not page_token:
                    page_token = None
                    break
                if page == 4:
                    errors.append("osv_pagination_limited")

            for vulnerability in osv_vulnerabilities:
                if _osv_version_match(
                    vulnerability,
                    ecosystem=ecosystem,
                    package_name=package_name,
                    version=version,
                ) is not True:
                    continue
                osv_id = vulnerability.get("id")
                aliases = vulnerability.get("aliases", [])
                identifiers = [
                    item for item in [osv_id, *(aliases if isinstance(aliases, list) else [])]
                    if isinstance(item, str) and item and len(item) <= 80
                ]
                cve_id = next((item for item in identifiers if re.fullmatch(r"CVE-\d{4}-\d{4,}", item)), None)
                advisory_ids = [item for item in identifiers if item != cve_id]
                references = _advisory_references(vulnerability.get("references", []))
                vendor_advisories = []
                for reference in vulnerability.get("references", []):
                    if (
                        isinstance(reference, dict)
                        and reference.get("type") == "ADVISORY"
                        and isinstance(reference.get("url"), str)
                        and reference["url"].startswith(("https://", "http://"))
                    ):
                        vendor_advisories.append(reference["url"])
                affected_range = "OSV affected version"
                for affected in vulnerability.get("affected", []):
                    package = affected.get("package", {}) if isinstance(affected, dict) else {}
                    if not isinstance(package, dict) or package.get("ecosystem") != ecosystem or package.get("name") != package_name:
                        continue
                    ranges = affected.get("ranges", [])
                    if isinstance(ranges, list):
                        for version_range in ranges:
                            if not isinstance(version_range, dict):
                                continue
                            events = version_range.get("events", [])
                            if isinstance(events, list):
                                event_text = ", ".join(
                                    f"{key} {value}"
                                    for event in events
                                    if isinstance(event, dict)
                                    for key, value in event.items()
                                )
                                if event_text:
                                    affected_range = event_text[:512]
                                    break
                    if affected_range != "OSV affected version":
                        break
                recommended_version = next(
                    (
                        fixed
                        for fixed in _fixed_versions(vulnerability, ecosystem, package_name)
                        if compare_versions(fixed, version) > 0
                    ),
                    None,
                )
                source_updated = vulnerability.get("modified")
                confidence = "low" if corroborated_fingerprint else "medium"
                add_record(
                    {
                        "cve_id": cve_id,
                        "advisory_ids": advisory_ids,
                        "product": technology.get("name", package_name),
                        "detected_version": version,
                        "match_status": "potentially_affected",
                        "cvss_score": None,
                        "cvss_version": None,
                        "severity": None,
                        "epss": None,
                        "epss_date": None,
                        "cisa_kev": None,
                        "description": str(vulnerability.get("summary") or vulnerability.get("details") or "")[:2000],
                        "affected_range": affected_range,
                        "recommended_version": recommended_version,
                        "confidence": confidence,
                        "sources": ["OSV"],
                        "references": references,
                        "vendor_advisories": list(dict.fromkeys(vendor_advisories)),
                        "source_updated_at": source_updated,
                        "source_update_dates": {"OSV": source_updated} if source_updated else {},
                        "technology_name": technology.get("name", package_name),
                        "backport_status": "unknown",
                        "backport_note": "Public package fingerprint does not establish the deployed build or vendor backports.",
                    }
                )

            github_payload, github_stale = await self._get_json(
                f"github_advisory:{github_ecosystem}:{package_name}@{version}",
                GITHUB_ADVISORIES_URL,
                {
                    "ecosystem": github_ecosystem,
                    "affects": f"{package_name}@{version}",
                    "type": "reviewed",
                    "per_page": "100",
                },
                github=True,
            )
            if github_stale:
                errors.append("github_advisory_stale_cache")
            if github_payload is None:
                errors.append("github_advisory_unavailable")
                continue
            advisories = github_payload.get("items", [])
            if not isinstance(advisories, list):
                errors.append("github_advisory_invalid_response")
                continue
            for advisory in advisories:
                if not isinstance(advisory, dict):
                    continue
                vulnerabilities = advisory.get("vulnerabilities", [])
                if not isinstance(vulnerabilities, list):
                    continue
                for affected in vulnerabilities:
                    if not isinstance(affected, dict):
                        continue
                    package = affected.get("package")
                    if (
                        not isinstance(package, dict)
                        or package.get("ecosystem") != github_ecosystem
                        or package.get("name") != package_name
                    ):
                        continue
                    vulnerable_range = affected.get("vulnerable_version_range")
                    if not isinstance(vulnerable_range, str):
                        continue
                    range_match = _github_range_match(version, vulnerable_range)
                    if range_match is False:
                        continue
                    ghsa_id = advisory.get("ghsa_id")
                    cve_id = advisory.get("cve_id")
                    if not isinstance(cve_id, str) or not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve_id):
                        cve_id = None
                    if not isinstance(ghsa_id, str) or not re.fullmatch(
                        r"GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}", ghsa_id, re.I
                    ):
                        ghsa_id = None
                    if cve_id is None and ghsa_id is None:
                        continue
                    patched = affected.get("first_patched_version")
                    cvss = advisory.get("cvss_severities", {})
                    if not isinstance(cvss, dict):
                        cvss = {}
                    cvss_score = None
                    cvss_version = None
                    for key, version_label in (("cvss_v4", "4.0"), ("cvss_v3", "3.1")):
                        metric = cvss.get(key)
                        if isinstance(metric, dict):
                            try:
                                cvss_score = float(metric["score"])
                                cvss_version = version_label
                                break
                            except (KeyError, TypeError, ValueError):
                                pass
                    refs = _advisory_references(
                        [*advisory.get("references", []), advisory.get("html_url"), advisory.get("url")]
                        if isinstance(advisory.get("references", []), list)
                        else [advisory.get("html_url"), advisory.get("url")]
                    )
                    update = advisory.get("updated_at")
                    advisory_ids = [ghsa_id] if ghsa_id else []
                    add_record(
                        {
                            "cve_id": cve_id,
                            "advisory_ids": advisory_ids,
                            "product": technology.get("name", package_name),
                            "detected_version": version,
                            "match_status": "potentially_affected" if range_match is True else "insufficient_evidence",
                            "cvss_score": cvss_score,
                            "cvss_version": cvss_version,
                            "severity": advisory.get("severity"),
                            "epss": None,
                            "epss_date": None,
                            "cisa_kev": None,
                            "description": str(advisory.get("summary") or advisory.get("description") or "")[:2000],
                            "affected_range": vulnerable_range,
                            "recommended_version": patched if isinstance(patched, str) else None,
                            "confidence": "medium" if range_match is True and not corroborated_fingerprint else "low",
                            "sources": ["GitHub Security Advisories"],
                            "references": refs,
                            "vendor_advisories": refs,
                            "source_updated_at": update,
                            "source_update_dates": {"GitHub Security Advisories": update} if update else {},
                            "technology_name": technology.get("name", package_name),
                            "backport_status": "unknown",
                            "backport_note": "Public package fingerprint does not establish the deployed build or vendor backports.",
                        }
                    )

        cves.sort(key=lambda record: (
            str(record.get("cve_id") or ""),
            str(record.get("advisory_ids", [""])[0] if record.get("advisory_ids") else ""),
            str(record.get("technology_name") or ""),
        ))
        cve_ids = sorted(
            {
                record["cve_id"]
                for record in cves
                if isinstance(record.get("cve_id"), str) and re.fullmatch(r"CVE-\d{4}-\d{4,}", record["cve_id"])
            }
        )
        kev_payload: dict[str, Any] | None = None
        kev_ids: set[str] = set()
        if cve_ids:
            kev_payload, kev_stale = await self._get_json("cisa:kev", CISA_KEV_URL, ttl=_CACHE_TTL_SECONDS)
            if kev_stale:
                errors.append("cisa_kev_stale_cache")
            if kev_payload is None:
                errors.append("cisa_kev_unavailable")
            else:
                entries = kev_payload.get("vulnerabilities", [])
                if isinstance(entries, list):
                    kev_ids = {
                        str(item.get("cveID"))
                        for item in entries
                        if isinstance(item, dict) and item.get("cveID")
                    }

        epss_values: dict[str, tuple[float, str | None]] = {}
        for offset in range(0, len(cve_ids), 100):
            batch_ids = cve_ids[offset : offset + 100]
            epss_payload, epss_stale = await self._get_json(
                "first:epss:" + ",".join(batch_ids),
                EPSS_URL,
                {"cve": ",".join(batch_ids)},
                ttl=_CACHE_TTL_SECONDS,
            )
            if epss_stale:
                errors.append("epss_stale_cache")
            if epss_payload is None:
                errors.append("epss_unavailable")
                continue
            entries = epss_payload.get("data", [])
            if isinstance(entries, list):
                for item in entries:
                    if not isinstance(item, dict) or not item.get("cve"):
                        continue
                    try:
                        score = float(item["epss"])
                    except (KeyError, TypeError, ValueError):
                        continue
                    epss_values[str(item["cve"])] = (score, str(item["date"]) if item.get("date") else None)

        for record in cves:
            cve_id = record.get("cve_id")
            if not isinstance(cve_id, str):
                continue
            if kev_payload is not None:
                record["cisa_kev"] = cve_id in kev_ids
                if "CISA KEV" not in record["sources"]:
                    record["sources"].append("CISA KEV")
                kev_updated = kev_payload.get("dateReleased") or kev_payload.get("catalogVersion")
                if isinstance(kev_updated, str):
                    record.setdefault("source_update_dates", {})["CISA KEV"] = kev_updated
            if cve_id in epss_values:
                score, date = epss_values[cve_id]
                record["epss"] = score
                record["epss_date"] = date
                if "FIRST EPSS" not in record["sources"]:
                    record["sources"].append("FIRST EPSS")
                if date:
                    record.setdefault("source_update_dates", {})["FIRST EPSS"] = date
        return CveOutcome(cves=cves, errors=sorted(set(errors)))
