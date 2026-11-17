from __future__ import annotations

import ipaddress
import json
import os
import re
from dataclasses import dataclass
from urllib.parse import urlsplit



EGRESS_PROXY_URL = os.environ.get("EGRESS_PROXY_URL", "http://egress:3128").rstrip("/")
_DOMAIN_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def normalize_domain(value: str) -> str:
    candidate = value.strip().rstrip(".").lower()
    if not candidate:
        raise ValueError("empty domain")
    try:
        domain = candidate.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("invalid domain") from exc
    if len(domain) > 253 or "." not in domain:
        raise ValueError("a public fully-qualified domain is required")
    try:
        ipaddress.ip_address(domain)
    except ValueError:
        pass
    else:
        raise ValueError("a domain name is required instead of an IP address")
    labels = domain.split(".")
    if any(not _DOMAIN_LABEL.fullmatch(label) for label in labels):
        raise ValueError("invalid domain label")
    return domain


def _required(name: str, minimum_length: int = 1) -> str:
    value = os.environ.get(name, "").strip()
    if len(value) < minimum_length:
        raise RuntimeError(f"{name} must contain at least {minimum_length} characters")
    return value


def _positive_int(name: str, default: int) -> int:
    raw = os.environ.get(name, str(default))
    try:
        value = int(raw)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be a positive integer") from exc
    if value < 1:
        raise RuntimeError(f"{name} must be a positive integer")
    return value


def _bounded_int(name: str, default: int, maximum: int) -> int:
    value = _positive_int(name, default)
    if value > maximum:
        raise RuntimeError(f"{name} must not exceed {maximum}")
    return value


def _api_client_tokens(api_token: str) -> dict[str, str]:
    raw = os.environ.get("API_CLIENT_TOKENS", "").strip()
    if not raw:
        return {}
    try:
        values = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError("API_CLIENT_TOKENS must be a JSON object") from exc
    if not isinstance(values, dict):
        raise RuntimeError("API_CLIENT_TOKENS must be a JSON object")
    result: dict[str, str] = {}
    seen = {api_token} if api_token else set()
    for principal, token in values.items():
        if (
            not isinstance(principal, str)
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", principal)
            or principal == "default"
            or not isinstance(token, str)
            or len(token) < 32
            or token in seen
        ):
            raise RuntimeError("API_CLIENT_TOKENS contains an invalid principal or token")
        result[principal] = token
        seen.add(token)
    return result


def _trusted_proxy_networks() -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    raw = os.environ.get("TRUSTED_PROXY_CIDRS", "").strip()
    if not raw:
        return ()
    try:
        return tuple(ipaddress.ip_network(item.strip(), strict=False) for item in raw.split(",") if item.strip())
    except ValueError as exc:
        raise RuntimeError("TRUSTED_PROXY_CIDRS must contain comma-separated CIDRs") from exc


def _egress_proxy_url() -> str:
    value = os.environ.get("EGRESS_PROXY_URL", EGRESS_PROXY_URL).strip()
    try:
        parsed = urlsplit(value)
        valid = (
            parsed.scheme == "http"
            and parsed.hostname
            and parsed.port == 3128
            and parsed.username is None
            and parsed.password is None
            and parsed.path in {"", "/"}
            and not parsed.query
            and not parsed.fragment
        )
    except ValueError:
        valid = False
    if not valid:
        raise RuntimeError("EGRESS_PROXY_URL must be an HTTP proxy on port 3128")
    return value.rstrip("/")

def _boolean(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    normalized = raw.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise RuntimeError(f"{name} must be a boolean value")


@dataclass(frozen=True)
class Settings:
    api_token: str
    api_client_tokens: dict[str, str]
    zap_api_key: str
    zap_api_url: str
    zap_proxy_url: str
    target_timeout_seconds: int
    passive_scan_timeout_seconds: int
    dns_timeout_seconds: int
    max_response_bytes: int
    max_request_body_bytes: int
    queue_size: int
    requests_per_minute: int
    scan_starts_per_minute: int
    trusted_proxy_networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]
    nvd_api_key: str | None
    cve_cache_path: str
    github_token: str | None
    enable_projectdiscovery_httpx: bool
    enable_bounded_http_fingerprint: bool
    fingerprint_tool_timeout_seconds: int

    @classmethod
    def from_env(cls, *, require_api_token: bool = True) -> "Settings":
        api_token = _required("API_BEARER_TOKEN", 32) if require_api_token else os.environ.get("API_BEARER_TOKEN", "").strip()
        zap_api_key = _required("ZAP_API_KEY", 32)
        _egress_proxy_url()
        if os.environ.get("ZAP_EGRESS_ISOLATION", "").strip().lower() != "proxy_only":
            raise RuntimeError("ZAP_EGRESS_ISOLATION=proxy_only is required; run with the isolated Docker Compose network")

        return cls(
            api_token=api_token,
            api_client_tokens=_api_client_tokens(api_token),
            zap_api_key=zap_api_key,
            zap_api_url=os.environ.get("ZAP_API_URL", "http://127.0.0.1:8080").rstrip("/"),
            zap_proxy_url=os.environ.get("ZAP_PROXY_URL", "http://127.0.0.1:8080").rstrip("/"),
            target_timeout_seconds=_bounded_int("TARGET_TIMEOUT_SECONDS", 30, 120),
            passive_scan_timeout_seconds=_bounded_int("PASSIVE_SCAN_TIMEOUT_SECONDS", 45, 300),
            dns_timeout_seconds=_bounded_int("DNS_TIMEOUT_SECONDS", 5, 30),
            max_response_bytes=_bounded_int("MAX_RESPONSE_BYTES", 2_000_000, 8_388_608),
            max_request_body_bytes=_bounded_int("MAX_REQUEST_BODY_BYTES", 16_384, 1_048_576),
            queue_size=_bounded_int("MAX_QUEUED_SCANS", 20, 100),
            requests_per_minute=_bounded_int("REQUESTS_PER_MINUTE", 60, 10_000),
            scan_starts_per_minute=_bounded_int("SCAN_STARTS_PER_MINUTE", 5, 1_000),
            trusted_proxy_networks=_trusted_proxy_networks(),
            nvd_api_key=os.environ.get("NVD_API_KEY", "").strip() or None,
            cve_cache_path=os.environ.get("CVE_CACHE_PATH", "/var/lib/scanner/cve-cache.sqlite3"),
            github_token=os.environ.get("GITHUB_TOKEN", "").strip() or None,
            enable_projectdiscovery_httpx=_boolean("ENABLE_PROJECTDISCOVERY_HTTPX", True),
            enable_bounded_http_fingerprint=_boolean("ENABLE_BOUNDED_HTTP_FINGERPRINT", True),
            fingerprint_tool_timeout_seconds=_bounded_int("FINGERPRINT_TOOL_TIMEOUT_SECONDS", 15, 60),
        )
    
