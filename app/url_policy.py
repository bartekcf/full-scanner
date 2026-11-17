from __future__ import annotations

import asyncio
import ipaddress
import socket
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from app.config import normalize_domain


class TargetValidationError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _load_non_public_ranges() -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    ranges_path = Path(__file__).with_name("non_public_ranges.txt")
    ranges = tuple(
        ipaddress.ip_network(line.strip())
        for line in ranges_path.read_text(encoding="ascii").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    )
    if not ranges:
        raise RuntimeError("non-public address policy is empty")
    return ranges


_NON_PUBLIC_RANGES = _load_non_public_ranges()


def _is_public_address(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return address.is_global and not any(
        network.version == address.version and address in network
        for network in _NON_PUBLIC_RANGES
    )


async def validate_target_with_addresses(
    raw_url: str,
    dns_timeout: int,
    *,
    resolve_dns: bool = True,
) -> tuple[str, list[str]]:
    if any(character.isspace() or ord(character) < 32 for character in raw_url) or "\\" in raw_url:
        raise TargetValidationError("invalid_url")
    try:
        parsed = urlsplit(raw_url)
        scheme = parsed.scheme.lower()
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise TargetValidationError("invalid_url") from exc

    if scheme not in {"http", "https"} or not hostname or parsed.username is not None or parsed.password is not None:
        raise TargetValidationError("invalid_url")
    if parsed.fragment:
        raise TargetValidationError("url_fragment_not_allowed")
    expected_port = 443 if scheme == "https" else 80
    if port is not None and port != expected_port:
        raise TargetValidationError("port_not_allowed")

    try:
        domain = normalize_domain(hostname)
    except ValueError as exc:
        raise TargetValidationError("invalid_or_non_public_hostname") from exc

    resolved: set[str] = set()
    if resolve_dns:
        try:
            loop = asyncio.get_running_loop()
            addresses = await asyncio.wait_for(
                loop.getaddrinfo(domain, expected_port, type=socket.SOCK_STREAM),
                timeout=dns_timeout,
            )
        except (OSError, asyncio.TimeoutError) as exc:
            raise TargetValidationError("target_not_resolvable") from exc
        if not addresses:
            raise TargetValidationError("target_not_resolvable")

        for address_info in addresses:
            address_text = address_info[4][0].split("%", 1)[0]
            try:
                address = ipaddress.ip_address(address_text)
            except ValueError as exc:
                raise TargetValidationError("target_resolution_rejected") from exc
            if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
                address = address.ipv4_mapped
            if not _is_public_address(address):
                raise TargetValidationError("target_resolution_rejected")
            resolved.add(str(address))

    authority = domain if port is None else f"{domain}:{port}"
    normalized = urlunsplit((scheme, authority, parsed.path or "/", parsed.query, ""))
    return normalized, sorted(resolved)


async def validate_target(
    raw_url: str,
    dns_timeout: int,
    *,
    resolve_dns: bool = True,
) -> str:
    normalized, _ = await validate_target_with_addresses(
        raw_url,
        dns_timeout,
        resolve_dns=resolve_dns,
    )
    return normalized
