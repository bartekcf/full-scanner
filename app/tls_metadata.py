from __future__ import annotations
import asyncio
import math
import socket
import ssl
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit


_MAX_PROXY_HEADERS = 16 * 1024


def _parse_url(url: str) -> tuple[str, str, int]:
    if not isinstance(url, str) or any(c.isspace() or ord(c) < 32 for c in url) or "\\" in url:
        raise ValueError("invalid_url")
    try:
        parsed = urlsplit(url)
        scheme, host, port = parsed.scheme.lower(), parsed.hostname, parsed.port
    except ValueError as exc:
        raise ValueError("invalid_url") from exc
    if scheme not in {"http", "https"} or not host or parsed.username is not None or parsed.password is not None:
        raise ValueError("invalid_url")
    if parsed.fragment:
        raise ValueError("invalid_url")
    expected = 443 if scheme == "https" else 80
    if port is not None and port != expected:
        raise ValueError("port_not_allowed")
    if any(ord(c) < 33 or c in "/?#@" for c in host):
        raise ValueError("invalid_url")
    return scheme, host, expected


def _parse_proxy(proxy_url: str) -> tuple[str, int]:
    if not isinstance(proxy_url, str) or any(c.isspace() or ord(c) < 32 for c in proxy_url) or "\\" in proxy_url:
        raise ValueError("invalid_proxy")
    try:
        parsed = urlsplit(proxy_url)
        host, port = parsed.hostname, parsed.port
    except ValueError as exc:
        raise ValueError("invalid_proxy") from exc
    if parsed.scheme.lower() != "http" or not host or parsed.username is not None or parsed.password is not None:
        raise ValueError("invalid_proxy")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ValueError("invalid_proxy")
    if any(ord(c) < 33 or c in "/?#@" for c in host):
        raise ValueError("invalid_proxy")
    return host, port or 3128


def _certificate_time(value: str | None) -> str | None:
    if value is None:
        return None
    try:
        parsed = datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        return parsed.isoformat().replace("+00:00", "Z")
    except ValueError:
        return value


def _collect(url: str, proxy_url: str, timeout_seconds: float) -> dict[str, Any]:
    result: dict[str, Any] = {"status": "error", "host": None, "port": None, "tls_version": None,
                              "cipher": None, "subject": None, "issuer": None, "dns_sans": [],
                              "not_before": None, "not_after": None, "verified": False, "error_code": None}
    try:
        scheme, host, port = _parse_url(url)
        if scheme == "http":
            return {**result, "status": "not_applicable", "host": host, "port": port}
        proxy_host, proxy_port = _parse_proxy(proxy_url)
        timeout = float(timeout_seconds)
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("invalid_timeout")
        result.update(host=host, port=port)
        connect_host = f"[{host}]" if ":" in host else host.encode("idna").decode("ascii")
        # The sole outbound TCP connection is to the configured proxy.
        with socket.create_connection((proxy_host, proxy_port), timeout=timeout) as tunnel:
            tunnel.settimeout(timeout)
            tunnel.sendall(f"CONNECT {connect_host}:443 HTTP/1.1\r\nHost: {connect_host}:443\r\n\r\n".encode("ascii"))
            response = bytearray()
            while b"\r\n\r\n" not in response:
                chunk = tunnel.recv(min(4096, _MAX_PROXY_HEADERS + 1 - len(response)))
                if not chunk:
                    raise OSError("proxy_connect_failed")
                response.extend(chunk)
                if len(response) > _MAX_PROXY_HEADERS:
                    raise OSError("proxy_response_too_large")
            first_line = bytes(response).split(b"\r\n", 1)[0]
            fields = first_line.split()
            if len(fields) < 2 or fields[0] not in {b"HTTP/1.0", b"HTTP/1.1"} or fields[1] != b"200":
                raise OSError("proxy_connect_failed")
            context = ssl.create_default_context()
            with context.wrap_socket(tunnel, server_hostname=host) as tls:
                tls.settimeout(timeout)
                certificate = tls.getpeercert()
                result.update(status="ok", tls_version=tls.version(), cipher=tls.cipher()[0] if tls.cipher() else None,
                              subject=certificate.get("subject"), issuer=certificate.get("issuer"),
                              dns_sans=[value for kind, value in certificate.get("subjectAltName", ()) if kind == "DNS"],
                              not_before=_certificate_time(certificate.get("notBefore")),
                              not_after=_certificate_time(certificate.get("notAfter")), verified=True)
        return result
    except ValueError as exc:
        code = str(exc)
    except ssl.SSLCertVerificationError:
        code = "certificate_verification_failed"
    except (socket.timeout, TimeoutError):
        code = "timeout"
    except ssl.SSLError:
        code = "tls_error"
    except OSError:
        code = "connection_failed"
    except Exception:
        code = "collection_failed"
    result["error_code"] = code if code in {"invalid_url", "port_not_allowed", "invalid_proxy", "invalid_timeout", "certificate_verification_failed", "timeout", "tls_error", "connection_failed", "collection_failed"} else "invalid_url"
    return result


async def collect_tls_metadata(url: str, proxy_url: str, timeout_seconds: float) -> dict[str, Any]:
    """Collect certificate metadata through one HTTP CONNECT proxy tunnel."""
    return await asyncio.to_thread(_collect, url, proxy_url, timeout_seconds)
