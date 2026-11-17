from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import re
import signal
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import httpx

from app.technology import fingerprint_response

PROJECTDISCOVERY_HTTPX_VERSION = "1.12.0"
BOUNDED_HTTP_FINGERPRINT_VERSION = "built-in"
_MAX_TIMEOUT_SECONDS = 60.0
_MAX_OUTPUT_BYTES = 1_000_000
_TERMINATE_GRACE_SECONDS = 1.0
_VERSION_RE = re.compile(r"^([A-Za-z][A-Za-z0-9_. -]{0,79}?)(?:[/ ]([0-9][A-Za-z0-9.+_-]{0,39}))?$")
logger = logging.getLogger(__name__)


@dataclass
class ToolRun:
    observations: list[dict[str, Any]]
    tool_version: str
    error: str | None
    normalized: bool = False
    raw: Any = None


def _proxy_parts(proxy_url: str) -> tuple[str, int] | None:
    try:
        parsed = urlsplit(proxy_url)
        if parsed.scheme != "http" or not parsed.hostname or parsed.username or parsed.password:
            return None
        if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
            return None
        port = parsed.port
        if port != 3128:
            return None
        return parsed.hostname, port
    except (ValueError, AttributeError):
        return None


def _observation(name: str, version: str | None, evidence: str, source: str) -> dict[str, Any]:
    return {"name": name, "version": version, "evidence": evidence[:256], "source": source}


def _pd_httpx_observations(output: str) -> list[dict[str, Any]]:
    observations: list[dict[str, Any]] = []
    for line in output.splitlines():
        try:
            item = json.loads(line)
        except (json.JSONDecodeError, TypeError):
            continue
        if not isinstance(item, dict):
            continue
        candidates: list[tuple[str, str]] = []
        technologies = item.get("tech")
        if isinstance(technologies, list):
            candidates.extend((value, "httpx technology detection") for value in technologies if isinstance(value, str))
        for key, label in (("webserver", "httpx web server"), ("framework", "httpx framework")):
            value = item.get(key)
            if isinstance(value, str):
                candidates.append((value, label))
        for value, source in candidates:
            if re.fullmatch(r"HTTP/[0-9.]+", value, re.I):
                continue
            match = _VERSION_RE.fullmatch(value.strip())
            if match:
                observations.append(
                    _observation(match.group(1).strip(), match.group(2), f"{source}: {value}", "projectdiscovery_httpx")
                )
    return observations


async def _read_bounded(stream: asyncio.StreamReader) -> tuple[bytes, bool]:
    captured = bytearray()
    exceeded = False
    while True:
        chunk = await stream.read(65536)
        if not chunk:
            break
        remaining = _MAX_OUTPUT_BYTES - len(captured)
        if remaining > 0:
            captured.extend(chunk[:remaining])
        if len(chunk) > remaining:
            exceeded = True
    return bytes(captured), exceeded


async def _stop_process(process: asyncio.subprocess.Process) -> None:
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    except OSError:
        if process.returncode is None:
            process.terminate()
    await asyncio.sleep(_TERMINATE_GRACE_SECONDS)
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except OSError:
        if process.returncode is None:
            process.kill()
    if process.returncode is None:
        await process.wait()

async def _run(
    executable: str,
    arguments: list[str],
    timeout_seconds: float,
    version: str,
    parser,
) -> ToolRun:
    timeout = min(max(float(timeout_seconds), 0.1), _MAX_TIMEOUT_SECONDS)
    env = {
        "PATH": os.environ.get("PATH", os.defpath),
        "HOME": "/tmp",
        "LANG": os.environ.get("LANG", "C.UTF-8"),
    }
    try:
        process = await asyncio.create_subprocess_exec(
            executable,
            *arguments,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
            env=env,
            start_new_session=True,
        )
    except (OSError, ValueError):
        return ToolRun([], version, "tool_unavailable")

    assert process.stdout is not None
    reader = asyncio.create_task(_read_bounded(process.stdout))
    waiter = asyncio.create_task(process.wait())
    try:
        _, pending = await asyncio.wait({reader, waiter}, timeout=timeout)
        if pending:
            await _stop_process(process)
            await asyncio.gather(reader, waiter, return_exceptions=True)
            return ToolRun([], version, "tool_timeout")
        output, exceeded = reader.result()
        returncode = waiter.result()
    except asyncio.CancelledError:
        await _stop_process(process)
        await asyncio.gather(reader, waiter, return_exceptions=True)
        raise
    if exceeded:
        return ToolRun([], version, "tool_output_too_large", raw={"stdout": output.decode("utf-8", errors="replace"), "truncated": True})
    if returncode != 0:
        return ToolRun([], version, "tool_failed", raw={"stdout": output.decode("utf-8", errors="replace"), "exit_code": returncode})
    return ToolRun(parser(output.decode("utf-8", errors="replace")), version, None, raw={"stdout": output.decode("utf-8", errors="replace")})


async def run_projectdiscovery_httpx(url: str, proxy_url: str, timeout_seconds: float) -> ToolRun:
    if _proxy_parts(proxy_url) is None:
        return ToolRun([], PROJECTDISCOVERY_HTTPX_VERSION, "proxy_required")
    arguments = [
        "-proxy", proxy_url,
        "-td", "-json", "-silent", "-no-stdin", "-no-fallback-scheme", "-duc",
        "-threads", "1", "-rate-limit", "1", "-retries", "0",
        "-timeout", str(max(1, min(int(timeout_seconds), int(_MAX_TIMEOUT_SECONDS)))),
        "-response-size-to-read", str(_MAX_OUTPUT_BYTES),
        "-u", url,
    ]
    return await _run("pd-httpx", arguments, timeout_seconds, PROJECTDISCOVERY_HTTPX_VERSION, _pd_httpx_observations)


async def run_bounded_http_fingerprint(
    url: str,
    proxy_url: str,
    timeout_seconds: float,
    max_response_bytes: int,
) -> ToolRun:
    if _proxy_parts(proxy_url) is None:
        return ToolRun([], BOUNDED_HTTP_FINGERPRINT_VERSION, "proxy_required", normalized=True)
    if max_response_bytes < 1:
        return ToolRun([], BOUNDED_HTTP_FINGERPRINT_VERSION, "tool_failed", normalized=True)

    timeout = min(max(float(timeout_seconds), 0.1), _MAX_TIMEOUT_SECONDS)
    try:
        async with asyncio.timeout(timeout):
            async with httpx.AsyncClient(
                proxy=proxy_url,
                timeout=httpx.Timeout(timeout, connect=min(timeout, 8.0)),
                follow_redirects=False,
                verify=True,
                trust_env=False,
                headers={
                    "User-Agent": "PassiveSecurityScanner/1.0",
                    "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.1",
                    "Accept-Encoding": "identity",
                },
            ) as client:
                async with client.stream("GET", url) as response:
                    body = bytearray()
                    error: str | None = None
                    encoding = response.headers.get("content-encoding", "identity").strip().lower()
                    content_length = response.headers.get("content-length")
                    declared_length: int | None = None
                    if encoding not in {"", "identity"}:
                        error = "content_encoding_unsupported"
                    elif content_length is not None:
                        try:
                            declared_length = int(content_length)
                        except ValueError:
                            error = "tool_failed"
                        if declared_length is not None and declared_length < 0:
                            error = "tool_failed"
                        elif declared_length is not None and declared_length > max_response_bytes:
                            error = "response_size_limit"
                    if error is None:
                        async for chunk in response.aiter_raw():
                            remaining = max_response_bytes - len(body)
                            if len(chunk) > remaining:
                                body.extend(chunk[:remaining])
                                error = "response_size_limit"
                                break
                            body.extend(chunk)
                    observations = fingerprint_response(response.headers, bytes(body))
                    return ToolRun(observations, BOUNDED_HTTP_FINGERPRINT_VERSION, error, normalized=True, raw={"status": response.status_code, "headers": dict(response.headers), "body_base64": base64.b64encode(body).decode(), "capture_limit_bytes": max_response_bytes})
    except (asyncio.TimeoutError, httpx.TimeoutException):
        return ToolRun([], BOUNDED_HTTP_FINGERPRINT_VERSION, "tool_timeout", normalized=True)
    except httpx.HTTPError as exc:
        logger.warning("Bounded HTTP fingerprint failed (%s)", type(exc).__name__)
        return ToolRun([], BOUNDED_HTTP_FINGERPRINT_VERSION, "tool_failed", normalized=True)
