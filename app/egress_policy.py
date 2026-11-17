from __future__ import annotations

import httpx


_BLOCKED_PROXY_PROBES = (
    "http://127.0.0.1/",
    "http://10.0.0.1/",
    "http://[::1]/",
    "http://[::ffff:127.0.0.1]/",
    "http://[64:ff9b::a00:1]/",
    "http://1.1.1.1:8080/",
)


async def verify_egress_proxy(proxy_url: str) -> None:
    """Fail startup unless the configured proxy rejects representative forbidden destinations."""
    try:
        async with httpx.AsyncClient(
            proxy=proxy_url,
            timeout=httpx.Timeout(3.0, connect=2.0),
            follow_redirects=False,
            trust_env=False,
        ) as client:
            for target in _BLOCKED_PROXY_PROBES:
                response = await client.get(target)
                if response.status_code != 403:
                    raise RuntimeError("egress proxy policy check failed")
    except httpx.HTTPError as exc:
        raise RuntimeError("egress proxy is unavailable or its deny policy failed") from exc
