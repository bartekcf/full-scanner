from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any


_VERSION = r"([0-9]+(?:\.[0-9]+){0,3})"
_SERVER_PRODUCTS: tuple[tuple[str, str, str, re.Pattern[str]], ...] = (
    ("openresty", "OpenResty", "openresty", re.compile(r"openresty(?:/" + _VERSION + r")?", re.I)),
    ("nginx", "nginx", "nginx", re.compile(r"nginx(?:/" + _VERSION + r")?", re.I)),
    ("apache", "Apache HTTP Server", "apache", re.compile(r"(?:apache(?: http server)?)(?:/" + _VERSION + r")?", re.I)),
    ("caddy", "Caddy", "caddyserver", re.compile(r"caddy(?:/" + _VERSION + r")?", re.I)),
    ("iis", "Microsoft IIS", "microsoft", re.compile(r"microsoft-iis(?:/" + _VERSION + r")?", re.I)),
    ("litespeed", "LiteSpeed", "litespeedtech", re.compile(r"(?:open)?litespeed(?:/" + _VERSION + r")?", re.I)),
    ("envoy", "Envoy", "envoyproxy", re.compile(r"envoy(?:/" + _VERSION + r")?", re.I)),
    ("haproxy", "HAProxy", "haproxy", re.compile(r"haproxy(?:/" + _VERSION + r")?", re.I)),
    ("traefik", "Traefik", "traefik", re.compile(r"traefik(?:/" + _VERSION + r")?", re.I)),
)

_CPE_PRODUCTS = {
    "nginx": ("nginx", "nginx"),
    "openresty": ("openresty", "openresty"),
    "apache http server": ("apache", "http_server"),
    "caddy": ("caddyserver", "caddy"),
    "php": ("php", "php"),
}


def _cpe_for(name: str, version: str | None) -> str | None:
    product = _CPE_PRODUCTS.get(name.lower())
    if product is None or version is None:
        return None
    vendor, product_name = product
    return f"cpe:2.3:a:{vendor}:{product_name}:{version}:*:*:*:*:*:*:*"


def _evidence(kind: str, name: str, value: str) -> dict[str, str]:
    return {"type": kind, "name": name, "value": value[:256]}


def _observation(
    name: str,
    vendor: str,
    category: str,
    version: str | None,
    version_status: str,
    confidence: str,
    source: str,
    evidence: dict[str, str],
    *,
    is_edge: bool | None = None,
) -> dict[str, Any]:
    return {
        "name": name,
        "vendor": vendor,
        "category": category,
        "version": version,
        "version_status": version_status,
        "confidence": confidence,
        "sources": [source],
        "evidence": [evidence],
        "is_edge": is_edge,
        "version_conflict": False,
        "observed_versions": [version] if version else [],
        "cpe": _cpe_for(name, version),
    }


_TOOL_ALIASES: dict[str, tuple[str, str, str]] = {
    "nginx": ("nginx", "nginx", "web_server"),
    "apache": ("Apache HTTP Server", "Apache", "web_server"),
    "apachehttpserver": ("Apache HTTP Server", "Apache", "web_server"),
    "httpd": ("Apache HTTP Server", "Apache", "web_server"),
    "caddy": ("Caddy", "Caddy", "web_server"),
    "openresty": ("OpenResty", "OpenResty", "web_server"),
    "litespeed": ("LiteSpeed", "LiteSpeed Technologies", "web_server"),
    "openlitespeed": ("OpenLiteSpeed", "LiteSpeed Technologies", "web_server"),
    "microsoftiis": ("Microsoft IIS", "Microsoft", "web_server"),
    "iis": ("Microsoft IIS", "Microsoft", "web_server"),
    "cloudflare": ("Cloudflare", "Cloudflare", "cdn"),
    "php": ("PHP", "PHP Group", "language_runtime"),
    "wordpress": ("WordPress", "WordPress", "cms"),
    "drupal": ("Drupal", "Drupal", "cms"),
    "joomla": ("Joomla", "Open Source Matters", "cms"),
    "magento": ("Magento", "Adobe", "cms"),
    "prestashop": ("PrestaShop", "PrestaShop", "cms"),
    "laravel": ("Laravel", "Laravel", "framework"),
    "symfony": ("Symfony", "Symfony", "framework"),
    "yii": ("Yii", "Yii Software", "framework"),
    "yii2": ("Yii", "Yii Software", "framework"),
    "codeigniter": ("CodeIgniter", "CodeIgniter Foundation", "framework"),
    "cakephp": ("CakePHP", "Cake Software Foundation", "framework"),
    "react": ("React", "Meta", "frontend_framework"),
    "reactjs": ("React", "Meta", "frontend_framework"),
    "next": ("Next.js", "Vercel", "frontend_framework"),
    "nextjs": ("Next.js", "Vercel", "frontend_framework"),
    "vue": ("Vue.js", "Evan You", "frontend_framework"),
    "vuejs": ("Vue.js", "Evan You", "frontend_framework"),
    "nuxt": ("Nuxt", "Nuxt", "frontend_framework"),
    "nuxtjs": ("Nuxt", "Nuxt", "frontend_framework"),
    "angular": ("Angular", "Google", "frontend_framework"),
    "svelte": ("Svelte", "Svelte contributors", "frontend_framework"),
    "jquery": ("jQuery", "OpenJS Foundation", "frontend_library"),
    "bootstrap": ("Bootstrap", "Bootstrap Authors", "css_framework"),
    "alpine": ("Alpine.js", "Alpine.js", "frontend_framework"),
    "alpinejs": ("Alpine.js", "Alpine.js", "frontend_framework"),
    "tailwind": ("Tailwind CSS", "Tailwind Labs", "css_framework"),
    "tailwindcss": ("Tailwind CSS", "Tailwind Labs", "css_framework"),
    "node": ("Node.js", "OpenJS Foundation", "runtime"),
    "nodejs": ("Node.js", "OpenJS Foundation", "runtime"),
    "express": ("Express", "OpenJS Foundation", "framework"),
    "expressjs": ("Express", "OpenJS Foundation", "framework"),
    "aspnet": ("ASP.NET", "Microsoft", "framework"),
    "aspnetcore": ("ASP.NET Core", "Microsoft", "framework"),
    "spring": ("Spring", "Broadcom", "framework"),
    "springboot": ("Spring Boot", "Broadcom", "framework"),
    "django": ("Django", "Django Software Foundation", "framework"),
    "flask": ("Flask", "Pallets Projects", "framework"),
    "fastapi": ("FastAPI", "FastAPI", "framework"),
}


def normalize_tool_observation(item: Mapping[str, Any], source: str) -> dict[str, Any] | None:
    raw_name = item.get("name")
    if not isinstance(raw_name, str) or not raw_name.strip():
        return None
    raw_name = raw_name.strip()[:80]
    alias = re.sub(r"[^a-z0-9]+", "", raw_name.lower())
    name, vendor, category = _TOOL_ALIASES.get(alias, (raw_name, "Unknown", "technology"))
    raw_version = item.get("version")
    version = (
        raw_version.strip()
        if isinstance(raw_version, str)
        and re.fullmatch(r"[0-9]+(?:\.[0-9]+){0,3}(?:[-+][A-Za-z0-9.-]+)?", raw_version.strip())
        else None
    )
    raw_evidence = item.get("evidence")
    evidence = str(raw_evidence if isinstance(raw_evidence, str) else raw_name)[:256]
    return _observation(
        name,
        vendor,
        category,
        version,
        "fingerprinted" if version else "unknown",
        "medium" if version else "low",
        source,
        _evidence("technology_fingerprint", source, evidence),
        is_edge=True if category == "cdn" else None,
    )


def _header(headers: Mapping[str, str], name: str) -> str | None:
    value = headers.get(name)
    if value is not None:
        return str(value).strip()
    wanted = name.lower()
    for key, candidate in headers.items():
        if str(key).lower() == wanted:
            return str(candidate).strip()
    return None


def _server_observation(server: str) -> dict[str, Any] | None:
    lowered = server.strip().lower()
    if lowered == "cloudflare" or lowered.startswith("cloudflare/"):
        match = re.match(r"cloudflare(?:/" + _VERSION + r")?", server, re.I)
        version = match.group(1) if match else None
        return _observation(
            "Cloudflare",
            "Cloudflare",
            "cdn",
            version,
            "declared" if version else "unknown",
            "high",
            "http_headers",
            _evidence("http_header", "Server", server),
            is_edge=True,
        )

    for key, name, vendor, pattern in _SERVER_PRODUCTS:
        match = pattern.search(server)
        if match:
            version = match.group(1)
            return _observation(
                name,
                vendor,
                "web_server" if key not in {"envoy", "haproxy", "traefik"} else "reverse_proxy",
                version,
                "declared" if version else "unknown",
                "high",
                "http_headers",
                _evidence("http_header", "Server", server),
            )
    return None


def _add_php_header(
    observations: list[dict[str, Any]],
    value: str,
    header_name: str = "X-Powered-By",
) -> None:
    match = re.search(r"\bPHP(?:/" + _VERSION + r")?\b", value, re.I)
    if match:
        version = match.group(1)
        observations.append(
            _observation(
                "PHP",
                "PHP Group",
                "runtime",
                version,
                "declared" if version else "unknown",
                "high",
                "http_headers",
                _evidence("http_header", header_name, match.group(0)),
            )
        )


def _add_generator(observations: list[dict[str, Any]], generator: str) -> None:
    rules = (
        ("wordpress", "WordPress", "WordPress", "cms"),
        ("drupal", "Drupal", "Drupal", "cms"),
        ("joomla", "Joomla", "Open Source Matters", "cms"),
        ("magento", "Magento", "Adobe", "cms"),
        ("prestashop", "PrestaShop", "PrestaShop", "cms"),
        ("laravel", "Laravel", "Laravel", "framework"),
        ("symfony", "Symfony", "Symfony", "framework"),
        ("django", "Django", "Django Software Foundation", "framework"),
    )
    for token, name, vendor, category in rules:
        if token not in generator.lower():
            continue
        match = re.search(r"\b" + re.escape(token) + r"\s*(?:v|version)?\s*" + _VERSION, generator, re.I)
        version = match.group(1) if match else None
        observations.append(
            _observation(
                name,
                vendor,
                category,
                version,
                "declared" if version else "unknown",
                "high",
                "html_meta_generator",
                _evidence("html_meta", "generator", generator),
            )
        )
        return


def _add_asset_observations(observations: list[dict[str, Any]], html: str) -> None:
    assets = re.findall(r"<(?:script|link)\b[^>]*(?:src|href)\s*=\s*['\"]([^'\"]+)['\"]", html, re.I)
    library_rules: tuple[tuple[str, str, str, str, re.Pattern[str]], ...] = (
        ("jquery", "jQuery", "OpenJS Foundation", "frontend_library", re.compile(r"jquery(?:[-./]|(?:\.min))" + _VERSION, re.I)),
        ("bootstrap", "Bootstrap", "Bootstrap Authors", "css_framework", re.compile(r"bootstrap(?:[-./]|(?:\.min))" + _VERSION, re.I)),
        ("vue", "Vue.js", "Evan You", "frontend_framework", re.compile(r"vue(?:[-./]|(?:\.runtime))" + _VERSION, re.I)),
        ("react", "React", "Meta", "frontend_framework", re.compile(r"react(?:[-./])" + _VERSION, re.I)),
        ("angular", "Angular", "Google", "frontend_framework", re.compile(r"angular(?:[-./])" + _VERSION, re.I)),
        ("alpine", "Alpine.js", "Alpine.js", "frontend_framework", re.compile(r"alpine(?:[-./])" + _VERSION, re.I)),
    )
    for asset in assets:
        asset_path = asset.split("?", 1)[0].split("#", 1)[0]
        basename = asset_path.rsplit("/", 1)[-1]
        for token, name, vendor, category, pattern in library_rules:
            if token not in basename.lower() and token not in asset_path.lower():
                continue
            match = pattern.search(asset_path)
            version = match.group(1) if match else None
            observations.append(
                _observation(
                    name,
                    vendor,
                    category,
                    version,
                    "fingerprinted" if version else "unknown",
                    "medium" if version else "low",
                    "public_asset_url",
                    _evidence("public_asset_url", "path", basename),
                )
            )
            break


def merge_observations(observations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[tuple[str, str, str], dict[str, Any]] = {}
    confidence_score = {"low": 0, "medium": 1, "high": 2}
    version_score = {"unknown": 0, "partial": 1, "fingerprinted": 2, "declared": 3, "verified": 4}
    for item in observations:
        key = (item["vendor"].lower(), item["name"].lower(), item["category"])
        current = merged.get(key)
        if current is None:
            merged[key] = dict(item)
            continue
        versions = set(current["observed_versions"]) | set(item["observed_versions"])
        current["observed_versions"] = sorted(versions)
        current["version_conflict"] = len(versions) > 1
        if len(versions) > 1:
            current["version"] = None
            current["version_status"] = "unknown"
            current["confidence"] = "medium"
            current["cpe"] = None
        elif item["version"] and version_score[item["version_status"]] > version_score[current["version_status"]]:
            current["version"] = item["version"]
            current["version_status"] = item["version_status"]
            current["cpe"] = item["cpe"]
        if confidence_score[item["confidence"]] > confidence_score[current["confidence"]] and not current["version_conflict"]:
            current["confidence"] = item["confidence"]
        current["sources"] = sorted(set(current["sources"]) | set(item["sources"]))
        seen_evidence = {(entry["type"], entry["name"], entry["value"]) for entry in current["evidence"]}
        for entry in item["evidence"]:
            evidence_key = (entry["type"], entry["name"], entry["value"])
            if evidence_key not in seen_evidence:
                current["evidence"].append(entry)
                seen_evidence.add(evidence_key)
        if item["is_edge"] is True:
            current["is_edge"] = True
        elif current["is_edge"] is None and item["is_edge"] is not None:
            current["is_edge"] = item["is_edge"]
    return sorted(merged.values(), key=lambda item: (item["category"], item["name"].lower()))


def fingerprint_response(headers: Mapping[str, str], body: bytes | str) -> list[dict[str, Any]]:
    """Extract only public response signatures; never infer an undisclosed version."""
    observations: list[dict[str, Any]] = []
    server = _header(headers, "server")
    if server:
        for server_part in re.split(r",\s*", server):
            server_observation = _server_observation(server_part)
            if server_observation:
                observations.append(server_observation)
        _add_php_header(observations, server, "Server")

    if _header(headers, "cf-ray") or _header(headers, "cf-cache-status"):
        if not any(item["name"] == "Cloudflare" for item in observations):
            observations.append(
                _observation(
                    "Cloudflare",
                    "Cloudflare",
                    "cdn",
                    None,
                    "unknown",
                    "high",
                    "http_headers",
                    _evidence("http_header", "cf-ray", "present"),
                    is_edge=True,
                )
            )

    powered_by = _header(headers, "x-powered-by")
    if powered_by:
        _add_php_header(observations, powered_by)
        if re.search(r"\bASP\.NET\b", powered_by, re.I):
            observations.append(
                _observation(
                    "ASP.NET",
                    "Microsoft",
                    "framework",
                    None,
                    "unknown",
                    "high",
                    "http_headers",
                    _evidence("http_header", "X-Powered-By", "ASP.NET"),
                )
            )
        if re.search(r"\bExpress\b", powered_by, re.I):
            observations.append(
                _observation(
                    "Express",
                    "OpenJS Foundation",
                    "framework",
                    None,
                    "unknown",
                    "high",
                    "http_headers",
                    _evidence("http_header", "X-Powered-By", "Express"),
                )
            )

    cookies = _header(headers, "set-cookie") or ""
    for cookie in re.split(r",(?=[^;,]+=)", cookies):
        cookie_name = cookie.split("=", 1)[0].strip().lower()
        if cookie_name == "phpsessid":
            observations.append(
                _observation(
                    "PHP",
                    "PHP Group",
                    "runtime",
                    None,
                    "unknown",
                    "low",
                    "http_cookie_name",
                    _evidence("http_cookie", "Set-Cookie", "PHPSESSID cookie name present"),
                )
            )
        elif cookie_name == "laravel_session":
            observations.append(
                _observation(
                    "Laravel",
                    "Laravel",
                    "framework",
                    None,
                    "unknown",
                    "medium",
                    "http_cookie_name",
                    _evidence("http_cookie", "Set-Cookie", "laravel_session cookie name present"),
                )
            )

    content_type = (_header(headers, "content-type") or "").split(";", 1)[0].strip().lower()
    is_html = not content_type or content_type in {"text/html", "application/xhtml+xml"}
    if isinstance(body, bytes):
        html = body.decode("utf-8", errors="replace") if is_html else ""
    else:
        html = body if is_html else ""
    html = html[:2_000_000]
    generator_match = re.search(
        r"<meta\b[^>]*\bname\s*=\s*['\"]generator['\"][^>]*\bcontent\s*=\s*['\"]([^'\"]{1,200})['\"]",
        html,
        re.I,
    )
    if generator_match:
        _add_generator(observations, generator_match.group(1))

    lower_html = html.lower()
    cms_signatures = (
        ("wordpress", "WordPress", "WordPress", ("/wp-content/", "/wp-includes/")),
        ("drupal", "Drupal", "Drupal", ("/sites/default/", "drupal.settings")),
        ("joomla", "Joomla", "Open Source Matters", ("/media/system/js/", "com_content")),
        ("magento", "Magento", "Adobe", ("mage/cookies", "/static/version")),
        ("prestashop", "PrestaShop", "PrestaShop", ("prestashop", "content=\"prestashop")),
    )
    for token, name, vendor, markers in cms_signatures:
        if any(marker in lower_html for marker in markers) and not any(item["name"] == name for item in observations):
            marker = next(marker for marker in markers if marker in lower_html)
            observations.append(
                _observation(
                    name,
                    vendor,
                    "cms",
                    None,
                    "unknown",
                    "medium",
                    "html_signature",
                    _evidence("html_signature", token, f"marker {marker} present"),
                )
            )

    if "laravel_session" in lower_html and not any(item["name"] == "Laravel" for item in observations):
        observations.append(
            _observation(
                "Laravel",
                "Laravel",
                "framework",
                None,
                "unknown",
                "low",
                "html_signature",
                _evidence("html_signature", "laravel_session", "marker present"),
            )
        )
    if "__next_data__" in lower_html or "/_next/" in lower_html:
        observations.append(
            _observation(
                "Next.js",
                "Vercel",
                "frontend_framework",
                None,
                "unknown",
                "medium",
                "html_signature",
                _evidence("html_signature", "Next.js", "Next.js document or asset marker present"),
            )
        )
    angular_version = re.search(r"\bng-version\s*=\s*['\"]" + _VERSION + r"['\"]", html, re.I)
    if angular_version:
        observations.append(
            _observation(
                "Angular",
                "Google",
                "frontend_framework",
                angular_version.group(1),
                "declared",
                "high",
                "html_signature",
                _evidence("html_attribute", "ng-version", angular_version.group(1)),
            )
        )
    elif "ng-version" in lower_html:
        observations.append(
            _observation(
                "Angular",
                "Google",
                "frontend_framework",
                None,
                "unknown",
                "medium",
                "html_signature",
                _evidence("html_signature", "ng-version", "attribute present without a parseable version"),
            )
        )
    if "data-v-" in lower_html:
        observations.append(
            _observation(
                "Vue.js",
                "Evan You",
                "frontend_framework",
                None,
                "unknown",
                "low",
                "html_signature",
                _evidence("html_signature", "data-v-", "Vue-style scoped CSS attribute present"),
            )
        )
    if "data-reactroot" in lower_html or "__reactfiber" in lower_html:
        observations.append(
            _observation(
                "React",
                "Meta",
                "frontend_framework",
                None,
                "unknown",
                "low",
                "html_signature",
                _evidence("html_signature", "React marker", "React-style DOM marker present"),
            )
        )

    _add_asset_observations(observations, html)
    return merge_observations(observations)


def inspect_http_headers(headers: Mapping[str, str], scheme: str) -> list[dict[str, str]]:
    """Report a small set of visible response-header checks without claiming full TLS coverage."""
    result: list[dict[str, str]] = []
    csp = _header(headers, "content-security-policy")
    result.append(
        {
            "check": "content_security_policy",
            "status": "present" if csp else "missing",
            "evidence": "Content-Security-Policy header present" if csp else "header not present on the sampled response",
            "recommendation": "Define a policy appropriate to the application; avoid blindly copying a generic policy.",
        }
    )
    nosniff = _header(headers, "x-content-type-options")
    result.append(
        {
            "check": "x_content_type_options",
            "status": "present" if nosniff and nosniff.lower() == "nosniff" else "missing",
            "evidence": "nosniff present" if nosniff and nosniff.lower() == "nosniff" else "nosniff control not present on the sampled response",
            "recommendation": "Set X-Content-Type-Options: nosniff where compatible.",
        }
    )
    frame_options = _header(headers, "x-frame-options")
    has_frame_ancestors = bool(csp and re.search(r"(?:^|;)\s*frame-ancestors\b", csp, re.I))
    result.append(
        {
            "check": "clickjacking_protection",
            "status": "present" if frame_options or has_frame_ancestors else "missing",
            "evidence": "X-Frame-Options or CSP frame-ancestors present" if frame_options or has_frame_ancestors else "neither control present on the sampled response",
            "recommendation": "Set an appropriate CSP frame-ancestors directive or X-Frame-Options policy.",
        }
    )
    if scheme.lower() == "https":
        hsts = _header(headers, "strict-transport-security")
        valid_hsts = bool(hsts and re.search(r"(?:^|;)\s*max-age\s*=\s*[1-9][0-9]*", hsts, re.I))
        result.append(
            {
                "check": "strict_transport_security",
                "status": "present" if valid_hsts else "missing",
                "evidence": "valid max-age directive present" if valid_hsts else "Strict-Transport-Security with positive max-age not present on the sampled response",
                "recommendation": "Enable HSTS after confirming HTTPS is correctly deployed for the intended host scope.",
            }
        )
    else:
        result.append(
            {
                "check": "strict_transport_security",
                "status": "not_applicable",
                "evidence": "sampled URL uses HTTP",
                "recommendation": "Use HTTPS; HSTS is delivered over HTTPS.",
            }
        )
    return result
