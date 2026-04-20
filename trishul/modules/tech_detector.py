"""
TRISHUL Scanner — Technology Detector
Fingerprints server, framework, CDN, CMS from headers and HTML.
"""
from __future__ import annotations

import re
from typing import Dict

from trishul.core.http_client import HTTPClient
from trishul.core.models import TechInfo

# ── Server / Framework fingerprints (header-based) ──────────────────────────
SERVER_FINGERPRINTS: Dict[str, str] = {
    "nginx": "Nginx", "apache": "Apache", "iis": "Microsoft IIS",
    "litespeed": "LiteSpeed", "caddy": "Caddy", "gunicorn": "Gunicorn",
    "uvicorn": "Uvicorn", "tornado": "Tornado", "node": "Node.js",
    "openresty": "OpenResty", "cloudflare": "Cloudflare",
}

FRAMEWORK_FINGERPRINTS: Dict[str, str] = {
    "django": "Django", "flask": "Flask", "fastapi": "FastAPI",
    "rails": "Ruby on Rails", "spring": "Spring Framework",
    "express": "Express.js", "laravel": "Laravel", "symfony": "Symfony",
    "asp.net": "ASP.NET", "next.js": "Next.js", "nuxt": "Nuxt.js",
    "wordpress": "WordPress", "drupal": "Drupal", "joomla": "Joomla",
}

CDN_FINGERPRINTS: Dict[str, str] = {
    "cloudflare": "Cloudflare", "akamai": "Akamai",
    "fastly": "Fastly", "cloudfront": "AWS CloudFront",
    "sucuri": "Sucuri", "incapsula": "Imperva Incapsula",
    "azure": "Azure CDN", "bunny": "Bunny CDN",
}

LANG_FINGERPRINTS: Dict[str, str] = {
    "php": "PHP", "python": "Python", "ruby": "Ruby",
    "java": "Java", "node": "Node.js", "perl": "Perl",
    "asp": "ASP", ".net": ".NET",
}

# ── HTML-based patterns ──────────────────────────────────────────────────────
CMS_HTML_PATTERNS: Dict[str, str] = {
    "wp-content": "WordPress",
    "wp-includes": "WordPress",
    'content="wordpress': "WordPress",
    "drupal.settings": "Drupal",
    "/sites/default/files": "Drupal",
    'content="joomla': "Joomla",
    "magento": "Magento",
    "prestashop": "PrestaShop",
    "shopify.com": "Shopify",
    "squarespace": "Squarespace",
    "wix.com": "Wix",
}

GENERATOR_RE = re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', re.IGNORECASE)


def _match_fingerprints(source: str, fingerprints: Dict[str, str]) -> str:
    source_lower = source.lower()
    for key, name in fingerprints.items():
        if key.lower() in source_lower:
            return name
    return ""


class TechDetector:
    """Detects technologies from headers and HTML body."""

    def __init__(self, client: HTTPClient) -> None:
        self.client = client

    async def detect(self, url: str) -> TechInfo:
        tech = TechInfo()
        resp = await self.client.get(url)
        if resp is None:
            return tech

        status, headers, body, final_url = resp
        headers_str = str(headers)
        headers_lower = {k.lower(): v for k, v in headers.items()}

        html = body.decode("utf-8", errors="ignore")

        # ── Server ──────────────────────────────────────────────────────────
        server_header = headers_lower.get("server", "")
        tech.server = _match_fingerprints(server_header, SERVER_FINGERPRINTS) or server_header[:50]

        # ── Framework ───────────────────────────────────────────────────────
        powered_by = headers_lower.get("x-powered-by", "")
        framework = _match_fingerprints(powered_by, FRAMEWORK_FINGERPRINTS)
        if not framework:
            framework = _match_fingerprints(headers_str, FRAMEWORK_FINGERPRINTS)
        if not framework:
            framework = _match_fingerprints(html[:5000], FRAMEWORK_FINGERPRINTS)
        tech.framework = framework

        # ── CDN ─────────────────────────────────────────────────────────────
        cf_ray = headers_lower.get("cf-ray", "")
        if cf_ray:
            tech.cdn = "Cloudflare"
        else:
            tech.cdn = _match_fingerprints(headers_str, CDN_FINGERPRINTS)

        # ── Language ────────────────────────────────────────────────────────
        tech.language = _match_fingerprints(powered_by, LANG_FINGERPRINTS)
        if not tech.language:
            tech.language = _match_fingerprints(headers_str, LANG_FINGERPRINTS)

        # ── CMS from HTML ────────────────────────────────────────────────────
        html_lower = html[:10000].lower()
        for pattern, cms_name in CMS_HTML_PATTERNS.items():
            if pattern.lower() in html_lower:
                tech.cms = cms_name
                break

        # ── Generator meta tag ───────────────────────────────────────────────
        gen_match = GENERATOR_RE.search(html[:5000])
        if gen_match:
            gen_val = gen_match.group(1).strip()
            tech.extras["generator"] = gen_val
            if not tech.cms:
                tech.cms = gen_val

        # ── Extras ───────────────────────────────────────────────────────────
        for extra_header in ["x-generator", "x-aspnet-version", "x-aspnetmvc-version"]:
            if extra_header in headers_lower:
                tech.extras[extra_header] = headers_lower[extra_header]

        return tech
