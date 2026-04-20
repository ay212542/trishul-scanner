"""
TRISHUL Scanner — Fuzz Engine
Discovers sensitive/exposed paths with false-positive reduction.
"""
from __future__ import annotations

import asyncio
from typing import List
from urllib.parse import urljoin

from trishul.core.http_client import HTTPClient
from trishul.core.models import Finding, Severity
from trishul.core.response_analyzer import ResponseAnalyzer

# Comprehensive sensitive path wordlist
SENSITIVE_PATHS: List[str] = [
    # Admin panels
    "/admin", "/admin/", "/admin/login", "/administrator",
    "/wp-admin", "/wp-login.php", "/phpmyadmin", "/phpmyadmin/",
    "/adminer", "/adminer.php", "/panel", "/controlpanel",
    # Config & secrets
    "/.env", "/.env.local", "/.env.production", "/.env.backup",
    "/config.php", "/config.yml", "/config.yaml", "/config.json",
    "/configuration.php", "/settings.php", "/web.config", "/app.config",
    "/.htaccess", "/.htpasswd", "/secrets.yml", "/secrets.json",
    # Source control
    "/.git/", "/.git/HEAD", "/.git/config", "/.svn/", "/.svn/entries",
    "/.DS_Store", "/.hg/", "/Makefile", "/Dockerfile", "/docker-compose.yml",
    # Backups
    "/backup", "/backup/", "/backup.zip", "/backup.tar.gz",
    "/backup.sql", "/dump.sql", "/db.sql", "/database.sql",
    "/site.zip", "/www.zip", "/old/", "/bak/",
    # API endpoints
    "/api", "/api/", "/api/v1", "/api/v2", "/api/v3",
    "/swagger", "/swagger-ui", "/swagger.json", "/swagger.yaml",
    "/openapi.json", "/openapi.yaml", "/graphql", "/graphiql",
    "/api-docs", "/docs", "/redoc",
    # Debug / monitoring
    "/debug", "/test", "/trace", "/debug.php", "/.well-known/",
    "/server-status", "/server-info", "/_profiler", "/status",
    "/metrics", "/health", "/healthz", "/ping", "/_health",
    "/actuator", "/actuator/env", "/actuator/info", "/actuator/metrics",
    "/actuator/health", "/actuator/beans", "/actuator/mappings",
    # Log files
    "/logs", "/log", "/error.log", "/access.log", "/debug.log",
    "/app.log", "/application.log",
    # Common uploads / includes
    "/uploads", "/upload", "/files", "/static", "/assets",
    "/include", "/includes", "/lib", "/vendor", "/node_modules",
    # CMS
    "/wp-content/", "/wp-includes/", "/wp-json/", "/xmlrpc.php",
    "/joomla", "/drupal", "/magento", "/prestashop",
]

SEVERITY_MAP = {
    # High sensitivity paths
    "/.env": Severity.CRITICAL,
    "/.git/": Severity.CRITICAL,
    "/.git/HEAD": Severity.CRITICAL,
    "/wp-admin": Severity.HIGH,
    "/phpmyadmin": Severity.HIGH,
    "/adminer": Severity.HIGH,
    "/actuator/env": Severity.CRITICAL,
    "/actuator/beans": Severity.HIGH,
    "/swagger.json": Severity.HIGH,
    "/openapi.json": Severity.HIGH,
    "/graphql": Severity.MEDIUM,
    "/admin": Severity.MEDIUM,
    "/backup": Severity.HIGH,
}


def _get_severity(path: str) -> Severity:
    for key, sev in SEVERITY_MAP.items():
        if path.startswith(key):
            return sev
    return Severity.MEDIUM


class FuzzEngine:
    """
    Discovers sensitive paths and filters false positives using
    ResponseAnalyzer baseline comparison.
    """

    def __init__(self, client: HTTPClient, analyzer: ResponseAnalyzer) -> None:
        self.client = client
        self.analyzer = analyzer
        self._semaphore = asyncio.Semaphore(20)

    async def fuzz(self, base_url: str) -> List[Finding]:
        # Establish baseline with a random nonexistent path
        baseline_path = "/trishul_nonexistent_path_xk9z"
        baseline_url = urljoin(base_url.rstrip("/") + "/", baseline_path.lstrip("/"))
        resp = await self.client.get(baseline_url)
        if resp:
            _, _, body, _ = resp
            self.analyzer.set_baseline(body)

        # Now fuzz all paths concurrently
        tasks = [self._check_path(base_url, path) for path in SENSITIVE_PATHS]
        results = await asyncio.gather(*tasks)
        return [f for f in results if f is not None]

    async def _check_path(self, base_url: str, path: str) -> Finding | None:
        async with self._semaphore:
            url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
            resp = await self.client.get(url, allow_redirects=False)
            if resp is None:
                return None

            status, headers, body, final_url = resp

            # Filter obvious negatives
            if status == 404:
                return None
            if not self.analyzer.is_interesting_status(status):
                return None

            # False positive check
            if self.analyzer.is_soft_404(status, body):
                return None

            # It's a real hit
            severity = _get_severity(path)
            body_preview = body[:200].decode("utf-8", errors="ignore").strip()[:100]
            content_len = len(body)

            return Finding(
                title=f"Sensitive Path Exposed: {path}",
                severity=severity,
                url=final_url,
                description=(
                    f"The path '{path}' returned HTTP {status} with {content_len} bytes. "
                    f"This may expose sensitive data or functionality."
                ),
                evidence=f"Status: {status} | Content-Length: {content_len} | Preview: {body_preview!r}",
                module="fuzz_engine",
                remediation=(
                    f"Restrict access to '{path}' via web server configuration "
                    "or remove the exposed resource."
                ),
            )
