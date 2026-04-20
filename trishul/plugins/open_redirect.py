"""
TRISHUL Plugin — Open Redirect Detector
Detects open redirect vulnerabilities by analyzing redirect parameters.

⚠ Passive analysis only — checks for unvalidated redirect parameters.
"""
from __future__ import annotations

import re
from typing import Dict, List
from urllib.parse import parse_qs, urlparse

from trishul.core.models import Finding, Severity
from trishul.plugins.base import BasePlugin

# Common redirect parameter names
REDIRECT_PARAMS = [
    "redirect", "redirect_uri", "redirect_url", "redirecturl",
    "redirect_to", "redirectto", "next", "url", "return", "returnurl",
    "return_to", "goto", "target", "destination", "dest", "to",
    "forward", "continue", "ref", "referer", "referrer", "r", "u",
    "link", "follow", "location",
]

# External URL patterns in redirect params
EXTERNAL_URL_RE = re.compile(
    r"https?://(?!(?:localhost|127\.0\.0\.1|0\.0\.0\.0))", re.IGNORECASE
)

# Protocol-relative URLs
PROTO_REL_RE = re.compile(r"//[a-zA-Z0-9\-\.]+\.", re.IGNORECASE)


def _is_external(value: str, base_host: str) -> bool:
    """Check if a redirect value points to an external host."""
    # Absolute URL
    if EXTERNAL_URL_RE.match(value):
        parsed = urlparse(value)
        if parsed.netloc and parsed.netloc != base_host:
            return True
    # Protocol-relative
    if PROTO_REL_RE.match(value):
        return True
    # URL-encoded schemes
    lower = value.lower()
    for scheme in ["%2f%2f", "%2f%2", "//", "\\\\", "%5c%5c"]:
        if lower.startswith(scheme):
            return True
    return False


class OpenRedirectPlugin(BasePlugin):
    name = "Open Redirect Detector"
    description = "Detects unvalidated open redirect vulnerabilities in URL parameters."
    author = "TRISHUL Project"
    version = "1.0.0"

    async def run(
        self,
        url: str,
        headers: Dict[str, str],
        body: bytes,
        status_code: int,
    ) -> List[Finding]:
        findings: List[Finding] = []

        parsed = urlparse(url)
        base_host = parsed.netloc
        query_params = parse_qs(parsed.query, keep_blank_values=True)

        # ── 1. Check redirect params in URL ───────────────────────────────────
        for param in REDIRECT_PARAMS:
            if param in query_params:
                values = query_params[param]
                for value in values:
                    if _is_external(value, base_host):
                        findings.append(
                            Finding(
                                title="Open Redirect Parameter Detected",
                                severity=Severity.MEDIUM,
                                url=url,
                                description=(
                                    f"Parameter '{param}' contains an external URL that could "
                                    "be used for open redirect attacks and phishing."
                                ),
                                evidence=(
                                    f"Param: {param}={value[:100]} | "
                                    f"Base host: {base_host}"
                                ),
                                module="plugin:open_redirect",
                                remediation=(
                                    "Validate redirect destinations against a whitelist of allowed URLs. "
                                    "Never redirect to arbitrary user-supplied URLs. "
                                    "Use relative paths for internal redirects."
                                ),
                                cwe="CWE-601",
                                cvss=6.1,
                            )
                        )
                        break

        # ── 2. Check response Location header for external redirect ───────────
        if status_code in (301, 302, 303, 307, 308):
            headers_lower = {k.lower(): v for k, v in headers.items()}
            location = headers_lower.get("location", "")
            if location and _is_external(location, base_host):
                # Check if a redirect param was in the URL (suggests user-controlled)
                had_redirect_param = any(p in query_params for p in REDIRECT_PARAMS)
                if had_redirect_param:
                    findings.append(
                        Finding(
                            title="Confirmed Open Redirect",
                            severity=Severity.HIGH,
                            url=url,
                            description=(
                                "The server performed an external redirect following a user-supplied "
                                f"redirect parameter. Location: {location}"
                            ),
                            evidence=(
                                f"Status: {status_code} | Location: {location[:200]}"
                            ),
                            module="plugin:open_redirect",
                            remediation=(
                                "Implement strict URL validation. Only allow redirects to "
                                "pre-approved internal paths."
                            ),
                            cwe="CWE-601",
                            cvss=7.4,
                        )
                    )

        return findings
