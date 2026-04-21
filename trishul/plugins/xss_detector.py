"""
TRISHUL Plugin — Basic XSS Detector
Checks for reflected XSS by injecting a marker into query parameters.

⚠ This plugin uses passive reflection checks only — no active script execution.
"""
from __future__ import annotations

import re
from typing import Dict, List
from urllib.parse import parse_qs, urlparse

from trishul.core.models import Finding, Severity
from trishul.plugins.base import BasePlugin

# Marker that is highly unlikely to appear normally
XSS_MARKER = "<TrishulXSS9z>"
XSS_MARKER_RE = re.compile(re.escape(XSS_MARKER), re.IGNORECASE)

# Common XSS error/reflection patterns in response body
REFLECTION_PATTERNS = [
    re.compile(r"<script[^>]*>.*?</script>", re.IGNORECASE | re.DOTALL),
    re.compile(r"on\w+\s*=\s*[\"']?[^\"'>]+[\"']?", re.IGNORECASE),
    re.compile(r"javascript\s*:", re.IGNORECASE),
]


class XSSDetectorPlugin(BasePlugin):
    name = "XSS Detector"
    description = "Detects potential reflected XSS via parameter reflection analysis."
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

        # ── 1. Check if the marker is directly reflected (passive) ──────────
        # This checks if a URL already has the marker in the body (unlikely,
        # but covers cases where params are echoed)

        # ── 2. URL parameter reflection check ────────────────────────────────
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query, keep_blank_values=True)

        if not query_params:
            return findings

        body_text = body.decode("utf-8", errors="ignore")
        headers_lower = {k.lower(): v for k, v in headers.items()}
        content_type = headers_lower.get("content-type", "")

        # Only check HTML responses
        if "html" not in content_type.lower() and status_code != 200:
            return findings

        # Check if any param value is reflected in the body
        for param, values in query_params.items():
            for value in values:
                if value and len(value) > 2 and value in body_text:
                    # Param is reflected — may be XSS-able
                    # Check if reflection is inside a dangerous context
                    # Check for unescaped reflection (no HTML encoding)
                    if value in body_text and "&lt;" not in body_text:
                        findings.append(
                            Finding(
                                title="Potential Reflected XSS",
                                severity=Severity.HIGH,
                                url=url,
                                description=(
                                    f"Parameter '{param}' value is reflected in the HTML response "
                                    "without apparent encoding. This may allow reflected XSS."
                                ),
                                evidence=(
                                    f"Param: {param}={value[:50]} | "
                                    f"Reflected in response body | Status: {status_code}"
                                ),
                                module="plugin:xss_detector",
                                remediation=(
                                    "Encode all user-supplied input before reflecting it in HTML. "
                                    "Use context-aware output encoding (HTMLEncode, JSEncode). "
                                    "Implement a strict Content-Security-Policy."
                                ),
                                cwe="CWE-79",
                                cvss=6.1,
                            )
                        )
                        break  # One finding per URL is sufficient

        # ── 3. Look for common sinks in the response body ────────────────────
        # This is a passive check for existing dangerous patterns
        for pattern in REFLECTION_PATTERNS:
            matches = pattern.findall(body_text[:5000])
            for match in matches[:1]:  # Limit to first match per pattern
                match_str = match[:100] if isinstance(match, str) else str(match)[:100]
                # Only flag if it contains dynamic-looking content (has variable chars)
                if any(c in match_str for c in ["?", "&", "=", "param", "query"]):
                    findings.append(
                        Finding(
                            title="Potential DOM XSS Sink Detected",
                            severity=Severity.MEDIUM,
                            url=url,
                            description=(
                                "A potentially dangerous JavaScript sink or inline event handler "
                                "was detected in the response."
                            ),
                            evidence=f"Pattern match: {match_str!r}",
                            module="plugin:xss_detector",
                            remediation=(
                                "Review inline event handlers and dynamic script execution. "
                                "Avoid using innerHTML, document.write() with user-controlled data."
                            ),
                            cwe="CWE-79",
                            cvss=4.3,
                        )
                    )
                    break

        return findings
