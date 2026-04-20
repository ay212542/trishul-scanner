"""
TRISHUL Scanner — Security Header Analyzer
"""
from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from trishul.core.http_client import HTTPClient
from trishul.core.models import Finding, Severity

# (header_name, severity, description, remediation, cwe)
SECURITY_HEADERS: List[Tuple[str, Severity, str, str, str]] = [
    (
        "Content-Security-Policy",
        Severity.HIGH,
        "Missing Content-Security-Policy (CSP) header. Allows XSS and data injection attacks.",
        "Add a strict CSP: Content-Security-Policy: default-src 'self'; ...",
        "CWE-693",
    ),
    (
        "Strict-Transport-Security",
        Severity.HIGH,
        "Missing HTTP Strict Transport Security (HSTS). Allows downgrade attacks.",
        "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        "CWE-523",
    ),
    (
        "X-Frame-Options",
        Severity.MEDIUM,
        "Missing X-Frame-Options. Page can be embedded in iframes (clickjacking risk).",
        "Add: X-Frame-Options: SAMEORIGIN",
        "CWE-1021",
    ),
    (
        "X-Content-Type-Options",
        Severity.MEDIUM,
        "Missing X-Content-Type-Options. Browser may MIME-sniff responses.",
        "Add: X-Content-Type-Options: nosniff",
        "CWE-693",
    ),
    (
        "Referrer-Policy",
        Severity.LOW,
        "Missing Referrer-Policy. Sensitive URL data may leak to third parties.",
        "Add: Referrer-Policy: strict-origin-when-cross-origin",
        "CWE-601",
    ),
    (
        "Permissions-Policy",
        Severity.LOW,
        "Missing Permissions-Policy. Browser features (camera, mic) not restricted.",
        "Add: Permissions-Policy: geolocation=(), camera=(), microphone=()",
        "CWE-693",
    ),
    (
        "X-XSS-Protection",
        Severity.INFO,
        "Missing X-XSS-Protection (legacy header, but still expected by some scanners).",
        "Add: X-XSS-Protection: 1; mode=block (or use CSP instead)",
        "CWE-79",
    ),
]

INSECURE_HEADER_VALUES: List[Tuple[str, str, Severity, str]] = [
    (
        "Server",
        "",  # any value
        Severity.INFO,
        "Server header discloses technology version information.",
    ),
    (
        "X-Powered-By",
        "",
        Severity.INFO,
        "X-Powered-By header discloses backend technology.",
    ),
]


class HeaderAnalyzer:
    """Checks HTTP response headers for security misconfigurations."""

    def __init__(self, client: HTTPClient) -> None:
        self.client = client

    async def analyze(self, url: str) -> List[Finding]:
        findings: List[Finding] = []

        resp = await self.client.get(url)
        if resp is None:
            return findings

        status, headers, body, final_url = resp
        headers_lower: Dict[str, str] = {k.lower(): v for k, v in headers.items()}

        # ── Check for missing security headers ───────────────────────────────
        for header_name, severity, description, remediation, cwe in SECURITY_HEADERS:
            if header_name.lower() not in headers_lower:
                findings.append(
                    Finding(
                        title=f"Missing Header: {header_name}",
                        severity=severity,
                        url=final_url,
                        description=description,
                        evidence=f"Header '{header_name}' not present in HTTP response.",
                        module="header_analyzer",
                        remediation=remediation,
                        cwe=cwe,
                    )
                )
            else:
                # Check CSP for unsafe directives
                if header_name == "Content-Security-Policy":
                    csp_value = headers_lower[header_name.lower()]
                    issues = _check_csp_quality(csp_value)
                    for issue in issues:
                        findings.append(
                            Finding(
                                title=f"Weak CSP: {issue}",
                                severity=Severity.MEDIUM,
                                url=final_url,
                                description=f"Content-Security-Policy contains unsafe directive: {issue}",
                                evidence=f"CSP: {csp_value[:200]}",
                                module="header_analyzer",
                                remediation="Remove unsafe-inline and unsafe-eval directives from CSP.",
                                cwe="CWE-693",
                            )
                        )

                # Check HSTS max-age
                if header_name == "Strict-Transport-Security":
                    hsts_val = headers_lower[header_name.lower()]
                    issue = _check_hsts_quality(hsts_val)
                    if issue:
                        findings.append(
                            Finding(
                                title=f"Weak HSTS: {issue}",
                                severity=Severity.LOW,
                                url=final_url,
                                description=issue,
                                evidence=f"HSTS: {hsts_val}",
                                module="header_analyzer",
                                remediation="Set max-age >= 31536000 and add includeSubDomains.",
                                cwe="CWE-523",
                            )
                        )

        # ── Check for information-disclosing headers ──────────────────────────
        for header_name, _, severity, description in INSECURE_HEADER_VALUES:
            if header_name.lower() in headers_lower:
                val = headers_lower[header_name.lower()]
                findings.append(
                    Finding(
                        title=f"Information Disclosure: {header_name}",
                        severity=severity,
                        url=final_url,
                        description=description,
                        evidence=f"{header_name}: {val}",
                        module="header_analyzer",
                        remediation=f"Remove or mask the '{header_name}' header in your web server config.",
                    )
                )

        return findings


def _check_csp_quality(csp: str) -> List[str]:
    issues = []
    csp_lower = csp.lower()
    if "'unsafe-inline'" in csp_lower:
        issues.append("'unsafe-inline' allows inline scripts/styles")
    if "'unsafe-eval'" in csp_lower:
        issues.append("'unsafe-eval' allows eval() and similar")
    if "data:" in csp_lower:
        issues.append("data: URI scheme can enable XSS")
    if "*" in csp and "nonce" not in csp_lower:
        issues.append("Wildcard (*) source without nonces is overly permissive")
    return issues


def _check_hsts_quality(hsts: str) -> Optional[str]:
    import re
    match = re.search(r"max-age\s*=\s*(\d+)", hsts, re.IGNORECASE)
    if not match:
        return "HSTS max-age directive missing"
    max_age = int(match.group(1))
    if max_age < 31536000:
        return f"HSTS max-age={max_age} is below recommended 31536000 (1 year)"
    return None
