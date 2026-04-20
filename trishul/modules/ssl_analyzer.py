"""
TRISHUL Scanner — SSL/TLS Certificate Analyzer
"""
from __future__ import annotations

import asyncio
import socket
import ssl
from datetime import datetime, timezone
from typing import List, Optional, Tuple
from urllib.parse import urlparse

from trishul.core.models import Finding, Severity, SSLInfo


async def _get_ssl_info(hostname: str, port: int = 443, timeout: int = 10) -> dict:
    """Retrieve SSL certificate info using stdlib ssl."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _sync_ssl_check, hostname, port, timeout)


def _sync_ssl_check(hostname: str, port: int, timeout: int) -> dict:
    result = {
        "valid": False,
        "hostname_match": False,
        "self_signed": False,
        "expiry_date": None,
        "days_to_expiry": None,
        "issuer": "",
        "subject": "",
        "protocol": "",
        "error": None,
    }

    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                result["valid"] = True
                result["hostname_match"] = True
                result["protocol"] = ssock.version() or ""

                cert = ssock.getpeercert()
                if cert:
                    # Parse expiry
                    not_after = cert.get("notAfter", "")
                    if not_after:
                        try:
                            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                            expiry = expiry.replace(tzinfo=timezone.utc)
                            now = datetime.now(timezone.utc)
                            result["expiry_date"] = expiry.isoformat()
                            result["days_to_expiry"] = (expiry - now).days
                        except ValueError:
                            pass

                    # Issuer / Subject
                    issuer = dict(x[0] for x in cert.get("issuer", ()))
                    subject = dict(x[0] for x in cert.get("subject", ()))
                    result["issuer"] = issuer.get("organizationName", str(issuer))
                    result["subject"] = subject.get("commonName", str(subject))

                    # Self-signed: issuer == subject
                    result["self_signed"] = (
                        cert.get("issuer") == cert.get("subject")
                    )

    except ssl.SSLCertVerificationError as exc:
        result["error"] = str(exc)
        if "hostname" in str(exc).lower():
            result["hostname_match"] = False
        result["valid"] = False
    except ssl.SSLError as exc:
        result["error"] = str(exc)
        result["valid"] = False
    except (OSError, socket.timeout) as exc:
        result["error"] = str(exc)

    return result


class SSLAnalyzer:
    """Analyzes SSL/TLS configuration for a target URL."""

    async def analyze(self, url: str) -> Tuple[Optional[SSLInfo], List[Finding]]:
        parsed = urlparse(url)
        scheme = parsed.scheme.lower()
        findings: List[Finding] = []

        if scheme != "https":
            findings.append(
                Finding(
                    title="HTTPS Not Used",
                    severity=Severity.CRITICAL,
                    url=url,
                    description="The target is accessible over plain HTTP without TLS encryption.",
                    evidence=f"URL scheme: {scheme}",
                    module="ssl_analyzer",
                    remediation=(
                        "Enforce HTTPS by redirecting all HTTP traffic to HTTPS. "
                        "Obtain a free certificate from Let's Encrypt."
                    ),
                    cwe="CWE-319",
                )
            )
            return None, findings

        hostname = parsed.hostname or ""
        port = parsed.port or 443

        raw = await _get_ssl_info(hostname, port)

        ssl_info = SSLInfo(
            valid=raw["valid"],
            hostname_match=raw["hostname_match"],
            self_signed=raw["self_signed"],
            expiry_date=raw["expiry_date"],
            days_to_expiry=raw["days_to_expiry"],
            issuer=raw["issuer"],
            subject=raw["subject"],
            protocol=raw["protocol"],
        )

        error = raw.get("error")

        if not ssl_info.valid:
            findings.append(
                Finding(
                    title="Invalid SSL Certificate",
                    severity=Severity.CRITICAL,
                    url=url,
                    description=f"SSL certificate validation failed: {error}",
                    evidence=error or "Certificate is invalid",
                    module="ssl_analyzer",
                    remediation="Obtain a valid certificate from a trusted CA.",
                    cwe="CWE-295",
                )
            )

        if ssl_info.self_signed:
            findings.append(
                Finding(
                    title="Self-Signed SSL Certificate",
                    severity=Severity.HIGH,
                    url=url,
                    description="Self-signed certificates are not trusted by browsers.",
                    evidence=f"Issuer == Subject: {ssl_info.issuer}",
                    module="ssl_analyzer",
                    remediation="Replace with a certificate from a trusted CA (e.g., Let's Encrypt).",
                    cwe="CWE-295",
                )
            )

        if not ssl_info.hostname_match:
            findings.append(
                Finding(
                    title="SSL Hostname Mismatch",
                    severity=Severity.HIGH,
                    url=url,
                    description="Certificate hostname does not match the requested hostname.",
                    evidence=f"Requested: {hostname} | Cert subject: {ssl_info.subject}",
                    module="ssl_analyzer",
                    remediation="Ensure the SSL certificate covers the correct hostname.",
                    cwe="CWE-297",
                )
            )

        if ssl_info.days_to_expiry is not None:
            if ssl_info.days_to_expiry <= 0:
                findings.append(
                    Finding(
                        title="SSL Certificate Expired",
                        severity=Severity.CRITICAL,
                        url=url,
                        description=f"SSL certificate expired {abs(ssl_info.days_to_expiry)} day(s) ago.",
                        evidence=f"Expiry: {ssl_info.expiry_date}",
                        module="ssl_analyzer",
                        remediation="Renew the SSL certificate immediately.",
                        cwe="CWE-298",
                    )
                )
            elif ssl_info.days_to_expiry <= 30:
                findings.append(
                    Finding(
                        title="SSL Certificate Expiring Soon",
                        severity=Severity.MEDIUM,
                        url=url,
                        description=f"SSL certificate expires in {ssl_info.days_to_expiry} day(s).",
                        evidence=f"Expiry: {ssl_info.expiry_date}",
                        module="ssl_analyzer",
                        remediation="Schedule certificate renewal before expiration.",
                        cwe="CWE-298",
                    )
                )

        return ssl_info, findings
