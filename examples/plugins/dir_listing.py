# Example: Custom Plugin — Directory Listing Detector
# Save to: trishul/plugins/dir_listing.py  OR  --plugins-dir ./examples/plugins/

from typing import Dict, List
from trishul.core.models import Finding, Severity
from trishul.plugins.base import BasePlugin


class DirectoryListingPlugin(BasePlugin):
    """
    Detects exposed directory listings.

    Directory listing reveals file structure and can expose
    sensitive files, backups, or configuration files.
    """

    name = "Directory Listing Detector"
    description = "Detects enabled directory listing on the web server."
    author = "TRISHUL Project"
    version = "1.0.0"

    # Signatures that indicate directory listing is enabled
    LISTING_SIGNATURES = [
        "index of /",
        "parent directory",
        "directory listing for",
        "<title>index of",
        "[to parent directory]",
        "last modified",  # Common in Apache directory listings
    ]

    async def run(
        self,
        url: str,
        headers: Dict[str, str],
        body: bytes,
        status_code: int,
    ) -> List[Finding]:
        findings = []

        if status_code != 200:
            return findings

        headers_lower = {k.lower(): v for k, v in headers.items()}
        content_type = headers_lower.get("content-type", "")
        if "html" not in content_type.lower():
            return findings

        body_text = body.decode("utf-8", errors="ignore").lower()

        matches = [sig for sig in self.LISTING_SIGNATURES if sig in body_text]
        if len(matches) >= 2:  # Require at least 2 signatures to reduce false positives
            findings.append(
                Finding(
                    title="Directory Listing Enabled",
                    severity=Severity.MEDIUM,
                    url=url,
                    description=(
                        "The web server has directory listing enabled. "
                        "This exposes the file structure and may reveal sensitive files."
                    ),
                    evidence=f"Detected signatures: {', '.join(matches[:3])}",
                    module="plugin:dir_listing",
                    remediation=(
                        "Disable directory listing in your web server config:\n"
                        "  Apache: Options -Indexes\n"
                        "  Nginx: autoindex off;"
                    ),
                    cwe="CWE-548",
                    cvss=5.3,
                )
            )

        return findings
