"""
TRISHUL Plugin — Basic SQL Injection Detector
Passive error-based detection: checks response for SQL error strings.

⚠ This is a passive/heuristic plugin. It does NOT inject payloads.
"""
from __future__ import annotations

import re
from typing import Dict, List

from trishul.core.models import Finding, Severity
from trishul.plugins.base import BasePlugin

# Common SQL error messages from various databases
SQL_ERROR_PATTERNS = [
    # MySQL
    (re.compile(r"you have an error in your sql syntax", re.IGNORECASE), "MySQL"),
    (re.compile(r"warning: mysql_", re.IGNORECASE), "MySQL"),
    (re.compile(r"mysql_num_rows\(\)", re.IGNORECASE), "MySQL"),
    (re.compile(r"supplied argument is not a valid mysql", re.IGNORECASE), "MySQL"),
    # PostgreSQL
    (re.compile(r"postgresql.*error", re.IGNORECASE), "PostgreSQL"),
    (re.compile(r"pg_query\(\): query failed", re.IGNORECASE), "PostgreSQL"),
    (re.compile(r"syntax error at or near", re.IGNORECASE), "PostgreSQL"),
    # MSSQL
    (re.compile(r"microsoft.*ole db.*sql server", re.IGNORECASE), "MSSQL"),
    (re.compile(r"odbc sql server driver", re.IGNORECASE), "MSSQL"),
    (re.compile(r"unclosed quotation mark after the character string", re.IGNORECASE), "MSSQL"),
    (re.compile(r"incorrect syntax near", re.IGNORECASE), "MSSQL"),
    # Oracle
    (re.compile(r"ora-\d{5}:", re.IGNORECASE), "Oracle"),
    (re.compile(r"quoted string not properly terminated", re.IGNORECASE), "Oracle"),
    # SQLite
    (re.compile(r"sqlite3::exception", re.IGNORECASE), "SQLite"),
    (re.compile(r"sqlite_step\(\)", re.IGNORECASE), "SQLite"),
    # Generic
    (re.compile(r"sql syntax.*?for the right syntax", re.IGNORECASE), "Generic SQL"),
    (re.compile(r"division by zero", re.IGNORECASE), "Generic SQL"),
    (re.compile(r"supplied argument is not a valid mysql result", re.IGNORECASE), "MySQL"),
]

# Patterns for parameter-based injection opportunity
INJECTION_PARAM_MARKERS = ["id", "user", "username", "search", "q", "query",
                           "cat", "category", "page", "item", "product", "order"]


class SQLiDetectorPlugin(BasePlugin):
    name = "SQL Injection Detector"
    description = "Detects SQL injection vulnerabilities via error-based passive analysis."
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
        body_text = body.decode("utf-8", errors="ignore")

        # ── 1. Error-based: scan response body for SQL error strings ─────────
        for pattern, db_name in SQL_ERROR_PATTERNS:
            match = pattern.search(body_text[:10000])
            if match:
                findings.append(
                    Finding(
                        title=f"SQL Error Disclosure ({db_name})",
                        severity=Severity.HIGH,
                        url=url,
                        description=(
                            f"The server returned a {db_name} SQL error message in the response. "
                            "This indicates unsanitized user input reaching the database layer."
                        ),
                        evidence=f"Error pattern: {match.group(0)[:200]!r}",
                        module="plugin:sqli_detector",
                        remediation=(
                            "Use parameterized queries / prepared statements. "
                            "Never expose raw database errors to users. "
                            "Implement a generic error page."
                        ),
                        cwe="CWE-89",
                        cvss=8.5,
                    )
                )
                break  # One finding per URL

        # ── 2. Heuristic: URL has numeric/injection-prone params ──────────────
        if "?" in url and not findings:
            from urllib.parse import parse_qs, urlparse
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            for param_name in params:
                if param_name.lower() in INJECTION_PARAM_MARKERS:
                    param_value = params[param_name][0] if params[param_name] else ""
                    # Check if value looks like a number (classic injection target)
                    if param_value.isdigit():
                        findings.append(
                            Finding(
                                title="Potential SQL Injection Point",
                                severity=Severity.MEDIUM,
                                url=url,
                                description=(
                                    f"Parameter '{param_name}' with numeric value appears to be "
                                    "a potential SQL injection entry point. Manual verification required."
                                ),
                                evidence=f"URL parameter: {param_name}={param_value}",
                                module="plugin:sqli_detector",
                                remediation=(
                                    "Validate and sanitize all user inputs. "
                                    "Use ORM or parameterized queries."
                                ),
                                cwe="CWE-89",
                                cvss=5.0,
                            )
                        )
                        break

        return findings
