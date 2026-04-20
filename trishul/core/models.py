"""
TRISHUL Scanner — Core Data Models
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


SEVERITY_COLORS: Dict[str, str] = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "INFO": "dim white",
}

SEVERITY_ORDER: Dict[str, int] = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
}


@dataclass
class Finding:
    """Represents a single vulnerability finding."""
    title: str
    severity: Severity
    url: str
    description: str
    evidence: str = ""
    module: str = ""
    remediation: str = ""
    cwe: str = ""
    cvss: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "title": self.title,
            "severity": self.severity.value,
            "url": self.url,
            "description": self.description,
            "evidence": self.evidence,
            "module": self.module,
            "remediation": self.remediation,
            "cwe": self.cwe,
            "cvss": self.cvss,
        }


@dataclass
class ScanConfig:
    """Configuration for a scan run."""
    target_url: str
    depth: int = 3
    enabled_modules: List[str] = field(default_factory=lambda: ["crawler", "ports", "headers", "fuzz", "ssl", "tech", "plugins"])
    report_format: str = "cli"
    output_file: Optional[str] = None
    rate_limit: int = 10
    timeout: int = 10
    retries: int = 3
    plugins_dir: Optional[str] = None
    verbose: bool = False


@dataclass
class PortInfo:
    port: int
    is_open: bool
    service: str = ""
    banner: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "port": self.port,
            "is_open": self.is_open,
            "service": self.service,
            "banner": self.banner,
        }


@dataclass
class SSLInfo:
    valid: bool
    hostname_match: bool
    self_signed: bool
    expiry_date: Optional[str]
    days_to_expiry: Optional[int]
    issuer: str
    subject: str
    protocol: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "valid": self.valid,
            "hostname_match": self.hostname_match,
            "self_signed": self.self_signed,
            "expiry_date": self.expiry_date,
            "days_to_expiry": self.days_to_expiry,
            "issuer": self.issuer,
            "subject": self.subject,
            "protocol": self.protocol,
        }


@dataclass
class TechInfo:
    server: str = ""
    framework: str = ""
    cdn: str = ""
    language: str = ""
    cms: str = ""
    extras: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "server": self.server,
            "framework": self.framework,
            "cdn": self.cdn,
            "language": self.language,
            "cms": self.cms,
            "extras": self.extras,
        }


@dataclass
class ScanResult:
    """Aggregated result of a complete scan."""
    target_url: str
    scan_start: str = field(default_factory=lambda: datetime.now().isoformat())
    scan_end: str = ""
    findings: List[Finding] = field(default_factory=list)
    crawled_urls: List[str] = field(default_factory=list)
    open_ports: List[PortInfo] = field(default_factory=list)
    ssl_info: Optional[SSLInfo] = None
    tech_info: Optional[TechInfo] = None
    errors: List[str] = field(default_factory=list)

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)

    def sorted_findings(self) -> List[Finding]:
        return sorted(self.findings, key=lambda f: SEVERITY_ORDER.get(f.severity.value, 99))

    def summary(self) -> Dict[str, int]:
        counts: Dict[str, int] = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_url": self.target_url,
            "scan_start": self.scan_start,
            "scan_end": self.scan_end,
            "summary": self.summary(),
            "findings": [f.to_dict() for f in self.sorted_findings()],
            "crawled_urls": self.crawled_urls,
            "open_ports": [p.to_dict() for p in self.open_ports],
            "ssl_info": self.ssl_info.to_dict() if self.ssl_info else None,
            "tech_info": self.tech_info.to_dict() if self.tech_info else None,
            "errors": self.errors,
        }
