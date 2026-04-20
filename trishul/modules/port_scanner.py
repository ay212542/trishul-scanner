"""
TRISHUL Scanner — Async Port Scanner
Uses asyncio TCP connect scan (no root required).
"""
from __future__ import annotations

import asyncio
from typing import Dict, List, Optional, Tuple

from trishul.core.models import Finding, PortInfo, Severity

# Common + extended ports
COMMON_PORTS: List[int] = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    465, 587, 631, 993, 995, 1433, 1521, 2049, 2375, 2376, 3000,
    3306, 3389, 4443, 4848, 5000, 5432, 5900, 5985, 6379, 6443,
    7070, 7443, 8000, 8008, 8080, 8081, 8082, 8083, 8084, 8085,
    8086, 8087, 8088, 8089, 8090, 8181, 8443, 8444, 8888, 9000,
    9001, 9090, 9200, 9300, 9443, 10000, 11211, 27017, 27018,
    28017, 50000,
]

SERVICE_NAMES: Dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 111: "RPC",
    135: "MSRPC", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 465: "SMTPS", 587: "SMTP/TLS", 631: "IPP",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
    2049: "NFS", 2375: "Docker (unencrypted)", 2376: "Docker TLS",
    3000: "Dev Server", 3306: "MySQL", 3389: "RDP", 4443: "HTTPS-alt",
    4848: "GlassFish", 5000: "Dev/Flask", 5432: "PostgreSQL",
    5900: "VNC", 5985: "WinRM HTTP", 6379: "Redis", 6443: "K8s API",
    7070: "HTTP-alt", 7443: "HTTPS-alt", 8080: "HTTP-alt",
    8443: "HTTPS-alt", 8888: "Jupyter/Dev", 9000: "PHP-FPM/Portainer",
    9090: "Prometheus", 9200: "Elasticsearch", 9300: "Elasticsearch",
    10000: "Webmin", 11211: "Memcached", 27017: "MongoDB",
    28017: "MongoDB Web", 50000: "IBM DB2",
}

RISKY_PORTS: Dict[int, str] = {
    23: "Telnet transmits data in plaintext",
    2375: "Unencrypted Docker daemon—remote code execution risk",
    5900: "VNC often has weak/no authentication",
    6379: "Redis with no authentication configured",
    11211: "Memcached—potential amplification vector",
    27017: "MongoDB with no authentication by default",
    9200: "Elasticsearch with no authentication by default",
    135: "MSRPC—common attack surface on Windows",
    445: "SMB—EternalBlue and ransomware propagation",
}


async def _check_port(host: str, port: int, timeout: float = 3.0) -> bool:
    """Try to open a TCP connection; return True if port is open."""
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except (OSError, asyncio.TimeoutError, ConnectionRefusedError):
        return False


class PortScanner:
    """Async TCP connect port scanner."""

    def __init__(self, host: str, ports: Optional[List[int]] = None) -> None:
        self.host = host
        self.ports = ports or COMMON_PORTS

    async def scan(self, concurrency: int = 200) -> List[PortInfo]:
        sem = asyncio.Semaphore(concurrency)

        async def bounded_check(port: int) -> Tuple[int, bool]:
            async with sem:
                is_open = await _check_port(self.host, port)
                return port, is_open

        tasks = [bounded_check(p) for p in self.ports]
        results = await asyncio.gather(*tasks)

        open_ports = []
        for port, is_open in results:
            if is_open:
                open_ports.append(
                    PortInfo(
                        port=port,
                        is_open=True,
                        service=SERVICE_NAMES.get(port, "Unknown"),
                    )
                )
        return sorted(open_ports, key=lambda p: p.port)

    @staticmethod
    def to_findings(open_ports: List[PortInfo], target_url: str) -> List[Finding]:
        findings = []
        for port_info in open_ports:
            risk = RISKY_PORTS.get(port_info.port)
            if risk:
                findings.append(
                    Finding(
                        title=f"Risky Port Open: {port_info.port}/{port_info.service}",
                        severity=Severity.HIGH,
                        url=target_url,
                        description=risk,
                        evidence=f"Port {port_info.port} ({port_info.service}) is open",
                        module="port_scanner",
                        remediation=(
                            f"Restrict access to port {port_info.port} via firewall rules "
                            "unless explicitly required."
                        ),
                    )
                )
            else:
                findings.append(
                    Finding(
                        title=f"Open Port: {port_info.port}/{port_info.service}",
                        severity=Severity.INFO,
                        url=target_url,
                        description=f"Port {port_info.port} ({port_info.service}) is accessible.",
                        module="port_scanner",
                    )
                )
        return findings
