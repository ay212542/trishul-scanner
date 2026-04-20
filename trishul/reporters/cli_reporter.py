"""
TRISHUL Scanner — Rich CLI Reporter
Renders scan results to the terminal with color-coded severity badges.
"""
from __future__ import annotations



from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from trishul.core.models import (
    SEVERITY_COLORS,
    Finding,
    ScanResult,
)

SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🔵",
    "INFO": "⚪",
}


class CLIReporter:
    """Renders scan results with Rich formatting."""

    def __init__(self, console: Console) -> None:
        self.console = console

    def report(self, result: ScanResult) -> None:
        self.console.print()
        self.console.print(Rule("[bold cyan]TRISHUL SCAN RESULTS[/bold cyan]", style="cyan"))

        # ── Summary Banner ────────────────────────────────────────────────────
        self._print_summary(result)

        # ── Scan Metadata ─────────────────────────────────────────────────────
        self._print_metadata(result)

        # ── Tech Info ─────────────────────────────────────────────────────────
        if result.tech_info:
            self._print_tech(result)

        # ── SSL Info ──────────────────────────────────────────────────────────
        if result.ssl_info:
            self._print_ssl(result)

        # ── Open Ports ────────────────────────────────────────────────────────
        if result.open_ports:
            self._print_ports(result)

        # ── Findings ──────────────────────────────────────────────────────────
        self._print_findings(result)

        # ── Crawled URLs ──────────────────────────────────────────────────────
        if result.crawled_urls:
            self.console.print(
                f"\n[dim]Crawled {len(result.crawled_urls)} URLs[/dim]"
            )

        # ── Errors ────────────────────────────────────────────────────────────
        if result.errors:
            self.console.print("\n[bold red]Errors during scan:[/bold red]")
            for err in result.errors:
                self.console.print(f"  [red]• {err}[/red]")

        self.console.print(Rule(style="dim"))

    def _print_summary(self, result: ScanResult) -> None:
        summary = result.summary()
        total = sum(summary.values())

        table = Table(title="Findings Summary", show_header=True,
                      header_style="bold white", box=None, padding=(0, 2))
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            table.add_column(sev, style=SEVERITY_COLORS[sev], justify="center")

        table.add_row(
            *[f"{SEVERITY_EMOJI[s]} {summary[s]}" for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]]
        )

        panel_content = Text()
        panel_content.append(f"Total Findings: {total}\n", style="bold white")
        panel_content.append(f"Target: {result.target_url}\n", style="dim")
        if result.scan_end:
            panel_content.append(f"Scan Time: {result.scan_start[:19]} → {result.scan_end[:19]}", style="dim")

        self.console.print(Panel(panel_content, title="[bold]Scan Complete[/bold]",
                                 border_style="cyan"))
        self.console.print(table)

    def _print_metadata(self, result: ScanResult) -> None:
        pass  # Covered in summary

    def _print_tech(self, result: ScanResult) -> None:
        tech = result.tech_info
        if not tech:
            return
        self.console.print("\n[bold white]🔍 Technology Stack[/bold white]")
        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column("Key", style="bold dim", width=20)
        table.add_column("Value", style="white")
        if tech.server:
            table.add_row("Server", tech.server)
        if tech.framework:
            table.add_row("Framework", tech.framework)
        if tech.cms:
            table.add_row("CMS", tech.cms)
        if tech.cdn:
            table.add_row("CDN", tech.cdn)
        if tech.language:
            table.add_row("Language", tech.language)
        for k, v in tech.extras.items():
            table.add_row(k.title(), v)
        self.console.print(table)

    def _print_ssl(self, result: ScanResult) -> None:
        ssl = result.ssl_info
        if not ssl:
            return
        self.console.print("\n[bold white]🔒 SSL/TLS Info[/bold white]")
        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column("Key", style="bold dim", width=20)
        table.add_column("Value", style="white")
        table.add_row("Valid", "[green]✔ Yes[/green]" if ssl.valid else "[red]✘ No[/red]")
        table.add_row("Protocol", ssl.protocol or "Unknown")
        table.add_row("Issuer", ssl.issuer)
        table.add_row("Subject", ssl.subject)
        if ssl.days_to_expiry is not None:
            color = "red" if ssl.days_to_expiry <= 30 else "green"
            table.add_row("Expires In", f"[{color}]{ssl.days_to_expiry} days[/{color}]")
        self.console.print(table)

    def _print_ports(self, result: ScanResult) -> None:
        self.console.print("\n[bold white]🔌 Open Ports[/bold white]")
        table = Table(show_header=True, header_style="bold dim", box=None, padding=(0, 2))
        table.add_column("Port", style="cyan", width=8)
        table.add_column("Service", style="white")
        for port in result.open_ports:
            table.add_row(str(port.port), port.service)
        self.console.print(table)

    def _print_findings(self, result: ScanResult) -> None:
        findings = result.sorted_findings()
        if not findings:
            self.console.print("\n[bold green]✔ No vulnerability findings.[/bold green]")
            return

        self.console.print(f"\n[bold white]⚠ Findings ({len(findings)} total)[/bold white]\n")
        for i, finding in enumerate(findings, 1):
            sev_color = SEVERITY_COLORS.get(finding.severity.value, "white")
            emoji = SEVERITY_EMOJI.get(finding.severity.value, "•")

            sev_badge = f"[{sev_color}][{finding.severity.value}][/{sev_color}]"
            title_line = Text()
            title_line.append(f"{i}. {emoji} ", style="bold")
            title_line.append(f"[{finding.severity.value}] ", style=sev_color + " bold")
            title_line.append(finding.title, style="bold white")

            self.console.print(title_line)
            self.console.print(f"   [dim]URL:[/dim] {finding.url}")
            self.console.print(f"   [dim]Module:[/dim] {finding.module}")
            self.console.print(f"   [dim]Description:[/dim] {finding.description}")
            if finding.evidence:
                self.console.print(f"   [dim]Evidence:[/dim] [italic]{finding.evidence[:150]}[/italic]")
            if finding.remediation:
                self.console.print(f"   [dim]Fix:[/dim] [green]{finding.remediation[:150]}[/green]")
            if finding.cwe:
                self.console.print(f"   [dim]CWE:[/dim] {finding.cwe}")
            self.console.print()
