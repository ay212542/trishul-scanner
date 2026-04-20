"""
TRISHUL Scanner — CLI Entry Point
"""
from __future__ import annotations

import asyncio
import sys
from typing import List, Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from trishul.core.engine import ScanEngine
from trishul.core.models import ScanConfig

console = Console()

BANNER = """
████████╗██████╗ ██╗███████╗██╗  ██╗██╗   ██╗██╗
╚══██╔══╝██╔══██╗██║██╔════╝██║  ██║██║   ██║██║
   ██║   ██████╔╝██║███████╗███████║██║   ██║██║
   ██║   ██╔══██╗██║╚════██║██╔══██║██║   ██║██║
   ██║   ██║  ██║██║███████║██║  ██║╚██████╔╝███████╗
   ╚═╝   ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝
               Advanced Web Vulnerability Scanner v1.0.0
          [ By TRISHUL Project | For Educational Use Only ]
"""

DISCLAIMER = """
⚠  LEGAL DISCLAIMER
This tool is intended for authorized security testing ONLY.
Scanning systems without explicit written permission is illegal.
The authors assume NO liability for misuse or damage caused.
Always obtain proper authorization before scanning any target.
"""


def print_banner() -> None:
    console.print(Text(BANNER, style="bold cyan"))
    console.print(
        Panel(DISCLAIMER, border_style="yellow", title="[bold red]WARNING[/bold red]")
    )


@click.command()
@click.argument("target_url")
@click.option("--depth", "-d", default=3, show_default=True,
              help="Crawler depth (1–10).")
@click.option("--output", "-o", default=None,
              help="Output file path (auto-detects format from extension).")
@click.option("--format", "-f", "report_format",
              type=click.Choice(["json", "html", "cli"], case_sensitive=False),
              default="cli", show_default=True, help="Report format.")
@click.option("--modules", "-m", default="all",
              help="Comma-separated module list or 'all'. "
                   "Available: crawler,ports,headers,fuzz,ssl,tech,plugins")
@click.option("--rate-limit", default=10, show_default=True,
              help="Max requests per second.")
@click.option("--timeout", default=10, show_default=True,
              help="Request timeout in seconds.")
@click.option("--retries", default=3, show_default=True,
              help="Max retry attempts per request.")
@click.option("--plugins-dir", default=None,
              help="Path to custom plugins directory.")
@click.option("--no-banner", is_flag=True, default=False,
              help="Suppress the banner.")
@click.option("--verbose", "-v", is_flag=True, default=False,
              help="Verbose output.")
def main(
    target_url: str,
    depth: int,
    output: Optional[str],
    report_format: str,
    modules: str,
    rate_limit: int,
    timeout: int,
    retries: int,
    plugins_dir: Optional[str],
    no_banner: bool,
    verbose: bool,
) -> None:
    """
    TRISHUL Scanner — Scan TARGET_URL for web vulnerabilities.

    \b
    Examples:
      trishul http://example.com
      trishul http://example.com -d 5 -f json -o report.json
      trishul http://example.com -m "headers,ssl,tech" -v
    """
    if not no_banner:
        print_banner()

    # Parse enabled modules
    if modules.strip().lower() == "all":
        enabled_modules: List[str] = ["crawler", "ports", "headers", "fuzz", "ssl", "tech", "plugins"]
    else:
        enabled_modules = [m.strip().lower() for m in modules.split(",")]

    config = ScanConfig(
        target_url=target_url,
        depth=max(1, min(depth, 10)),
        enabled_modules=enabled_modules,
        report_format=report_format,
        output_file=output,
        rate_limit=rate_limit,
        timeout=timeout,
        retries=retries,
        plugins_dir=plugins_dir,
        verbose=verbose,
    )

    try:
        asyncio.run(run_scan(config))
    except KeyboardInterrupt:
        console.print("\n[bold red]Scan interrupted by user.[/bold red]")
        sys.exit(1)


async def run_scan(config: ScanConfig) -> None:
    engine = ScanEngine(config)
    result = await engine.run()

    from trishul.reporters.cli_reporter import CLIReporter
    from trishul.reporters.json_reporter import JSONReporter
    from trishul.reporters.html_reporter import HTMLReporter

    cli_reporter = CLIReporter(console)
    cli_reporter.report(result)

    if config.report_format == "json" and config.output_file:
        JSONReporter().save(result, config.output_file)
        console.print(f"\n[bold green]✔ JSON report saved:[/bold green] {config.output_file}")
    elif config.report_format == "html" and config.output_file:
        HTMLReporter().save(result, config.output_file)
        console.print(f"\n[bold green]✔ HTML report saved:[/bold green] {config.output_file}")

    # Always auto-save if output specified
    if config.output_file and config.report_format == "cli":
        JSONReporter().save(result, config.output_file)
        console.print(f"\n[bold green]✔ Report saved:[/bold green] {config.output_file}")


if __name__ == "__main__":
    main()
