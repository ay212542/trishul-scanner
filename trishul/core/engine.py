"""
TRISHUL Scanner — Scan Engine (Orchestrator)
"""
from __future__ import annotations

from datetime import datetime
from typing import List
from urllib.parse import urlparse

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

from trishul.core.http_client import HTTPClient
from trishul.core.models import ScanConfig, ScanResult, Finding

console = Console()


class ScanEngine:
    """
    Orchestrates all scanning modules and aggregates findings into a ScanResult.
    """

    def __init__(self, config: ScanConfig) -> None:
        self.config = config
        self.result = ScanResult(target_url=config.target_url)

    async def run(self) -> ScanResult:
        console.print(f"\n[bold cyan]🎯 Target:[/bold cyan] {self.config.target_url}")
        console.print(
            f"[dim]Modules:[/dim] [bold]{', '.join(self.config.enabled_modules)}[/bold]"
        )
        console.print(f"[dim]Depth:[/dim] [bold]{self.config.depth}[/bold]\n")

        async with HTTPClient(
            rate_limit=self.config.rate_limit,
            timeout=self.config.timeout,
            retries=self.config.retries,
        ) as client:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                console=console,
                transient=False,
            ) as progress:
                await self._run_modules(client, progress)

        self.result.scan_end = datetime.now().isoformat()
        return self.result

    async def _run_modules(self, client: HTTPClient, progress: Progress) -> None:
        mods = self.config.enabled_modules

        # ── 1. Crawler ───────────────────────────────────────────────────────
        crawled_urls: List[str] = [self.config.target_url]
        if "crawler" in mods:
            task = progress.add_task("[cyan]Crawling endpoints...", total=None)
            from trishul.modules.crawler import Crawler
            crawler = Crawler(client, self.config)
            crawled_urls = await crawler.crawl()
            self.result.crawled_urls = crawled_urls
            progress.update(task, completed=100, total=100,
                            description=f"[cyan]✔ Crawler[/cyan] — {len(crawled_urls)} URLs")

        # ── 2. Port Scanner ──────────────────────────────────────────────────
        if "ports" in mods:
            task = progress.add_task("[blue]Scanning ports...", total=None)
            from trishul.modules.port_scanner import PortScanner
            parsed = urlparse(self.config.target_url)
            host = parsed.hostname or self.config.target_url
            scanner = PortScanner(host)
            open_ports = await scanner.scan()
            self.result.open_ports = open_ports
            findings = scanner.to_findings(open_ports, self.config.target_url)
            for f in findings:
                self.result.add_finding(f)
            progress.update(task, completed=100, total=100,
                            description=f"[blue]✔ Ports[/blue] — {len(open_ports)} open")

        # ── 3. Security Headers ──────────────────────────────────────────────
        if "headers" in mods:
            task = progress.add_task("[yellow]Analyzing security headers...", total=None)
            from trishul.modules.header_analyzer import HeaderAnalyzer
            analyzer = HeaderAnalyzer(client)
            findings = await analyzer.analyze(self.config.target_url)
            for f in findings:
                self.result.add_finding(f)
            progress.update(task, completed=100, total=100,
                            description=f"[yellow]✔ Headers[/yellow] — {len(findings)} issues")

        # ── 4. Fuzz Engine ───────────────────────────────────────────────────
        if "fuzz" in mods:
            task = progress.add_task("[magenta]Fuzzing sensitive paths...", total=None)
            from trishul.modules.fuzz_engine import FuzzEngine
            from trishul.core.response_analyzer import ResponseAnalyzer
            fuzzer = FuzzEngine(client, ResponseAnalyzer())
            findings = await fuzzer.fuzz(self.config.target_url)
            for f in findings:
                self.result.add_finding(f)
            progress.update(task, completed=100, total=100,
                            description=f"[magenta]✔ Fuzzer[/magenta] — {len(findings)} hits")

        # ── 5. SSL Analyzer ──────────────────────────────────────────────────
        if "ssl" in mods:
            task = progress.add_task("[green]Analyzing SSL/TLS...", total=None)
            from trishul.modules.ssl_analyzer import SSLAnalyzer
            ssl_analyzer = SSLAnalyzer()
            ssl_info, findings = await ssl_analyzer.analyze(self.config.target_url)
            self.result.ssl_info = ssl_info
            for f in findings:
                self.result.add_finding(f)
            progress.update(task, completed=100, total=100,
                            description="[green]✔ SSL[/green]")

        # ── 6. Tech Detection ────────────────────────────────────────────────
        if "tech" in mods:
            task = progress.add_task("[white]Detecting technologies...", total=None)
            from trishul.modules.tech_detector import TechDetector
            detector = TechDetector(client)
            tech_info = await detector.detect(self.config.target_url)
            self.result.tech_info = tech_info
            progress.update(task, completed=100, total=100,
                            description="[white]✔ Tech Detection[/white]")

        # ── 7. Plugins ───────────────────────────────────────────────────────
        if "plugins" in mods:
            task = progress.add_task("[red]Running security plugins...", total=None)
            from trishul.plugins.loader import PluginLoader
            import os

            plugin_dirs = []
            default_dir = os.path.join(os.path.dirname(__file__), "..", "plugins")
            plugin_dirs.append(os.path.abspath(default_dir))
            if self.config.plugins_dir:
                plugin_dirs.append(self.config.plugins_dir)

            loader = PluginLoader(plugin_dirs)
            plugins = loader.load()
            plugin_findings: List[Finding] = []

            # Run plugins on a sample of crawled URLs (max 20 to be ethical)
            scan_urls = crawled_urls[:20]
            for url in scan_urls:
                resp_data = await client.get(url)
                if resp_data is None:
                    continue
                status, headers, body, final_url = resp_data
                for plugin in plugins:
                    try:
                        pf = await plugin.run(url, headers, body, status)
                        plugin_findings.extend(pf)
                    except Exception as exc:
                        self.result.errors.append(f"Plugin {plugin.name} error: {exc}")

            for f in plugin_findings:
                self.result.add_finding(f)

            progress.update(task, completed=100, total=100,
                            description=f"[red]✔ Plugins[/red] — {len(plugin_findings)} findings")
