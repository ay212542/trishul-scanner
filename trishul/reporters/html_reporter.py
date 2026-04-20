"""
TRISHUL Scanner — HTML Reporter
Uses Jinja2 to render a rich HTML report.
"""
from __future__ import annotations

import os
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from trishul.core.models import SEVERITY_COLORS, ScanResult


class HTMLReporter:
    """Renders scan results as a styled HTML report using Jinja2."""

    def __init__(self) -> None:
        # Find template directory relative to this file
        template_dir = os.path.join(
            os.path.dirname(__file__), "..", "templates"
        )
        template_dir = os.path.abspath(template_dir)
        self.env = Environment(
            loader=FileSystemLoader(template_dir),
            autoescape=select_autoescape(["html"]),
        )

    def save(self, result: ScanResult, filepath: str) -> None:
        html = self._render(result)
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)

    def _render(self, result: ScanResult) -> str:
        template = self.env.get_template("report.html.j2")
        summary = result.summary()
        severity_colors_css = {
            "CRITICAL": "#ff3b3b",
            "HIGH": "#ff8c00",
            "MEDIUM": "#ffd700",
            "LOW": "#00bfff",
            "INFO": "#a0a0a0",
        }
        return template.render(
            result=result,
            summary=summary,
            severity_colors=severity_colors_css,
            findings=result.sorted_findings(),
        )
