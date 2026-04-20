"""
TRISHUL Scanner — Base Plugin Abstract Class
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Dict, List

from trishul.core.models import Finding


class BasePlugin(ABC):
    """
    Every TRISHUL plugin must inherit from BasePlugin and implement `run()`.

    Plugin lifecycle:
      1. PluginLoader discovers and instantiates plugins.
      2. ScanEngine calls plugin.run() for each URL.
      3. Plugin returns a (possibly empty) list of Finding objects.
    """

    #: Human-readable plugin name (set in subclass)
    name: str = "UnnamedPlugin"
    #: Short description
    description: str = ""
    #: Plugin author
    author: str = ""
    #: Plugin version
    version: str = "1.0.0"

    @abstractmethod
    async def run(
        self,
        url: str,
        headers: Dict[str, str],
        body: bytes,
        status_code: int,
    ) -> List[Finding]:
        """
        Analyze a single HTTP response and return findings.

        Args:
            url:         The URL that was requested.
            headers:     Response headers dict.
            body:        Raw response body bytes.
            status_code: HTTP status code.

        Returns:
            List of Finding objects (empty if no issues found).
        """
        ...
