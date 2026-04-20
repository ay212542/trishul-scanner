"""
TRISHUL Scanner — Async Web Crawler
"""
from __future__ import annotations

import re
from collections import deque
from typing import List, Set
from urllib.parse import urljoin, urlparse, urlunparse

from trishul.core.http_client import HTTPClient
from trishul.core.models import ScanConfig

# Patterns to extract URLs from HTML
_HREF_RE = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)
_SRC_RE = re.compile(r'src=["\']([^"\']+)["\']', re.IGNORECASE)
_ACTION_RE = re.compile(r'action=["\']([^"\']+)["\']', re.IGNORECASE)
_JS_FETCH_RE = re.compile(r'fetch\(["\']([^"\']+)["\']', re.IGNORECASE)

# Extensions to skip (binary files)
_SKIP_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".pdf",
    ".zip", ".tar", ".gz", ".mp4", ".mp3", ".woff", ".woff2",
    ".ttf", ".eot", ".css", ".js",
}


def _normalize_url(url: str) -> str:
    """Remove fragment and normalize trailing slashes."""
    parsed = urlparse(url)
    return urlunparse(parsed._replace(fragment="")).rstrip("/")


def _same_origin(base: str, url: str) -> bool:
    base_parsed = urlparse(base)
    url_parsed = urlparse(url)
    return base_parsed.netloc == url_parsed.netloc


def _extract_urls(base_url: str, html: str) -> List[str]:
    urls = []
    for pattern in [_HREF_RE, _SRC_RE, _ACTION_RE, _JS_FETCH_RE]:
        for match in pattern.findall(html):
            match = match.strip()
            if match.startswith(("javascript:", "mailto:", "tel:", "#", "data:")):
                continue
            full = urljoin(base_url, match)
            urls.append(full)
    return urls


def _should_skip(url: str) -> bool:
    parsed = urlparse(url)
    path = parsed.path.lower()
    for ext in _SKIP_EXT:
        if path.endswith(ext):
            return True
    return False


class Crawler:
    """
    Async BFS web crawler with depth control and deduplication.
    """

    def __init__(self, client: HTTPClient, config: ScanConfig) -> None:
        self.client = client
        self.config = config
        self.base_url = config.target_url
        self.max_depth = config.depth

    async def crawl(self) -> List[str]:
        visited: Set[str] = set()
        queue: deque = deque()
        start = _normalize_url(self.base_url)
        queue.append((start, 0))
        visited.add(start)

        while queue:
            url, depth = queue.popleft()

            if depth > self.max_depth:
                continue
            if _should_skip(url):
                continue

            resp = await self.client.get(url, allow_redirects=True)
            if resp is None:
                continue

            status, headers, body, final_url = resp
            if status not in range(200, 400):
                continue

            final_norm = _normalize_url(final_url)
            visited.add(final_norm)

            # Only extract links if within depth budget
            if depth < self.max_depth:
                content_type = headers.get("Content-Type", "")
                if "html" not in content_type.lower():
                    continue
                html = body.decode("utf-8", errors="ignore")
                new_urls = _extract_urls(url, html)
                for new_url in new_urls:
                    norm = _normalize_url(new_url)
                    if norm not in visited and _same_origin(self.base_url, norm):
                        visited.add(norm)
                        queue.append((norm, depth + 1))

        return list(visited)
