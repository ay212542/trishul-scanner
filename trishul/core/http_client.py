"""
TRISHUL Scanner — Async HTTP Client with Rate Limiting & Retry
"""
from __future__ import annotations

import asyncio
import hashlib
import time
from typing import Any, Dict, Optional, Tuple

import aiohttp
from aiohttp import ClientSession, ClientTimeout, TCPConnector


class TokenBucketRateLimiter:
    """Thread-safe token bucket rate limiter."""

    def __init__(self, rate: int) -> None:
        self.rate = rate          # tokens per second
        self.tokens = float(rate)
        self._lock = asyncio.Lock()
        self._last_refill = time.monotonic()

    async def acquire(self) -> None:
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_refill
            self.tokens = min(self.rate, self.tokens + elapsed * self.rate)
            self._last_refill = now
            if self.tokens < 1:
                wait = (1 - self.tokens) / self.rate
                await asyncio.sleep(wait)
                self.tokens = 0.0
            else:
                self.tokens -= 1


class HTTPClient:
    """
    Async HTTP client with:
    - Connection pooling
    - Rate limiting (token bucket)
    - Exponential backoff retry
    - Consistent User-Agent
    """

    USER_AGENT = (
        "Mozilla/5.0 (compatible; TrishulScanner/1.0; "
        "+https://github.com/trishul-scanner)"
    )

    def __init__(
        self,
        rate_limit: int = 10,
        timeout: int = 10,
        retries: int = 3,
        verify_ssl: bool = False,
    ) -> None:
        self.rate_limiter = TokenBucketRateLimiter(rate_limit)
        self.timeout = ClientTimeout(total=timeout)
        self.retries = retries
        self.verify_ssl = verify_ssl
        self._session: Optional[ClientSession] = None

    async def __aenter__(self) -> "HTTPClient":
        connector = TCPConnector(limit=100, ssl=False)
        self._session = ClientSession(
            connector=connector,
            timeout=self.timeout,
            headers={"User-Agent": self.USER_AGENT},
        )
        return self

    async def __aexit__(self, *args: Any) -> None:
        if self._session:
            await self._session.close()
            self._session = None

    async def get(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, str]] = None,
        allow_redirects: bool = True,
    ) -> Optional[Tuple[int, Dict[str, str], bytes, str]]:
        """
        Returns (status_code, headers_dict, body_bytes, final_url) or None on failure.
        """
        for attempt in range(self.retries):
            try:
                await self.rate_limiter.acquire()
                async with self._session.get(
                    url,
                    headers=headers,
                    params=params,
                    allow_redirects=allow_redirects,
                    ssl=False,
                ) as resp:
                    body = await resp.read()
                    resp_headers = dict(resp.headers)
                    return resp.status, resp_headers, body, str(resp.url)
            except (aiohttp.ClientError, asyncio.TimeoutError):
                if attempt < self.retries - 1:
                    await asyncio.sleep(2 ** attempt)
                else:
                    return None
        return None

    async def head(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        allow_redirects: bool = True,
    ) -> Optional[Tuple[int, Dict[str, str]]]:
        """
        Returns (status_code, headers_dict) or None on failure.
        """
        for attempt in range(self.retries):
            try:
                await self.rate_limiter.acquire()
                async with self._session.head(
                    url,
                    headers=headers,
                    allow_redirects=allow_redirects,
                    ssl=False,
                ) as resp:
                    return resp.status, dict(resp.headers)
            except (aiohttp.ClientError, asyncio.TimeoutError):
                if attempt < self.retries - 1:
                    await asyncio.sleep(2 ** attempt)
                else:
                    return None
        return None


def body_hash(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()
