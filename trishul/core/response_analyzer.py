"""
TRISHUL Scanner — Response Analysis Engine
Detects soft-404s and reduces false positives.
"""
from __future__ import annotations

import hashlib
from typing import Optional, Tuple

# Threshold: if body length differs by < this %, treat as potential soft-404
LENGTH_THRESHOLD_PERCENT = 5
# Well-known 404 indicators
SOFT_404_PHRASES = [
    "page not found",
    "404",
    "not found",
    "does not exist",
    "no page found",
    "error 404",
    "couldn't find",
    "could not find",
]


class ResponseAnalyzer:
    """
    Compares responses against a baseline 404 to detect soft-404 pages.
    """

    def __init__(self) -> None:
        self._baseline_hash: Optional[str] = None
        self._baseline_length: Optional[int] = None

    def set_baseline(self, body: bytes) -> None:
        self._baseline_hash = self._hash(body)
        self._baseline_length = len(body)

    def is_soft_404(self, status: int, body: bytes) -> bool:
        """
        Return True if the response is likely a soft-404 (false positive path).
        """
        if status == 404:
            return True
        if status in (301, 302, 303, 307, 308):
            # Redirect-based soft-404 sometimes used; flag conservatively
            return False

        content_text = body.decode("utf-8", errors="ignore").lower()

        # Check for well-known soft-404 phrases in body
        for phrase in SOFT_404_PHRASES:
            if phrase in content_text:
                return True

        # Compare against baseline
        if self._baseline_hash is not None and self._baseline_length is not None:
            current_hash = self._hash(body)
            current_length = len(body)
            if current_hash == self._baseline_hash:
                return True
            length_delta = abs(current_length - self._baseline_length)
            if self._baseline_length > 0:
                percent_diff = (length_delta / self._baseline_length) * 100
                if percent_diff < LENGTH_THRESHOLD_PERCENT:
                    return True

        return False

    @staticmethod
    def _hash(body: bytes) -> str:
        return hashlib.md5(body).hexdigest()

    @staticmethod
    def content_fingerprint(body: bytes) -> Tuple[str, int]:
        """Return (md5_hash, length)."""
        return hashlib.md5(body).hexdigest(), len(body)

    @staticmethod
    def is_interesting_status(status: int) -> bool:
        """200, 201, 204, 301, 302, 403 are considered 'interesting'."""
        return status in {200, 201, 204, 301, 302, 403}
