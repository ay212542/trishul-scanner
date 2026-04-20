"""
TRISHUL Scanner — JSON Reporter
"""
from __future__ import annotations

import json
from pathlib import Path

from trishul.core.models import ScanResult


class JSONReporter:
    """Exports scan results as structured JSON."""

    def save(self, result: ScanResult, filepath: str) -> None:
        data = result.to_dict()
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def to_string(self, result: ScanResult) -> str:
        return json.dumps(result.to_dict(), indent=2, ensure_ascii=False)
