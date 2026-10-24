from __future__ import annotations

import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Any


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def sha256_file(path: Path) -> str:
    return sha256_hex(path.read_bytes())

def json_dumps(obj: Any) -> str:
    return json.dumps(obj, indent=2, sort_keys=True)

def safe_read_text(path: Path, max_bytes: int = 5_000_000) -> str:
    data = path.read_bytes()
    if len(data) > max_bytes:
        raise ValueError(f"File too large: {path} ({len(data)} bytes)")
    return data.decode("utf-8", errors="replace")

def parse_iso8601(value: str | None) -> datetime | None:
    """Parse an ISO-8601 timestamp, handling the trailing 'Z' that fromisoformat rejects."""
    if not value:
        return None
    try:
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def ensure_writable_dir(path: Path) -> bool:
    try:
        path.mkdir(parents=True, exist_ok=True)
        test_file = path / ".write_test"
        test_file.write_text("ok", encoding="utf-8")
        test_file.unlink(missing_ok=True)
        return True
    except OSError:
        return False
