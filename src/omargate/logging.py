from __future__ import annotations

import json
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Any


class OmarLogger:
    """Structured JSON logger with GitHub Actions integration."""

    def __init__(self, run_id: str):
        self.run_id = run_id
        self._stage_starts: dict[str, datetime] = {}

    def info(self, message: str, **kwargs: Any) -> None:
        self._emit("info", message, **kwargs)

    def warning(self, message: str, **kwargs: Any) -> None:
        self._emit("warning", message, **kwargs)

    def error(self, message: str, **kwargs: Any) -> None:
        self._emit("error", message, **kwargs)

    @contextmanager
    def stage(self, name: str) -> Iterator[None]:
        """Context manager that tracks stage timing."""
        start = datetime.now(UTC)
        self._stage_starts[name] = start
        self.info("stage_start", stage=name)
        status = "ok"
        try:
            yield
        except Exception as exc:  # pragma: no cover - pass-through
            status = "error"
            self.error("stage_error", stage=name, error=str(exc))
            raise
        finally:
            end = datetime.now(UTC)
            duration_ms = int((end - start).total_seconds() * 1000)
            self.info("stage_end", stage=name, duration_ms=duration_ms, status=status)

    def _emit(self, level: str, message: str, **kwargs: Any) -> None:
        """Emit structured JSON log + GitHub annotation if error."""
        payload: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": level,
            "run_id": self.run_id,
            "message": message,
        }
        payload.update(self._sanitize(kwargs))

        sys.stderr.write(json.dumps(payload, ensure_ascii=False) + "\n")
        sys.stderr.flush()

        if level == "error":
            sys.stderr.write(f"::error::{message}\n")
            sys.stderr.flush()
        elif level == "warning":
            sys.stderr.write(f"::warning::{message}\n")
            sys.stderr.flush()

    @staticmethod
    def _sanitize(fields: dict[str, Any]) -> dict[str, Any]:
        redacted: dict[str, Any] = {}
        for key, value in fields.items():
            if OmarLogger._is_sensitive_key(key):
                redacted[key] = "***"
            else:
                redacted[key] = value
        return redacted

    @staticmethod
    def _is_sensitive_key(key: str) -> bool:
        lowered = key.lower()
        return any(token in lowered for token in ("token", "secret", "password", "api_key", "apikey"))
