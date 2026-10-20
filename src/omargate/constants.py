from __future__ import annotations

from enum import Enum


class Severity(str, Enum):
    """Severity levels for findings."""

    P0 = "P0"
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    P4 = "P4"


class ExitCode(int, Enum):
    """Process exit codes."""

    SUCCESS = 0
    BLOCKED = 1
    ERROR = 2
    SKIPPED = 10


class Limits:
    """Shared hard limits."""

    MAX_FILE_SIZE = 1_000_000  # 1MB
    MAX_FILES = 1_000
    MAX_TOTAL_SIZE = 50_000_000  # 50MB
    MAX_SNIPPET_LENGTH = 500
    MAX_FINDINGS_PER_FILE = 20
    MAX_TOTAL_FINDINGS = 200
