from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from ...analyze.deterministic.pattern_scanner import Finding
from ..detectors import iter_text_files, read_text_best_effort
from ..runner import SecuritySuite

_HEADER_MARKERS = (
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
)


@dataclass
class HttpSecurityHeadersSuite(SecuritySuite):
    tech_stack: list[str]

    @property
    def name(self) -> str:
        return "http_security_headers"

    def applies_to(self, tech_stack: list[str]) -> bool:
        return True

    async def run(self, project_root: str) -> list[Finding]:
        """
        Static-only checks: we do NOT start dev servers or execute user code.
        """
        root = Path(project_root)

        files = list(
            iter_text_files(
                root,
                patterns=("*.py", "*.js", "*.ts", "*.tsx", "*.mjs", "*.cjs"),
                max_files=200,
                max_bytes=200_000,
            )
        )
        found_markers = set()
        found_helmet = False

        for path in files:
            text = read_text_best_effort(path).lower()
            if not text:
                continue
            for marker in _HEADER_MARKERS:
                if marker in text:
                    found_markers.add(marker)
            if re.search(r"\bhelmet\s*\(", text):
                found_helmet = True

        # Heuristic: if we see explicit header markers or helmet, assume header hardening exists.
        if found_markers or found_helmet:
            return []

        return [
            Finding(
                id="HARNESS-HTTP-HEADERS",
                pattern_id="HARNESS-HTTP-HEADERS",
                severity="P3",
                category="web",
                file_path=".sentinelayer/harness",
                line_start=1,
                line_end=1,
                snippet="",
                message="No obvious HTTP security header configuration detected (static check)",
                recommendation="Ensure CSP, HSTS, X-Frame-Options, and related headers are configured for web responses",
                confidence=0.4,
                source="harness",
            )
        ]
