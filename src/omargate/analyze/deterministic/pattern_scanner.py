from __future__ import annotations

import fnmatch
import json
import re
from bisect import bisect_right
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

MAX_SNIPPET_CHARS = 500
MAX_SCAN_BYTES = 1_000_000

_COMMENT_LINE_RE = re.compile(r"^\s*(?://|#|\*|/\*)")
# Categories where comment-line matches are almost always false positives.
_COMMENT_SKIP_CATEGORIES = frozenset({"secrets"})
# Extra placeholder tokens to skip (in addition to per-pattern false_positive_hints).
_GLOBAL_PLACEHOLDER_TOKENS = frozenset({
    "your", "placeholder", "changeme", "change_this", "replace",
    "example", "sample", "dummy", "todo", "fixme", "xxx",
    "test_value", "fake", "mock", "stub", "fixture", "seed",
    "<redacted>", "redacted", "not-a-real", "your-key-here",
})



@dataclass
class Finding:
    id: str
    pattern_id: str
    severity: str
    category: str
    file_path: str
    line_start: int
    line_end: int
    snippet: str
    message: str
    recommendation: str
    confidence: float
    fix_plan: str = ""
    source: str = "deterministic"


def mask_secret_in_snippet(snippet: str, pattern_category: str) -> str:
    if pattern_category != "secrets":
        return snippet
    masked = re.sub(
        r'(["\'])([a-zA-Z0-9_-]{8,})\1',
        lambda m: f"{m.group(1)}{m.group(2)[:4]}****{m.group(1)}",
        snippet,
    )
    masked = re.sub(
        r"\b([A-Za-z0-9_-]{8,})\b",
        lambda m: f"{m.group(1)[:4]}****",
        masked,
    )
    return masked


def _truncate_snippet(snippet: str, max_chars: int = MAX_SNIPPET_CHARS) -> str:
    if len(snippet) <= max_chars:
        return snippet
    if max_chars <= 3:
        return snippet[:max_chars]
    return f"{snippet[: max_chars - 3]}..."


def _build_line_starts(content: str) -> list[int]:
    line_starts: list[int] = []
    offset = 0
    for line in content.splitlines(keepends=True):
        line_starts.append(offset)
        offset += len(line)
    if not line_starts:
        line_starts.append(0)
    return line_starts


def _index_to_line(line_starts: list[int], idx: int) -> int:
    return bisect_right(line_starts, idx)


def _snippet_from_lines(lines: list[str], line_start: int, line_end: int) -> str:
    if not lines:
        return ""
    start_idx = max(line_start - 1, 0)
    end_idx = min(line_end, len(lines))
    return "\n".join(lines[start_idx:end_idx])


def _build_finding_id(pattern_id: str, file_path: str, line_start: int) -> str:
    return f"{pattern_id}-{file_path}-{line_start}"


class PatternScanner:
    def __init__(self, patterns_dir: Path):
        self.patterns = self._load_patterns(patterns_dir)

    def _load_patterns(self, patterns_dir: Path) -> list[dict[str, Any]]:
        pattern_files = sorted(patterns_dir.glob("*.json"))
        if not pattern_files:
            raise ValueError(f"No pattern files found in {patterns_dir}")
        patterns: list[dict[str, Any]] = []
        for pattern_file in pattern_files:
            data = json.loads(pattern_file.read_text(encoding="utf-8"))
            if data.get("schema_version") != "1.0":
                raise ValueError(f"Unsupported schema version in {pattern_file}")
            entries = data.get("patterns", [])
            for entry in entries:
                if "regex" not in entry:
                    continue
                compiled = re.compile(entry["regex"], re.MULTILINE | re.IGNORECASE)
                enriched = dict(entry)
                enriched["_compiled"] = compiled
                patterns.append(enriched)
        return patterns

    def _file_matches_pattern(self, file_path: str, pattern: dict[str, Any]) -> bool:
        normalized = file_path.replace("\\", "/")
        include_patterns = pattern.get("file_patterns") or ["*"]
        if include_patterns and not any(fnmatch.fnmatch(normalized, pat) for pat in include_patterns):
            return False
        exclude_patterns = pattern.get("exclude_patterns") or []
        if any(fnmatch.fnmatch(normalized, pat) for pat in exclude_patterns):
            return False
        return True

    def _mask_sensitive(self, snippet: str, pattern: dict[str, Any]) -> str:
        return mask_secret_in_snippet(snippet, pattern.get("category", ""))

    def _scan_content(self, file_path: Path, content: str, patterns: Iterable[dict[str, Any]]) -> list[Finding]:
        rel_path = file_path.as_posix()
        line_starts = _build_line_starts(content)
        lines = content.splitlines()
        findings: list[Finding] = []
        for pattern in patterns:
            if not self._file_matches_pattern(rel_path, pattern):
                continue
            regex = pattern.get("_compiled")
            if not regex:
                continue
            for match in regex.finditer(content):
                if match.start() == match.end():
                    continue
                line_start = _index_to_line(line_starts, match.start())
                source_line = lines[line_start - 1] if line_start <= len(lines) else ""
                # Skip comment lines for secrets patterns (reduces false positives
                # from regex definitions, documentation examples, etc.)
                if pattern.get("category") in _COMMENT_SKIP_CATEGORIES:
                    if _COMMENT_LINE_RE.match(source_line):
                        continue
                # Honour false_positive_hints from the pattern definition.
                hints = pattern.get("false_positive_hints") or []
                line_lower = source_line.lower()
                if hints and any(h in line_lower for h in hints):
                    continue
                # Also skip lines containing global placeholder tokens.
                if pattern.get("category") in _COMMENT_SKIP_CATEGORIES:
                    if any(tok in line_lower for tok in _GLOBAL_PLACEHOLDER_TOKENS):
                        continue
                end_index = max(match.end() - 1, match.start())
                line_end = _index_to_line(line_starts, end_index)
                snippet = _snippet_from_lines(lines, line_start, line_end)
                snippet = self._mask_sensitive(snippet, pattern)
                snippet = _truncate_snippet(snippet)
                findings.append(
                    Finding(
                        id=_build_finding_id(pattern["id"], rel_path, line_start),
                        pattern_id=pattern["id"],
                        severity=pattern["severity"],
                        category=pattern["category"],
                        file_path=rel_path,
                        line_start=line_start,
                        line_end=line_end,
                        snippet=snippet,
                        message=pattern["message"],
                        recommendation=pattern["recommendation"],
                        fix_plan=str(pattern.get("fix_plan", "")),
                        confidence=1.0,
                    )
                )
        return findings

    def scan_file(self, file_path: Path, content: str) -> list[Finding]:
        return self._scan_content(file_path, content, self.patterns)

    def scan_file_with_patterns(
        self, file_path: Path, content: str, patterns: Iterable[dict[str, Any]]
    ) -> list[Finding]:
        return self._scan_content(file_path, content, patterns)

    def scan_files(self, files: list[dict[str, Any]], repo_root: Path) -> list[Finding]:
        findings: list[Finding] = []
        for entry in sorted(files, key=lambda item: item.get("path") or ""):
            rel_path = entry.get("path")
            if not rel_path:
                continue
            size_bytes = entry.get("size_bytes")
            if isinstance(size_bytes, int) and size_bytes > MAX_SCAN_BYTES:
                continue
            full_path = repo_root / rel_path
            try:
                with full_path.open("rb") as handle:
                    data = handle.read(MAX_SCAN_BYTES + 1)
            except OSError:
                continue
            if len(data) > MAX_SCAN_BYTES:
                continue
            content = data.decode("utf-8", errors="replace")
            findings.extend(self.scan_file(Path(rel_path), content))
        return findings
