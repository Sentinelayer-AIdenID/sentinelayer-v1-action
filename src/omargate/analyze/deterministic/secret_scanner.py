from __future__ import annotations

from bisect import bisect_right
from typing import List, Tuple

import math
import re

from .pattern_scanner import Finding, mask_secret_in_snippet

MAX_SNIPPET_CHARS = 500
ENTROPY_THRESHOLD = 4.0
STRONG_ENTROPY_THRESHOLD = 4.7
STRONG_ENTROPY_MIN_LENGTH = 32

# Matches obvious code identifiers that should not be flagged as secrets.
# Only skip strings that clearly follow naming conventions with underscores
# (snake_case, SCREAMING_SNAKE). Pure alphanumeric strings are NOT skipped
# because high-entropy secrets can also be purely alphanumeric.
_CODE_IDENTIFIER_RE = re.compile(
    r"^_*[a-zA-Z][a-zA-Z0-9]*(?:_[a-zA-Z0-9]+){1,}$"  # snake_case with 2+ segments
)
_SCREAMING_SNAKE_RE = re.compile(r"^_*[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$")
_IDENTIFIER_TOKEN_RE = re.compile(r"^_*[A-Za-z][A-Za-z0-9_]*$")
_COMMENT_LINE_RE = re.compile(r"^\s*(?://|#|\*|/\*)")
_MARKDOWN_TABLE_LINE_RE = re.compile(r"^\s*\|.*\|")
_SECRET_CONTEXT_KEY_RE = re.compile(
    r"(secret|token|password|passwd|pwd|api[_-]?key|private[_-]?key|credential|auth|bearer)",
    re.IGNORECASE,
)
_ENV_ASSIGN_RE = re.compile(r"^\s*([A-Z][A-Z0-9_]{2,})\s*=")
_KNOWN_SECRET_PREFIXES = (
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "ghr_",
    "sk_live_",
    "sk_test_",
    "xoxb-",
    "xoxp-",
    "xoxa-",
    "aiZa",
    "ya29.",
    "eyJ",  # JWT-like payload, explicit regex also covers these
)

_SECRET_PATTERNS = [
    {
        "id": "SEC-004",
        "name": "AWS Access Key",
        "severity": "P0",
        "category": "secrets",
        "regex": re.compile(r"AKIA[0-9A-Z]{16}"),
        "message": "AWS access key detected",
        "recommendation": "Revoke and rotate the key, use environment variables",
    },
    {
        "id": "SEC-005",
        "name": "GitHub Token",
        "severity": "P0",
        "category": "secrets",
        "regex": re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,}"),
        "message": "GitHub token detected",
        "recommendation": "Revoke and rotate the token, use GitHub Secrets",
    },
    {
        "id": "SEC-013",
        "name": "Stripe Secret Key",
        "severity": "P1",
        "category": "secrets",
        "regex": re.compile(r"sk_(live|test)_[0-9a-zA-Z]{24,}"),
        "message": "Stripe secret key detected",
        "recommendation": "Revoke and rotate the key, use a secrets manager",
    },
]

# '=' belongs to a token only as optional base64 padding. Keeping it inside
# the body joins source assignments (name=value) into fake high-entropy tokens
# and can hide the actual unquoted value behind an identifier shortcut.
_ENTROPY_CANDIDATE_RE = re.compile(r"[A-Za-z0-9+/_-]{20,}={0,2}")


def calculate_entropy(s: str) -> float:
    if not s:
        return 0.0
    length = len(s)
    frequencies = {}
    for char in s:
        frequencies[char] = frequencies.get(char, 0) + 1
    entropy = 0.0
    for count in frequencies.values():
        prob = count / length
        entropy -= prob * math.log2(prob)
    return entropy


def _truncate_snippet(snippet: str, max_chars: int = MAX_SNIPPET_CHARS) -> str:
    if len(snippet) <= max_chars:
        return snippet
    if max_chars <= 3:
        return snippet[:max_chars]
    return f"{snippet[: max_chars - 3]}..."


def _build_line_starts(content: str) -> List[int]:
    line_starts: List[int] = []
    offset = 0
    for line in content.splitlines(keepends=True):
        line_starts.append(offset)
        offset += len(line)
    if not line_starts:
        line_starts.append(0)
    return line_starts


def _index_to_line(line_starts: List[int], idx: int) -> int:
    return bisect_right(line_starts, idx)


def _snippet_from_lines(lines: List[str], line_start: int, line_end: int) -> str:
    if not lines:
        return ""
    start_idx = max(line_start - 1, 0)
    end_idx = min(line_end, len(lines))
    return "\n".join(lines[start_idx:end_idx])


def _overlaps(span: Tuple[int, int], spans: List[Tuple[int, int]]) -> bool:
    for other in spans:
        if span[0] < other[1] and other[0] < span[1]:
            return True
    return False


def _has_known_secret_prefix(candidate: str) -> bool:
    lowered = candidate.lower()
    for prefix in _KNOWN_SECRET_PREFIXES:
        if lowered.startswith(prefix.lower()):
            return True
    return False


def _char_class_count(candidate: str) -> int:
    classes = 0
    if any(c.islower() for c in candidate):
        classes += 1
    if any(c.isupper() for c in candidate):
        classes += 1
    if any(c.isdigit() for c in candidate):
        classes += 1
    if any(c in "+/=_-" for c in candidate):
        classes += 1
    return classes


def _looks_like_non_secret_identifier(candidate: str) -> bool:
    if _has_known_secret_prefix(candidate):
        return False
    if candidate.count("=") == 1:
        left, right = candidate.split("=", 1)
        if _IDENTIFIER_TOKEN_RE.match(left) and _IDENTIFIER_TOKEN_RE.match(right):
            return True
    if _SCREAMING_SNAKE_RE.match(candidate):
        return True
    if _CODE_IDENTIFIER_RE.match(candidate):
        # A long snake_case identifier without diverse charset is usually code, not a secret.
        return _char_class_count(candidate) <= 2
    if "/" in candidate or "\\" in candidate:
        return True
    if "." in candidate:
        return True

    has_digit = any(c.isdigit() for c in candidate)
    has_lower = any(c.islower() for c in candidate)
    has_upper = any(c.isupper() for c in candidate)
    has_symbol = any(c in "+/=_-" for c in candidate)
    class_count = _char_class_count(candidate)

    # Tokens with very low variety are typically identifiers.
    if class_count <= 2:
        return True

    # If no digits, require mixed case + symbol entropy to avoid flagging identifiers like ADR_TEMPLATE.
    if not has_digit and not (has_symbol and has_lower and has_upper):
        return True

    return False


def _is_unquoted_assignment_name(content: str, match: re.Match[str]) -> bool:
    """Keep scanning the RHS instead of treating ``identifier=`` as a token."""
    candidate = match.group(0)
    next_char = content[match.end() : match.end() + 1]
    return bool(
        candidate.endswith("=")
        and _IDENTIFIER_TOKEN_RE.fullmatch(candidate[:-1])
        and next_char
        and (next_char.isalnum() or next_char in "_$")
    )


def _is_jsx_expression_attribute(content: str, file_path: str, match: re.Match[str]) -> bool:
    """Skip the name of a JSX prop bound to an expression, not its value."""
    if not file_path.lower().endswith((".jsx", ".tsx")):
        return False
    candidate = match.group(0)
    if (
        not candidate.endswith("=")
        or not _IDENTIFIER_TOKEN_RE.fullmatch(candidate[:-1])
        or content[match.end() : match.end() + 1] != "{"
    ):
        return False
    tag_start = content.rfind("<", 0, match.start())
    if tag_start <= content.rfind(">", 0, match.start()):
        return False
    return bool(re.match(r"<[A-Za-z][A-Za-z0-9_.:-]*\b", content[tag_start:]))


def _likely_secret_context(source_line: str, candidate: str) -> bool:
    if _has_known_secret_prefix(candidate):
        return True

    stripped = source_line.strip()
    if not stripped:
        return False
    if _MARKDOWN_TABLE_LINE_RE.match(stripped):
        return False

    lowered = source_line.lower()
    if "authorization" in lowered or "bearer " in lowered:
        return True

    env_m = _ENV_ASSIGN_RE.search(source_line)
    if env_m and _SECRET_CONTEXT_KEY_RE.search(env_m.group(1)):
        return True

    idx = source_line.find(candidate)
    if idx < 0:
        idx = len(source_line)
    before = source_line[:idx]
    after = source_line[idx + len(candidate) :]
    if _SECRET_CONTEXT_KEY_RE.search(before):
        return True
    if _SECRET_CONTEXT_KEY_RE.search(after):
        return True

    return False


_LOCKFILE_NAMES = frozenset({
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock",
    "pipfile.lock", "gemfile.lock", "composer.lock", "cargo.lock",
})


def scan_for_secrets(content: str, file_path: str) -> List[Finding]:
    # Lockfiles contain only integrity hashes, not secrets.
    basename = file_path.rsplit("/", 1)[-1].rsplit("\\", 1)[-1].lower()
    if basename in _LOCKFILE_NAMES:
        return []
    line_starts = _build_line_starts(content)
    lines = content.splitlines()
    findings: List[Finding] = []
    matched_spans: List[Tuple[int, int]] = []

    for pattern in _SECRET_PATTERNS:
        for match in pattern["regex"].finditer(content):
            line_start = _index_to_line(line_starts, match.start())
            # Skip matches on comment lines (regex definitions, documentation, etc.)
            source_line = lines[line_start - 1] if line_start <= len(lines) else ""
            if _COMMENT_LINE_RE.match(source_line):
                continue
            # Skip matches inside regex literals (e.g. /AKIA[0-9A-Z]{16}/)
            if re.search(r"[/=]\s*/.+/", source_line):
                continue
            matched_spans.append(match.span())
            end_index = max(match.end() - 1, match.start())
            line_end = _index_to_line(line_starts, end_index)
            snippet = _snippet_from_lines(lines, line_start, line_end)
            snippet = mask_secret_in_snippet(snippet, "secrets")
            snippet = _truncate_snippet(snippet)
            findings.append(
                Finding(
                    id=f"{pattern['id']}-{file_path}-{line_start}",
                    pattern_id=pattern["id"],
                    severity=pattern["severity"],
                    category=pattern["category"],
                    file_path=file_path,
                    line_start=line_start,
                    line_end=line_end,
                    snippet=snippet,
                    message=pattern["message"],
                    recommendation=pattern["recommendation"],
                    confidence=1.0,
                )
            )

    for match in _ENTROPY_CANDIDATE_RE.finditer(content):
        if _overlaps(match.span(), matched_spans):
            continue
        candidate = match.group(0)
        entropy = calculate_entropy(candidate)
        if entropy < ENTROPY_THRESHOLD:
            continue
        # Skip common code identifiers (camelCase, snake_case, etc.)
        if _looks_like_non_secret_identifier(candidate):
            continue
        if _is_unquoted_assignment_name(content, match):
            continue
        if _is_jsx_expression_attribute(content, file_path, match):
            continue
        # Skip candidates on comment lines
        line_start = _index_to_line(line_starts, match.start())
        source_line = lines[line_start - 1] if line_start <= len(lines) else ""
        if _COMMENT_LINE_RE.match(source_line):
            continue
        has_secret_context = _likely_secret_context(source_line, candidate)
        if not has_secret_context and (
            len(candidate) < STRONG_ENTROPY_MIN_LENGTH or entropy < STRONG_ENTROPY_THRESHOLD
        ):
            continue
        end_index = max(match.end() - 1, match.start())
        line_end = _index_to_line(line_starts, end_index)
        snippet = _snippet_from_lines(lines, line_start, line_end)
        snippet = mask_secret_in_snippet(snippet, "secrets")
        snippet = _truncate_snippet(snippet)
        severity = "P1" if has_secret_context else "P2"
        message = (
            "High-entropy string detected"
            if has_secret_context
            else "High-entropy string detected (no explicit secret context)"
        )
        recommendation = (
            "Move secrets to a secure store and rotate credentials"
            if has_secret_context
            else "Review this token-like value; move to a secure store if it is a credential"
        )
        confidence = 1.0 if has_secret_context else 0.7
        findings.append(
            Finding(
                id=f"SEC-ENTROPY-{file_path}-{line_start}",
                pattern_id="SEC-ENTROPY",
                severity=severity,
                category="secrets",
                file_path=file_path,
                line_start=line_start,
                line_end=line_end,
                snippet=snippet,
                message=message,
                recommendation=recommendation,
                confidence=confidence,
            )
        )

    return findings
