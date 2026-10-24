from __future__ import annotations

from dataclasses import dataclass

from ..finding_contract import parse_finding_payload


@dataclass
class ParsedFinding:
    severity: str
    category: str
    file_path: str
    line_start: int
    line_end: int
    message: str
    recommendation: str
    fix_plan: str
    confidence: float
    source: str = "llm"


@dataclass
class ParseResult:
    findings: list[ParsedFinding]
    parse_errors: list[str]
    raw_response: str
    no_findings_reported: bool


class ResponseParser:
    """Parse LLM response into structured findings."""

    def parse(self, response_text: str) -> ParseResult:
        """
        Parse LLM response into findings.

        Handles:
        - JSONL format (one JSON per line)
        - JSON array format
        - Markdown code blocks containing JSON
        - {"no_findings": true} response
        - Malformed/partial JSON
        """
        raw = response_text or ""
        payload = parse_finding_payload(raw)
        findings = [self._normalize_finding(item) for item in payload.findings]
        return ParseResult(
            findings=findings,
            parse_errors=payload.parse_errors,
            raw_response=raw,
            no_findings_reported=payload.no_findings_reported,
        )

    def _normalize_finding(self, obj: dict) -> ParsedFinding:
        """Convert dict to ParsedFinding with defaults."""
        recommendation = obj.get("recommendation", "")
        return ParsedFinding(
            severity=obj["severity"],
            category=obj["category"],
            file_path=obj["file_path"],
            line_start=obj["line_start"],
            line_end=obj.get("line_end", obj["line_start"]),
            message=obj["message"],
            recommendation=recommendation,
            fix_plan=str(obj.get("fix_plan", "") or "").strip(),
            confidence=float(obj.get("confidence", 0.8)),
            source="llm",
        )
